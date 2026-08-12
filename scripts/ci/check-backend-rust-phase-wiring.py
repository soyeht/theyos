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

PHASE_CALL = re.compile(r"^scripts/ci/backend-rust ([a-z0-9][a-z0-9-]*)$")
SELF_TEST_CMD = f"python3 {SELF} --self-test"
LIVE_CMD = f"python3 {SELF}"

# Attributes that make a step or a job stop being an unconditional, load-bearing
# invocation. `shell` sits with the other two because changing the shell changes
# how a failure propagates, which is the property being asserted.
#
# The two levels are listed separately because they are not the same set, and
# collapsing them is what hid `needs` for a whole review cycle: it is a job key
# with no step-level meaning, so a single shared tuple had no natural place for
# it and it was simply never considered.
STEP_DISQUALIFYING = ("if", "continue-on-error", "shell")

# `needs` belongs here and its absence was a real fail-open, found in review.
#
# The property, stated precisely rather than dramatically: `needs` makes a judged
# job CONDITIONAL ON ANOTHER JOB'S OUTCOME. If the dependency is skipped, this
# job can be skipped without any failure of its own. If the dependency fails, the
# workflow may well already be red upstream — but this job has stopped proving
# its own 11 phases, and that is the thing the contract is about. Every step
# below it still reads as unconditional, and this gate would still count a full
# set of invocations for a job that ran nothing.
#
# The requirement is that both judged jobs are load-bearing BY THEMSELVES. A red
# arriving from somewhere else is not this gate's evidence.
#
# Any `needs` disqualifies, including an empty one and any future spelling. A
# legitimate dependency on these jobs is not forbidden; it is required to be a
# visible decision here, the same contract the other three already carry.
JOB_DISQUALIFYING = STEP_DISQUALIFYING + ("needs",)


class Malformed(SystemExit):
    """Raised instead of guessing. Every branch here is a deliberate refusal."""


def parse_workflow(text: str) -> tuple[dict, str | None]:
    """A narrow, section-aware scan of the subset this gate needs.

    Deliberately NOT PyYAML. No script in this repo imports yaml and no CI step
    installs it; `scripts/check_consumption_coverage.py` states the reason for
    the same choice — "A minimal indent-aware scan is used on purpose: it has no
    YAML dependency". A gate that needs an implicitly-present module is a new
    way to fail, and it fails asymmetrically: green under whichever interpreter
    CI happens to use, broken for anyone following the repo convention.

    Returns `({job: {attrs, defaults_shell, steps: [step, ...]}}, wf_shell)`.

    SECTION STATE IS THE POINT, and the negative control is live in this very
    file rather than invented: `on.push.branches` contains `- main` at indent 6,
    byte-identical to `- name: Checkout` at indent 6. A depth-only scan
    materialises the trigger list as a step. Steps are therefore collected only
    inside `jobs -> <job> -> steps`.

    Fails closed — raises rather than guessing — on tabs, unexpected
    indentation, YAML aliases or merge keys, and duplicated relevant keys.
    """
    if "\t" in text:
        raise Malformed("workflow contains a tab; indentation cannot be trusted")

    jobs: dict[str, dict] = {}
    wf_shell: str | None = None
    section = None          # None | "jobs" | "defaults"
    job = None
    in_steps = False
    step: dict | None = None
    lines = text.split("\n")

    def close_step() -> None:
        nonlocal step
        if step is not None:
            jobs[job]["steps"].append(step)
            step = None

    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        body = raw.strip()
        # YAML alias/merge syntax only. An earlier version tested for a bare `*`
        # and refused `- "admin/rust/**"`, a path glob in the trigger list — the
        # right instinct (fail closed) aimed at the wrong token. An alias is `*`
        # or `&` introducing an identifier in VALUE position, never a `*` inside
        # a quoted string.
        if (
            body.startswith("<<:")
            or re.match(r"^- [*&]\w", body)
            or re.search(r":\s+[*&]\w", body)
        ):
            raise Malformed(f"alias or merge key is not supported: {body!r}")

        if indent == 0:
            close_step()
            job, in_steps = None, False
            section = "jobs" if body == "jobs:" else ("defaults" if body == "defaults:" else None)
            continue

        if section == "defaults" and indent in (2, 4) and body.startswith("shell:"):
            wf_shell = body.split(":", 1)[1].strip()
            continue

        if section != "jobs":
            continue

        if indent == 2 and body.endswith(":") and not body.startswith("- "):
            close_step()
            job = body[:-1]
            jobs[job] = {
                "attrs": {},
                "defaults_shell": None,
                "steps": [],
                "seen_steps": False,
            }
            in_steps = False
            continue

        if job is None:
            continue

        if indent == 4:
            close_step()
            in_steps = body == "steps:"
            if in_steps:
                # A SECOND `steps:` in one job is refused, never merged. Tracked
                # on the job itself rather than inferred from `in_steps`, which
                # is reset by every intervening key and so cannot answer "has
                # this job already had a steps section?".
                #
                # Merging was the old behaviour and it modelled no YAML that
                # exists: every real parser either errors on a duplicate key or
                # keeps exactly one of the two. A gate whose document model is
                # weaker than the one CI uses can be handed a file where the
                # list it reads is not the list that runs.
                if jobs[job]["seen_steps"]:
                    raise Malformed(
                        f"job {job}: a second `steps:` section — duplicate keys "
                        "are not merged, and this gate refuses to guess which "
                        "list runs"
                    )
                jobs[job]["seen_steps"] = True
            if not in_steps and ":" in body:
                key, _, val = body.partition(":")
                key = key.strip()
                if key in jobs[job]["attrs"]:
                    raise Malformed(f"job {job}: duplicated key {key!r}")
                jobs[job]["attrs"][key] = val.strip()
            continue

        if not in_steps:
            # job-level defaults.run.shell lives under `defaults:` at indent 4,
            # so its children arrive here.
            if body.startswith("shell:"):
                jobs[job]["defaults_shell"] = body.split(":", 1)[1].strip()
            continue

        if indent == 6 and body.startswith("- "):
            close_step()
            step = {}
            body = body[2:]
            indent = 8  # fall through and record this first key
        elif indent > 8:
            # Nested content of a step key — `with:`, `env:` and their children.
            # Skipped rather than refused: this is ordinary YAML, and none of the
            # keys this gate cares about (`run`, `if`, `continue-on-error`,
            # `shell`, `uses`) can live at that depth, so ignoring it drops
            # nothing. Refusing it here was the first version's error: fail-closed
            # is for shapes the parser cannot interpret, not for shapes it simply
            # has no use for.
            continue
        elif indent != 8:
            raise Malformed(
                f"job {job}: unexpected indentation {indent} inside steps: {body!r}"
            )

        if step is None:
            raise Malformed(f"job {job}: step attribute outside a step: {body!r}")

        key, sep, val = body.partition(":")
        if not sep:
            continue  # a continuation line of a block scalar
        key, val = key.strip(), val.strip()
        if key in ("name", "run", "uses", "if", "continue-on-error", "shell"):
            if key in step:
                raise Malformed(f"job {job}: duplicated step key {key!r}")
            step[key] = val

    close_step()
    return jobs, wf_shell


def load_bearing(job: dict, step: dict, wf_shell: str | None) -> bool:
    """Does this step run unconditionally, with its status as the step's status?

    Anything conditional, advisory, or run under a shell whose failure
    propagation differs is refused. The refusal is deliberate: a legitimate
    condition should require a change here, visible in review, rather than
    silently satisfying the contract.
    """
    if wf_shell is not None or job["defaults_shell"] is not None:
        return False
    if any(a in job["attrs"] for a in JOB_DISQUALIFYING):
        return False
    return not any(a in step for a in STEP_DISQUALIFYING)


def command_of(step: dict) -> str | None:
    """The step's `run:` value, whatever it is. Matching happens at the caller.

    A candidate command must be EXACTLY the invocation — no wrapper, prefix,
    pipeline, `;`, `||` or `&` riding along — and that is enforced by the
    anchored comparisons in `invoked` and `gate_steps`, not here.

    Block scalars need no special case, and an earlier version's `run_is_block`
    flag was dead code: for `run: |` this narrow parser records the header `|`
    as the value, which matches no command. Review measured it — removing the
    flag entirely left all mutations, controls and runtime cases passing, so the
    guard's comment credited a protection nothing exercised. It is gone rather
    than paired with a new case invented to justify it.

    What keeps the block-scalar mutation honest is the mutation itself: it must
    stay RED through the missing-phase diagnosis. If anyone later widens this
    function to reconstruct a block scalar's body, that case turns green and the
    self-test fails, which is the alarm the dead flag was pretending to be.

    `uses:` is not `run:` and can never satisfy this contract.
    """
    if "run" not in step:
        return None
    return step["run"] or None


def registry(text: str) -> list[str]:
    block = re.search(r"^PHASES=\(\n(.*?)^\)$", text, re.M | re.S)
    if not block:
        raise SystemExit("PHASES=( ... ) not found — this gate's subject moved")
    return [ln.strip() for ln in block.group(1).splitlines() if ln.strip()]


def functions(text: str) -> list[str]:
    return [m.replace("_", "-") for m in re.findall(r"^phase_(\w+)\(\)", text, re.M)]


def invoked(job: dict, wf_shell: str | None) -> list[str]:
    """Phases this job actually runs: exact one-line commands on load-bearing steps."""
    out = []
    for step in job["steps"]:
        cmd = command_of(step)
        if cmd is None or not load_bearing(job, step, wf_shell):
            continue
        hit = PHASE_CALL.match(cmd)
        if hit:
            out.append(hit.group(1))
    return out


def gate_steps(jobs: dict, wf_shell: str | None) -> tuple[int, int]:
    """Count load-bearing, exactly-matching self-test and live invocations."""
    self_n = live_n = 0
    for job in jobs.values():
        for step in job["steps"]:
            cmd = command_of(step)
            if cmd is None or not load_bearing(job, step, wf_shell):
                continue
            if cmd == SELF_TEST_CMD:
                self_n += 1
            elif cmd == LIVE_CMD:
                live_n += 1
    return self_n, live_n


def duplicates(names: list[str]) -> list[str]:
    return sorted({n for n in names if names.count(n) > 1})


def assert_wired(jobs: dict, wf_shell: str | None) -> list[str]:
    """Exactly one load-bearing self-test step and exactly one live step.

    A gate nothing runs is not a gate, and the cheapest ways to neuter one are to
    delete its step, condition it away, mark it advisory, wrap the command so its
    status is discarded, or duplicate it so a green copy hides a red one. Each is
    a different edit and all of them land here as a count that is not 1.
    """
    self_n, live_n = gate_steps(jobs, wf_shell)
    errs = []
    if self_n != 1:
        errs.append(
            f"expected exactly 1 load-bearing `--self-test` invocation, found "
            f"{self_n} — an orphaned or advisory gate never fires"
        )
    if live_n != 1:
        errs.append(
            f"expected exactly 1 load-bearing live invocation, found {live_n}"
        )
    return errs


def evaluate(cmd: str, wf: str) -> tuple[list[str], dict[str, int]]:
    reg, fns = registry(cmd), functions(cmd)
    jobs, wf_shell = parse_workflow(wf)
    for name in JOBS:
        if name not in jobs:
            raise Malformed(f"job {name} not found — this gate's subject moved")
    per_job = {j: invoked(jobs[j], wf_shell) for j in JOBS}
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
            errs.append(
                f"{job} never invokes: {sorted(rset - jset)} — registered but not "
                "run by a load-bearing, exactly-matching step"
            )

    common = set.intersection(*(set(v) for v in per_job.values()))
    if len(common) != EXPECTED_COMMON:
        # This is a TRIPWIRE, not a defect detector, and the message has to say
        # so. Measured: it can only fire alone when the registry, the functions
        # and both jobs already AGREE — any disagreement trips one of the set
        # comparisons above first. So the one case where this is the sole error
        # is a phase count that legitimately changed.
        #
        # It is kept because 11 is an agreed number rather than an emergent one:
        # `Quarantine probe (issue #470)` is deliberately NOT a phase, pinned
        # inline by a contract test, and promoting it would be a decision. But a
        # pin whose message reads like a coverage hole sends the next person
        # hunting for a missing invocation that does not exist, so the message
        # names both readings and points at the constant to change.
        errs.append(
            f"the jobs share {len(common)} phases, expected {EXPECTED_COMMON}: "
            f"{sorted(common)}. Either a phase stopped being invoked by both "
            f"jobs, or the phase count legitimately changed — if the latter, "
            f"EXPECTED_COMMON in {SELF} is the number to update, deliberately."
        )

    errs += assert_wired(jobs, wf_shell)
    counts = {"PHASES": len(reg), "functions": len(fns)}
    counts.update({j: len(v) for j, v in per_job.items()})
    return errs, counts


def harness(
    cmd: str, phases: list[str], extra: str = "", bodies: dict[str, str] | None = None
) -> str:
    """The real header and the real dispatcher, with toy phases spliced in.

    Faithfulness is the entire point and it rests on this splice: everything
    outside `PHASES=( ... )` and the `phase_*` bodies is copied verbatim, so
    `validate_registry`, `run_phase` and `main` under test are the ones that
    ship. Weaken the membership check in the real file and these runtime cases
    inherit the weakening and fail — which is asserted below rather than
    assumed, because a harness that quietly reimplemented the dispatcher would
    keep passing while the shipped code rotted.

    Toy phases rather than the real ones because the real bodies invoke cargo.
    `bodies` supplies a multi-command body for a phase; the single-command
    default cannot express the defect the runtime cases below exist to catch,
    since masking only shows up when a phase has a command AFTER the failing one.
    """
    head = cmd[: cmd.index("PHASES=(")]
    tail = cmd[cmd.index("usage() {") :]
    bodies = bodies or {}
    body = "PHASES=(\n" + "".join(f"  {p}\n" for p in phases) + ")\n\n"
    for p in dict.fromkeys(phases):
        inner = bodies.get(p, f'echo "RAN-{p}"')
        body += f'phase_{p.replace("-", "_")}() {{ {inner}; }}\n'
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


def assert_mid_body_fails_loudly(cmd: str) -> None:
    """A phase failing part-way through its body must abort and report failure.

    Kept as its own function so the negative control can re-run these exact
    assertions against a crippled dispatcher and require them to raise. The
    single-command cases cannot express this defect at all: masking is only
    observable when a command FOLLOWS the failing one, hence the three-command
    fixture. Material exposure in the shipped pipeline — `phase_excluded_members`
    runs three cargo invocations in sequence, so a failing first run can be
    masked by a later one passing.
    """
    mid = {"mid": "echo BEFORE; false; echo AFTER", "after": "echo NEXT"}
    fixture = harness(cmd, ["mid", "after"], bodies=mid)

    rc, out = run_harness(fixture, "mid")
    if rc == 0 or "AFTER" in out or "mid: ok" in out or "BEFORE" not in out:
        raise SystemExit(
            f"RUNTIME SELF-TEST FAILED: a phase failing mid-body did not fail "
            f"loudly (rc={rc}, reached AFTER={'AFTER' in out}, reported "
            f"ok={'mid: ok' in out}). A later command masks an earlier failure."
        )

    rc, out = run_harness(fixture, "all")
    if rc == 0 or "AFTER" in out or "NEXT" in out or "BEFORE" not in out:
        raise SystemExit(
            f"RUNTIME SELF-TEST FAILED: `all` continued past a phase that failed "
            f"mid-body (rc={rc}, AFTER={'AFTER' in out}, NEXT={'NEXT' in out})"
        )


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

    assert_mid_body_fails_loudly(cmd)
    print("  self-test  runtime: mid-body failure aborts the phase, rc preserved")
    print("  self-test  runtime: `all` stops at a mid-body failure")

    green = harness(
        cmd, ["one", "two"], bodies={"one": "echo G1; echo G2; echo G3"}
    )
    rc, out = run_harness(green, "all")
    if rc != 0 or [out.count(f"G{i}") for i in (1, 2, 3)] != [1, 1, 1] or out.count("RAN-two") != 1:
        raise SystemExit(
            f"RUNTIME SELF-TEST FAILED: the multi-command green control did not "
            f"run every command exactly once (rc={rc})"
        )
    print("  self-test  runtime: multi-command green control runs everything once")

    rc, out = run_harness(harness(cmd, ["lastfail"], bodies={"lastfail": "echo L1; false"}), "lastfail")
    if rc == 0 or "L1" not in out:
        raise SystemExit(
            f"RUNTIME SELF-TEST FAILED: a failing LAST command did not propagate "
            f"(rc={rc})"
        )
    print("  self-test  runtime: a failing last command still propagates")

    # NEGATIVE CONTROL, stated as the property that matters: with the old
    # pattern restored, THE SELF-TEST MUST TERMINATE RED. Not "the mutant
    # masks" — that is a fact about the mutant. What has to hold is that these
    # assertions detect it, so the exact checks run above are re-run against the
    # crippled dispatcher and are required to raise.
    broken = cmd.replace(
        '  set +e\n  ( set -Eeuo pipefail; cd "$REPO_ROOT"; "$fn" )\n  rc=$?\n  set -e',
        '  ( cd "$REPO_ROOT" && "$fn" ) || rc=$?',
    )
    if broken == cmd:
        raise SystemExit(
            "RUNTIME SELF-TEST INVALID: cannot locate the errexit-safe dispatch "
            "block, so the regression it fixes cannot be simulated"
        )
    try:
        assert_mid_body_fails_loudly(broken)
    except SystemExit:
        print(
            "  self-test  runtime: negative control — restoring `( ... ) || rc=$?` "
            "makes this self-test RED"
        )
    else:
        raise SystemExit(
            "RUNTIME SELF-TEST INVALID: with `( ... ) || rc=$?` restored the "
            "mid-body assertions still passed. They do not detect the masking, "
            "so their green says nothing about the shipped dispatcher."
        )

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


# The one error the count tripwire raises. Filtered out before a mutation is
# allowed to count as caught: it fires as a co-symptom on almost every real
# failure, so a mutation that produced ONLY this would be red for a reason that
# says nothing about the defect it models.
TRIPWIRE_MARK = "the jobs share"

# Expected-reason fragments, named once so a case and its assertion cannot drift.
R_MISSING = "never invokes"          # a phase the job no longer runs
R_NONMEMBER = "invokes non-members"  # a phase not in the registry
R_ORPHAN = "defined but not in PHASES"
R_UNDEFINED = "in PHASES but not defined"
R_DUP_REG = "PHASES contains duplicates"
R_SELF_TEST = "`--self-test` invocation"
R_LIVE = "load-bearing live invocation"
MALFORMED = "MALFORMED:"             # prefix: the case must RAISE, not return


def fail_open_cases(wf: str, victim: str, step: str) -> list[tuple[str, str]]:
    """Every way a step can be in the file and still not gate anything.

    In all of them the text `scripts/ci/backend-rust <victim>` remains plainly
    visible in the job: a reviewer skimming the diff sees the invocation, and any
    grep over the job body finds it. What changes is whether the step runs
    unconditionally and whether its exit status becomes the step's status.

    This is the population that made the FIRST version of this parser useless. It
    asked "could this command execute?" — to which every entry below answers yes
    — instead of "does it execute unconditionally, with load-bearing status?".
    Thirteen of these were found by review, not by me, and they were found in a
    parser I had already called done.

    `if: always()` is the sharpest of them and is here deliberately: it does not
    stop the step running, it detaches the step from the failure chain. A form
    that still executes is the one that survives an eyeball check.
    """
    line = f"        {step}\n"
    if wf.count(line) != 2:
        raise SystemExit(
            f"SELF-TEST INVALID: expected the {victim} step in exactly 2 jobs, "
            f"found {wf.count(line)}"
        )

    def phase_step(replacement: str) -> str:
        """Mutate the FIRST occurrence only — the Linux job."""
        return wf.replace(line, replacement, 1)

    def attr(a: str) -> str:
        return phase_step(f"        {a}\n{line}")

    def suffix(s: str) -> str:
        return phase_step(f"        {step}{s}\n")

    linux = "  build-and-test-linux:\n"

    def job_attr(text: str) -> str:
        return wf.replace(linux, linux + text, 1)

    cases = [
        # --- the step is present but conditional or advisory -----------------
        ("step conditional (`if: always()` — it still RUNS)", attr("if: always()"), R_MISSING),
        ("step advisory (`continue-on-error: true`)", attr("continue-on-error: true"), R_MISSING),
        ("step under a custom shell", attr("shell: bash"), R_MISSING),
        # --- the command runs but its status is discarded --------------------
        ("status discarded by `|| true`", suffix(" || true"), R_MISSING),
        ("status replaced by a following `;` command", suffix("; true"), R_MISSING),
        ("status taken by the last stage of a pipeline", suffix(" | tee /dev/null"), R_MISSING),
        ("backgrounded with `&` — the step waits for nothing", suffix(" &"), R_MISSING),
        # --- the command is not the command ----------------------------------
        ("wrapped in `echo`, so it only prints", phase_step(line.replace("run: ", "run: echo ")), R_MISSING),
        (
            "moved into a block scalar, which can hide a wrapper",
            phase_step(f"        run: |\n          scripts/ci/backend-rust {victim}\n"),
            R_MISSING,
        ),
        ("`uses:` a composite action instead of `run:`", phase_step(f"        uses: ./.github/actions/{victim}\n"), R_MISSING),
        # --- the whole job stops being load-bearing --------------------------
        ("job conditional (`if:` on build-and-test-linux)", job_attr("    if: always()\n"), R_MISSING),
        ("job advisory (`continue-on-error:` on the job)", job_attr("    continue-on-error: true\n"), R_MISSING),
        (
            "job-level `defaults.run.shell`",
            job_attr("    defaults:\n      run:\n        shell: bash\n"),
            R_MISSING,
        ),
        # --- `needs:`, in every spelling -------------------------------------
        #
        # All four forms are here because review measured that the FAIL-OPEN is
        # identical across them while what the parser stores is not:
        #
        #   needs: [x]      attrs['needs'] = '[x]'      members visible
        #   needs: x        attrs['needs'] = 'x'        members visible
        #   needs: ['x']    attrs['needs'] = "['x']"    members visible
        #   needs:          attrs['needs'] = ''         MEMBERS LOST — the block
        #     - x                                       list is skipped entirely
        #
        # That asymmetry decides the predicate. Testing key PRESENCE catches all
        # four; anything transitive ("only disqualify if the needed job is
        # itself conditional") is structurally blind to the block form, because
        # there are no members left to follow — it would look like a smarter fix
        # and cover the class minus one form, which is precisely the defect being
        # closed here. Each form is its own case so that a future change to the
        # predicate cannot quietly lose one.
        ("job `needs:` — flow list", job_attr("    needs: [installer-tests]\n"), R_MISSING),
        ("job `needs:` — bare scalar", job_attr("    needs: installer-tests\n"), R_MISSING),
        ("job `needs:` — quoted flow list", job_attr("    needs: ['installer-tests']\n"), R_MISSING),
        ("job `needs:` — BLOCK list (members not parsed)", job_attr("    needs:\n      - installer-tests\n"), R_MISSING),
        # --- the document model itself ---------------------------------------
        (
            "a second `steps:` section in one job",
            wf.replace("  build-and-test-macos:\n",
                       "    steps:\n      - name: the only list that runs\n"
                       "        run: echo nothing\n  build-and-test-macos:\n", 1),
            MALFORMED + "a second `steps:` section",
        ),
        # --- the whole WORKFLOW stops being load-bearing ---------------------
        (
            "workflow-level `defaults.run.shell`",
            wf.replace("\njobs:\n", "\ndefaults:\n  run:\n    shell: bash\njobs:\n", 1),
            R_MISSING,
        ),
    ]

    # The gate's own two steps. Removal and duplication are separate edits and
    # both are counted, because a second green copy hides a red original just as
    # effectively as deleting it.
    #
    # NOTE, and it is a live trap rather than a hypothetical: LIVE_CMD is a
    # PREFIX of SELF_TEST_CMD. Matching must include the trailing newline or
    # "remove the live step" silently removes the self-test step instead, and the
    # case would pass for the wrong reason.
    for name, cmdline in (("self-test", SELF_TEST_CMD), ("live", LIVE_CMD)):
        gate_line = f"        run: {cmdline}\n"
        if wf.count(gate_line) != 1:
            raise SystemExit(
                f"SELF-TEST INVALID: expected exactly 1 {name} step, found "
                f"{wf.count(gate_line)}"
            )
        want = R_SELF_TEST if name == "self-test" else R_LIVE
        cases.append((f"the gate's own {name} step deleted", wf.replace(gate_line, "", 1), want))
        cases.append(
            (
                f"the gate's own {name} step duplicated",
                wf.replace(
                    gate_line,
                    gate_line + f"      - name: {name} (copy)\n" + gate_line,
                    1,
                ),
                want,
            )
        )

    return cases


def universe_controls(wf: str) -> list[tuple[str, str]]:
    """Shapes this gate must NOT judge. Each one must stay GREEN.

    Without these the fail-open battery above proves far less than it appears
    to. A checker that simply reds on any edit to the workflow catches all
    fourteen mutations and is worthless — the battery alone cannot tell a
    discriminating gate from an indiscriminate one. These controls are what make
    the reds mean something.

    They are also the practical failure mode: a gate that reds on unrelated
    edits gets marked `continue-on-error` by the next person it blocks, and then
    it is decoration.

    `set -o pipefail` in some other step is the adjudicated example. It does not
    belong to this gate's population — this gate does not audit shell strictness
    anywhere except in the exactly-matching steps it counts — so it must not be
    judged here.
    """
    anchor = "      - name: Clippy (deny warnings)\n"
    if wf.count(anchor) != 2:
        raise SystemExit(
            f"SELF-TEST INVALID: expected 2 anchors for control insertion, "
            f"found {wf.count(anchor)}"
        )

    def insert(block: str) -> str:
        """Add an unrelated step to the Linux job, before the first anchor."""
        return wf.replace(anchor, block + anchor, 1)

    return [
        (
            "an unrelated step running a pipeline under `set -o pipefail`",
            insert(
                "      - name: Unrelated pipeline (universe control)\n"
                "        run: |\n"
                "          set -o pipefail\n"
                "          echo x | cat\n"
            ),
        ),
        (
            "an unrelated step marked advisory",
            insert(
                "      - name: Unrelated advisory step (universe control)\n"
                "        continue-on-error: true\n"
                "        run: echo advisory\n"
            ),
        ),
        (
            "an unrelated step under a custom shell",
            insert(
                "      - name: Unrelated shell step (universe control)\n"
                "        shell: bash\n"
                "        run: echo other-shell\n"
            ),
        ),
        (
            "an unrelated JOB made conditional",
            wf.replace("  installer-tests:\n", "  installer-tests:\n    if: always()\n", 1),
        ),
        # Paired with the four `needs:` mutations above. Without it the battery
        # would gain four cases all pulling the same way and no case proving the
        # new key is judged only where it matters — `needs:` is ordinary and
        # common, and a gate that reds on it anywhere in the file would be
        # over-reaching into every job it does not judge.
        (
            "an unrelated JOB given `needs:`",
            wf.replace("  installer-tests:\n",
                       "  installer-tests:\n    needs: [no-bash-policy]\n", 1),
        ),
    ]


def assert_pin_is_deliberate(cmd: str, wf: str, victim: str, step: str) -> None:
    """A phase count that legitimately GROWS must be red — and red saying so.

    A third category, and it belongs to neither block above: this is not a defect
    the gate catches, nor an unrelated edit the gate ignores. It is a tripwire
    firing on a tree that is entirely correct.

    Measured before it was written: with a 12th phase added properly — in PHASES,
    with a function, invoked by a load-bearing exact step in both jobs — every set
    comparison agrees and `EXPECTED_COMMON` is the ONLY error. So the constant
    cannot detect a defect; it can only announce that an agreed number moved.

    Asserted here so that behaviour is on the record as a decision rather than
    discovered as a surprise, and so the message keeps naming the constant. A pin
    is a number nobody re-evaluates; the least it can do is say it is a pin.
    """
    fn = f"phase_{victim.replace('-', '_')}"
    cmd12 = cmd.replace(f"  {victim}\n)", f"  {victim}\n  new-phase\n)")
    cmd12 = cmd12.replace(f"{fn}() {{", f"phase_new_phase() {{ echo new; }}\n\n{fn}() {{", 1)
    wf12 = wf.replace(
        f"        {step}\n",
        f"        {step}\n      - name: New phase\n"
        f"        run: scripts/ci/backend-rust new-phase\n",
    )
    if cmd12 == cmd or wf12 == wf:
        raise SystemExit(
            "SELF-TEST INVALID: could not construct a correct 12-phase tree, so "
            "the tripwire's behaviour on legitimate growth is unproven"
        )

    errs, counts = evaluate(cmd12, wf12)
    if set(counts.values()) != {EXPECTED_COMMON + 1}:
        raise SystemExit(
            f"SELF-TEST INVALID: the grown tree is not internally consistent, so "
            f"any error it produces proves nothing: {counts}"
        )
    if len(errs) != 1 or "EXPECTED_COMMON" not in errs[0]:
        raise SystemExit(
            "SELF-TEST FAILED: a correctly added phase must trip exactly the "
            f"count tripwire and name the constant to change. Got: {errs}"
        )
    print("  self-test  tripwire: a correctly added phase is red BY DESIGN, "
          "and the message names the constant")


def self_test(cmd: str, wf: str) -> None:
    """Every mutation below must be caught, every control must stay green.

    A three-set comparison that has never been observed to fail is
    indistinguishable from one that returns success unconditionally, and this
    gate is what authorises trusting `backend-rust all` as the pipeline.
    """
    victim = registry(cmd)[-1]
    fn = f"phase_{victim.replace('-', '_')}"
    step = f"run: scripts/ci/backend-rust {victim}"
    macos_at = wf.index("  build-and-test-macos:")

    cases: list[tuple[str, str, str, str]] = [
        ("function defined but absent from PHASES", cmd.replace(f"  {victim}\n)", ")"), wf, R_ORPHAN),
        ("PHASES entry with no function", re.sub(rf"{fn}\(\) \{{.*?\n\}}\n", "", cmd, flags=re.S), wf, R_UNDEFINED),
        ("workflow invokes a non-member", cmd, wf.replace(step, "run: scripts/ci/backend-rust ghost-phase", 1), R_NONMEMBER),
        ("phase missing from one job only", cmd, wf[:macos_at] + wf[macos_at:].replace(f"        {step}\n", "", 1), R_MISSING),
        ("duplicate entry in PHASES", cmd.replace(f"  {victim}\n)", f"  {victim}\n  {victim}\n)"), wf, R_DUP_REG),
        ("invocation present only in a comment", cmd, wf.replace(f"        {step}", f"        run: /bin/true\n        # {step}", 1), R_MISSING),
        ("the gate's own step replaced by an echo", cmd, wf.replace(SELF, "echo neutered"), R_SELF_TEST),
    ]
    cases += [(label, cmd, mw, want) for label, mw, want in fail_open_cases(wf, victim, step)]

    n_caught = n_refused = 0
    for label, mc, mw, want in cases:
        if mc == cmd and mw == wf:
            raise SystemExit(f"SELF-TEST INVALID: mutation '{label}' changed nothing")

        # A case that must make the parser REFUSE, rather than report.
        if want.startswith(MALFORMED):
            needle = want[len(MALFORMED):]
            try:
                evaluate(mc, mw)
            except Malformed as e:
                if needle not in str(e):
                    raise SystemExit(
                        f"SELF-TEST FAILED: '{label}' raised Malformed but not for "
                        f"the expected reason. wanted {needle!r}, got {str(e)!r}"
                    )
                print(f"  self-test  refused: {label}  [{needle}]")
                n_refused += 1
                continue
            raise SystemExit(
                f"SELF-TEST FAILED: '{label}' did not raise Malformed. The parser "
                "accepted a document shape it cannot model."
            )

        errs, _ = evaluate(mc, mw)
        # THE REASON IS PART OF THE ASSERTION, not something read afterwards.
        # "errs is non-empty" accepts a red produced by any side effect of the
        # edit, so a case can pass while testing something other than its label.
        # The count tripwire is stripped first because it rides along on nearly
        # every genuine failure and would satisfy a naive check on its own.
        substantive = [e for e in errs if TRIPWIRE_MARK not in e]
        if not substantive:
            raise SystemExit(
                f"SELF-TEST FAILED: '{label}' produced no substantive error "
                f"(only the count tripwire, if anything): {errs}. A mutation red "
                "solely by the tripwire says nothing about the defect it models."
            )
        if not any(want in e for e in substantive):
            raise SystemExit(
                f"SELF-TEST FAILED: '{label}' was caught for the WRONG REASON. "
                f"expected an error containing {want!r}, got {substantive}"
            )
        print(f"  self-test  caught: {label}  [{want}]")
        n_caught += 1

    for label, mw in universe_controls(wf):
        if mw == wf:
            raise SystemExit(
                f"SELF-TEST INVALID: control '{label}' changed nothing, so its "
                "green proves nothing about the gate's reach"
            )
        errs, _ = evaluate(cmd, mw)
        if errs:
            raise SystemExit(
                f"SELF-TEST FAILED: control '{label}' was judged and went red: "
                f"{errs}. This gate is reaching outside its population."
            )
        print(f"  self-test  not judged: {label}")

    assert_pin_is_deliberate(cmd, wf, victim, step)

    errs, _ = evaluate(cmd, wf)
    if errs:
        raise SystemExit(f"SELF-TEST FAILED: the unmutated tree is red: {errs}")
    # The summary must decompose the way the log above does. An earlier version
    # printed "30 mutations caught" while the lines it summarised read 29
    # `caught` and 1 `refused` — a total that contradicts its own detail, and the
    # kind of number that gets quoted onward without the log beside it.
    print(f"  self-test  {n_caught} mutations caught, {n_refused} malformed "
          f"document refused, {len(universe_controls(wf))} controls left "
          f"unjudged, clean tree green")

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
