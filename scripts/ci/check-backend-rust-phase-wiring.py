#!/usr/bin/env python3
"""The registry, the functions and the workflow must name the same phases.

Unlike `check-backend-rust-equivalence.py`, which compares against the *old*
workflow text and therefore loses its referent the moment the change lands, this
gate's subject survives every merge. It is meant to sit in CI forever.

Three sets, per job, compared for EQUALITY and UNIQUENESS:

    A  PHASES=( ... ) in admin/rust/scripts/backend-rust      the registry
    B  the phase_* functions defined there            what can execute
    C  the phases each workflow job actually invokes  what CI runs

## Why this is not a tidiness check

`admin/rust/scripts/backend-rust all` is a published interface — it is how the pipeline
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
COMMAND = REPO_ROOT / "admin/rust/scripts/backend-rust"
# Where it used to be, ASSEMBLED FROM PARTS so the literal never appears in this
# file. A guard that searches for a string it also contains flags itself: the
# first version of this check reported its own source as a stale reference and
# went red on a clean tree. Splitting the constant is the mechanical fix — an
# exclusion list for "the guard's own file" would work today and rot the moment
# the check moves or gains a second reader.
RETIRED_PATH = "scripts/ci/" + "backend-rust"
WORKFLOW = REPO_ROOT / ".github/workflows/backend-ci.yml"

JOBS = ("build-and-test-linux", "build-and-test-macos")
EXPECTED_COMMON = 11
SELF = "scripts/ci/check-backend-rust-phase-wiring.py"

PHASE_CALL = re.compile(r"^admin/rust/scripts/backend-rust ([a-z0-9][a-z0-9-]*)$")
SELF_TEST_CMD = f"python3 {SELF} --self-test"
LIVE_CMD = f"python3 {SELF}"

# Step attributes that stop a step being an unconditional, load-bearing
# invocation. `shell` sits with the other two because changing the shell changes
# how a failure propagates, which is the property being asserted.
STEP_DISQUALIFYING = ("if", "continue-on-error", "shell")

# ---------------------------------------------------------------------------
# THE JOB-LEVEL CONTRACT IS AN ALLOW-LIST, AND THAT IS THE WHOLE POINT.
#
# Three review rounds were spent adding one forbidden key at a time — `if`,
# `continue-on-error`, `shell`, then `needs` — and each round a reviewer found
# more: an empty `strategy.matrix.include`, `environment`, `concurrency` with
# cancel-in-progress, `container`, `defaults.run.working-directory`. Every one
# leaves the steps textually unconditional and this gate counting a full set of
# invocations for a job that may run nothing.
#
# The lesson is not "we missed five keys". It is that ENUMERATING BY KEY IS THE
# WRONG AXIS: the set of job keys is a surface GitHub owns and extends, so a
# sweep by name-list only ever finds the names already on the list. What the
# contract actually says is positive —
#
#     each judged job must prove its own phases, by itself
#
# — and that is not expressible as a negative list over somebody else's
# vocabulary. So the boundary is inverted: these keys are permitted, everything
# else stops the gate until a human looks at it.
#
# THE COST IS DELIBERATE AND IS STATED HERE RATHER THAN DISCOVERED LATER.
# Adding `permissions:`, `env:` or any other perfectly legitimate key to a judged
# job will turn this gate RED. That is the intended behaviour: a new top-level
# key on a job whose only purpose is to prove 11 phases is a review event, even
# when it is benign. Clearing it means adding the key here — one line, visible in
# the diff, with the self-test's teeth applying to the new shape.
#
# The scope is deliberately narrow. Only the three judged jobs are governed;
# every other job in the workflow is outside this gate's universe and may carry
# whatever it needs. A control in `--self-test` proves that widening the universe
# to all jobs turns the self-test RED.
CONTRACT_JOB = "backend-rust-command-contract"
JOB_KEY_ALLOWLIST = frozenset({"name", "runs-on", "timeout-minutes"})

# THE ALLOW-LIST WAS STILL ON THE WRONG AXIS, ONE LEVEL DOWN.
#
# Naming the permitted keys says nothing about their VALUES, and a value can stop
# a job as thoroughly as an extra key. Measured in review: setting the contract
# job's `runs-on` to `[self-hosted, theyos-runner-that-does-not-exist]` — valid
# GitHub grammar, since a label array requires a runner satisfying every label —
# means the job is never dispatched, while this gate returned no errors at all.
# The instrument can be switched off by editing a key it already permits.
#
# So the contract is POSITIVE on both axes: these keys must be PRESENT, and each
# must carry the exact value this job is supposed to carry.
#
# The contract is EXACT and PER JOB, not a global set of admitted values. A
# global set would let the Linux job claim macOS's runner, or either job take the
# contract job's 5-minute budget, and every one of those is a real change to what
# CI proves while the gate stayed quiet.
#
# All three keys are load-bearing, which is why all three are pinned — but the
# reason `name` matters is NOT the same for all three jobs, and saying so
# uniformly would be false:
#
#   name              on build-and-test-linux and build-and-test-macos it is the
#                     CHECK CONTEXT branch protection requires, so a rename
#                     silently removes a context that was supposed to be required.
#                     On backend-rust-command-contract it is NOT protected — that
#                     job is deliberately outside main's required set — so the pin
#                     holds the published identity the body, the logs and this
#                     gate all name, and claims no protection it does not have.
#   runs-on           decides whether the job is dispatched at all
#   timeout-minutes   is the budget; shrink it and the phases stop finishing
#
# The parser stores raw strings, so the comparison is exact string equality.
JOB_CONTRACT = {
    "build-and-test-linux": {
        "name": "Build & Test (Rust / Linux)",
        "runs-on": "ubuntu-latest",
        "timeout-minutes": "75",
    },
    "build-and-test-macos": {
        "name": "Build & Test (Rust / macOS)",
        "runs-on": "macos-15",
        "timeout-minutes": "75",
    },
    CONTRACT_JOB: {
        "name": "Backend Rust command contract",
        "runs-on": "ubuntu-latest",
        "timeout-minutes": "5",
    },
}
REQUIRED_JOB_KEYS = ("name", "runs-on", "timeout-minutes")

# The self-referential limit, stated honestly rather than overclaimed. A value —
# or an `if:` — on the CONTRACT JOB itself can prevent this checker from running,
# and a check that does not run reports nothing. The earlier text claimed only
# deleting the whole job could silence it; that was too narrow. The backstop for
# this class is branch protection and review of the workflow diff, not this file,
# and `Backend Rust command contract` is deliberately not among main's required
# contexts — so its absence does not block a merge on its own.


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


def assert_command_location(wf: str, cmd_path: Path) -> list[str]:
    """The dispatcher must live outside the repository-root `scripts/` namespace,
    and nothing may still reference where it used to be.

    Both halves exist because of a real review BLOCK. The command first shipped
    under the repository-root `scripts/` tree (see `RETIRED_PATH`), and its own
    header argued that the no-bash policy check did not flag it because that
    check matches `*.sh` and this file has no extension. That reasoning was
    refused, correctly: an artifact that survives by a detector's blind spot is
    undetected, not compliant, and documenting the gap does not turn it into
    permission.

    The retired path is referred to indirectly here, and `RETIRED_PATH` is
    assembled from parts, for the same reason: this function greps for that
    string, so any file spelling it out — including this one — becomes a hit.
    A guard whose prose can trip it is a guard that gets an exclusion list, and
    exclusion lists are where guards go to stop guarding.

    So the location is now the compliance, which means the location needs teeth —
    otherwise the next move back is silent. This fails if the executable reappears
    under root `scripts/`, and fails if the workflow or either checker still cites
    the retired path.
    """
    errs = []
    rel = cmd_path.relative_to(REPO_ROOT).as_posix()
    if rel.startswith("scripts/"):
        errs.append(
            f"the dispatcher is at {rel}, inside the repository-root `scripts/` "
            "namespace that P28 governs. It lives in admin/rust/scripts/ "
            "deliberately; moving it back needs a policy decision, not an edit."
        )

    # THE RETIRED PATH MUST NOT EXIST ON DISK — checked by stat, not by config.
    #
    # The previous version asked only whether the CONFIGURED command sat under
    # `scripts/`, which is a question about this file's constant. Review planted
    # a byte-identical 100755 copy at the retired path while leaving the
    # canonical one in place, and this gate returned rc=0: the copy is invisible
    # to `no-bash-policy` too, because it has no `.sh` extension. So the body's
    # claim that the gate fails "if the executable reappears" was false as
    # written — a resurrected copy is exactly the case it was supposed to catch.
    #
    # The promise here is deliberately NARROW and verifiable: this one retired
    # path must not exist. A namespace-wide claim would need a defined universe
    # and a real sweep, and an unverifiable wide promise is what produced this
    # finding in the first place.
    # os.path.lexists, NOT .exists(): a dangling symlink at the retired path is
    # a real reappearance and `.exists()` follows the link and reports False.
    # Measured before this line existed — a broken symlink there left the gate
    # green. The promise is "this path must not exist", and a name in the
    # directory exists whether or not its target does.
    resurrected = REPO_ROOT / RETIRED_PATH
    if os.path.lexists(resurrected):
        errs.append(
            f"{RETIRED_PATH} exists on disk. The dispatcher was moved out of the "
            "repository-root `scripts/` namespace for P28; a copy left or "
            "recreated there is undetected by the policy check (no `.sh` "
            "extension) and re-creates exactly the condition review blocked."
        )
    # The COMMAND ITSELF is on this list, and it was the surface I missed. My
    # first sweep covered only the files I had edited — workflow and the two
    # checkers — and reported "0 residual references" while the moved script
    # still carried four: one narrative line and, worse, three usage examples
    # that are operational instructions telling a reader to run a path that no
    # longer exists. A relocation's most likely stale reference is inside the
    # thing relocated.
    stale = [p for p in (WORKFLOW, COMMAND, Path(__file__).resolve(),
                         REPO_ROOT / "scripts/ci/check-backend-rust-equivalence.py")
             if p.exists() and RETIRED_PATH in p.read_text()]
    if stale:
        errs.append(
            f"the retired path {RETIRED_PATH!r} is still cited in "
            f"{[p.name for p in stale]} — a reference to where the command used "
            "to be will not run it, and will not fail loudly either."
        )
    return errs


def assert_root_resolves(cmd_path: Path) -> list[str]:
    """RUN the command's `--check-root` and require the repository root back.

    Tested by value because the textual form cannot be tested at all. The line is

        REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

    and the correct number of `../` is a function of THIS FILE'S DEPTH. A grep
    that knows the right count has to be told the depth — the very fact that
    changes when the file moves — so it would agree with whatever the file says
    and confirm nothing.

    This defect was live and shipped past every text-level check I had: the file
    moved one level deeper, the line kept its two `../`, and REPO_ROOT resolved
    to <repo>/admin. `bash -n` parses the assignment without running it; this
    gate and the equivalence checker read the file as text. All green, and every
    phase would have failed on its first `cd` into <repo>/admin/admin/rust.

    Executed from a temporary cwd, so a resolution that secretly depends on the
    caller's directory fails here instead of in CI.
    """
    import subprocess
    import tempfile

    try:
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.run((str(cmd_path), "--check-root"), cwd=tmp,
                               capture_output=True, text=True, timeout=30)
    except OSError as e:
        return [f"could not execute {cmd_path.name} --check-root: {e}"]
    if p.returncode != 0:
        return [f"{cmd_path.name} --check-root failed (rc={p.returncode}): "
                f"{p.stderr.strip()[:200]}"]
    resolved = Path(p.stdout.strip())
    if resolved != REPO_ROOT:
        return [f"{cmd_path.name} resolves REPO_ROOT to {resolved}, expected "
                f"{REPO_ROOT} — the path arithmetic does not match the file's "
                "depth, and every phase's `cd` would land in the wrong tree"]
    return []


def judged_jobs() -> tuple[str, ...]:
    """The jobs this gate governs: the two Rust jobs and the job hosting the gate."""
    return JOBS + (CONTRACT_JOB,)


def why_pinned(job: str, key: str) -> str:
    """Why THIS key on THIS job is pinned — never a claim that is false elsewhere.

    A single sentence covering all three jobs would have to say `name` is the
    context branch protection requires, and that is untrue of the contract job,
    which this gate itself documents as outside main's required set. A diagnosis
    that overstates its own authority teaches the reader to discount it.
    """
    if key == "runs-on":
        return ("`runs-on` decides whether the job is dispatched at all; a label "
                "set no runner satisfies means it never starts while its steps "
                "still read as unconditional.")
    if key == "timeout-minutes":
        return ("`timeout-minutes` is the budget this job's phases need; too "
                "small and they stop finishing.")
    if job == CONTRACT_JOB:
        return ("`name` is this job's published identity — the body, the logs "
                "and this gate all refer to it. It is NOT among main's required "
                "contexts, so the pin protects recognisability, not enforcement.")
    return ("`name` is the CHECK CONTEXT branch protection requires for this "
            "job; renaming it silently removes a required context.")


def assert_job_keys(jobs: dict) -> list[str]:
    """Every top-level key on a judged job must be on the allow-list.

    Fail-closed, and it names the job, the offending key and the allow-list, so
    the reader is not left guessing what would satisfy it. An empty value fails
    exactly like a populated one — `needs:` with nothing under it disqualifies a
    job just as thoroughly as `needs: [x]`, and a parser that reads the value
    would have to understand every spelling to know that.

    `steps` is not on the list because it is not stored as an attribute; it is
    the section this gate walks, and its own rules (exactly one, never merged)
    live in the parser.
    """
    errs = []
    for name in judged_jobs():
        attrs = jobs[name]["attrs"]
        unknown = sorted(set(attrs) - JOB_KEY_ALLOWLIST)
        if unknown:
            errs.append(
                f"{name}: unknown top-level key(s) {unknown} — a judged job may "
                f"carry only {sorted(JOB_KEY_ALLOWLIST)} plus `steps`. A new key "
                "here is a review event even when legitimate: it can stop the "
                "job running while every step still reads as unconditional. Add "
                "it to JOB_KEY_ALLOWLIST deliberately, with teeth."
            )
        missing = [k for k in REQUIRED_JOB_KEYS if k not in attrs]
        if missing:
            errs.append(
                f"{name}: missing required key(s) {missing} — the contract is "
                "positive; a judged job must carry these, not merely avoid "
                "carrying others."
            )
        want = JOB_CONTRACT[name]
        for key in REQUIRED_JOB_KEYS:
            if key not in attrs:
                continue                       # already reported as missing
            if attrs[key] != want[key]:
                errs.append(
                    f"{name}: {key} is {attrs[key]!r}, expected {want[key]!r}. "
                    f"{why_pinned(name, key)} Changing it is a review decision, "
                    "not an edit."
                )
    return errs


def evaluate(cmd: str, wf: str) -> tuple[list[str], dict[str, int]]:
    reg, fns = registry(cmd), functions(cmd)
    jobs, wf_shell = parse_workflow(wf)
    for name in judged_jobs():
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

    errs += assert_command_location(wf, COMMAND)
    errs += assert_root_resolves(COMMAND)
    errs += assert_job_keys(jobs)
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
R_UNKNOWN_KEY = "unknown top-level key"   # the allow-list, now the job boundary
R_MISSING_KEY = "missing required key"    # the positive half of the same contract
R_JOB_VALUE = "expected"                  # a pinned key carrying the wrong value
R_RESURRECTED = "exists on disk"          # the retired path, checked by stat
MALFORMED = "MALFORMED:"             # prefix: the case must RAISE, not return


def fail_open_cases(wf: str, victim: str, step: str) -> list[tuple[str, str]]:
    """Every way a step can be in the file and still not gate anything.

    In all of them the text `admin/rust/scripts/backend-rust <victim>` remains plainly
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
            phase_step(f"        run: |\n          admin/rust/scripts/backend-rust {victim}\n"),
            R_MISSING,
        ),
        ("`uses:` a composite action instead of `run:`", phase_step(f"        uses: ./.github/actions/{victim}\n"), R_MISSING),
        # --- the job stops proving its own phases -----------------------------
        #
        # Every case below is now caught by the ALLOW-LIST, not by a per-key
        # rule, and their expected reason says so. That is the point: three
        # review rounds added `if`, `continue-on-error`, `shell`, `needs` one at
        # a time, and each round produced more — matrix, environment,
        # concurrency, container, working-directory. They are kept as named
        # cases anyway, because a case that names the exact YAML fails when
        # someone rewrites the boundary and forgets one; the allow-list is the
        # rule, these are its witnesses.
        ("job conditional (`if:`)", job_attr("    if: always()\n"), R_UNKNOWN_KEY),
        ("job advisory (`continue-on-error:`)", job_attr("    continue-on-error: true\n"), R_UNKNOWN_KEY),
        ("job-level `defaults.run.shell`", job_attr("    defaults:\n      run:\n        shell: bash\n"), R_UNKNOWN_KEY),
        # --- `needs:`, in every spelling -------------------------------------
        #
        # All four remain because the FAIL-OPEN is identical across them while
        # what the parser stores is not:
        #
        #   needs: [x]      attrs['needs'] = '[x]'      members visible
        #   needs: x        attrs['needs'] = 'x'        members visible
        #   needs: ['x']    attrs['needs'] = "['x']"    members visible
        #   needs:          attrs['needs'] = ''         MEMBERS LOST — the block
        #     - x                                       list is skipped entirely
        #
        # Key PRESENCE catches all four; anything transitive ("only disqualify
        # if the needed job is itself conditional") is structurally blind to the
        # block form, because no members survive to follow. The allow-list is
        # presence-based for exactly this reason.
        ("job `needs:` — flow list", job_attr("    needs: [installer-tests]\n"), R_UNKNOWN_KEY),
        ("job `needs:` — bare scalar", job_attr("    needs: installer-tests\n"), R_UNKNOWN_KEY),
        ("job `needs:` — quoted flow list", job_attr("    needs: ['installer-tests']\n"), R_UNKNOWN_KEY),
        ("job `needs:` — BLOCK list (members not parsed)", job_attr("    needs:\n      - installer-tests\n"), R_UNKNOWN_KEY),
        # --- the forms a NEGATIVE list would have missed ----------------------
        #
        # None of these was on any blacklist; all five were green before the
        # allow-list and are red after it, without being named by the predicate.
        ("empty matrix (`strategy.matrix.include: []`)", job_attr("    strategy:\n      matrix:\n        include: []\n"), R_UNKNOWN_KEY),
        ("`environment:` (can gate on required reviewers)", job_attr("    environment: production\n"), R_UNKNOWN_KEY),
        ("`concurrency:` with cancel-in-progress", job_attr("    concurrency:\n      group: x\n      cancel-in-progress: true\n"), R_UNKNOWN_KEY),
        ("`container:`", job_attr("    container: alpine\n"), R_UNKNOWN_KEY),
        ("`defaults.run.working-directory` — the sibling of the one key read", job_attr("    defaults:\n      run:\n        working-directory: admin/rust\n"), R_UNKNOWN_KEY),
        # --- the deliberate cost, asserted rather than left implicit ----------
        #
        # `permissions:` is legitimate and harmless. It is RED here on purpose:
        # a new top-level key on a job whose whole job is to prove 11 phases is a
        # review event even when benign. If this case ever stops being red, the
        # allow-list has been widened without anyone deciding to widen it.
        ("`permissions:` — LEGITIMATE, and red by design", job_attr("    permissions:\n      contents: read\n"), R_UNKNOWN_KEY),
        # --- an ALLOWED key whose VALUE stops the job ------------------------
        #
        # The allow-list named keys and said nothing about values. Review set the
        # contract job's `runs-on` to a label array no runner satisfies — valid
        # GitHub grammar — and the job is never dispatched while this gate
        # reported nothing. The instrument could be switched off by editing a key
        # it already permits, which is the same axis error one level down.
    ]

    # --- NINE cases: every pinned key, on every judged job --------------------
    #
    # Three keys x three jobs, each mutated on its own, because a global "admitted
    # values" set would let one job take another's runner or budget and stay
    # green. Each case must name the job, the key and the value.
    #
    # `name` is in here for a reason that DIFFERS by job, which is why the
    # diagnosis comes from `why_pinned` rather than a single sentence: on the two
    # Rust jobs it is the required check context, and on the contract job it is
    # the published identity of a job that is deliberately not required.
    # `timeout-minutes` is in here because a budget too small is a job that
    # cannot finish its phases.
    for _job, _want in JOB_CONTRACT.items():
        _blk_start = wf.index(f"  {_job}:")
        _blk_end = wf.index("    steps:", _blk_start)
        _blk = wf[_blk_start:_blk_end]
        for _key, _bad in (("name", "Renamed Job"),
                           ("runs-on", "[self-hosted, theyos-runner-that-does-not-exist]"),
                           ("timeout-minutes", "1")):
            _line = f"    {_key}: {_want[_key]}\n"
            assert _line in _blk, (_job, _key)
            _mut = wf[:_blk_start] + _blk.replace(_line, f"    {_key}: {_bad}\n", 1) + wf[_blk_end:]
            cases.append((f"{_job}: {_key} changed to {_bad[:34]!r}", _mut, R_JOB_VALUE))

    cases += [
        # --- the POSITIVE half: a required key removed ------------------------
        (
            "judged job missing a required key (`timeout-minutes`)",
            wf.replace("    timeout-minutes: 5\n", "", 1),
            R_MISSING_KEY,
        ),
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
        # The allow-list's blast radius, asserted. An unjudged job carrying EVERY
        # form the allow-list rejects must still be green: the universe is three
        # jobs, and a gate that reached further would red on ordinary workflow
        # edits made by people who have never heard of it.
        (
            "an unrelated JOB carrying every rejected form at once",
            wf.replace(
                "  installer-tests:\n",
                "  installer-tests:\n"
                "    needs: [no-bash-policy]\n"
                "    if: always()\n"
                "    continue-on-error: true\n"
                "    environment: production\n"
                "    container: alpine\n"
                "    permissions:\n      contents: read\n"
                "    strategy:\n      matrix:\n        include: []\n",
                1,
            ),
        ),
    ]


def assert_retired_path_absent(cmd: str, wf: str) -> None:
    """Plant a real copy AND a dangling symlink; require the gate to see both.

    FILESYSTEM mutants, not text ones, because the defect they model is a name
    existing in a directory. Two forms because they fail different predicates:

        a regular 100755 copy    caught by `.exists()` and by `lexists`
        a DANGLING symlink       `.exists()` follows the link and returns False

    The second is why this guard uses `os.path.lexists`. Measured before the
    change: a broken symlink at the retired path left the gate green, and the
    promise is "this path must not exist" — a name in a directory exists whether
    or not its target does.

    Restores in a `finally` and asserts the clean state afterwards, so a failure
    cannot leave the working tree dirty for the next reader.
    """
    import os
    import shutil

    resurrected = REPO_ROOT / RETIRED_PATH
    if os.path.lexists(resurrected):
        raise SystemExit(
            f"SELF-TEST INVALID: {RETIRED_PATH} already exists before a mutant "
            "is planted; the tree is not in the state these cases assume."
        )
    created_dir = not resurrected.parent.exists()
    resurrected.parent.mkdir(parents=True, exist_ok=True)

    def _cleanup() -> None:
        if os.path.lexists(resurrected):
            os.unlink(resurrected)
        if created_dir:
            try:
                resurrected.parent.rmdir()
            except OSError:
                pass

    for label, plant in (
        ("a regular 100755 copy", lambda: (shutil.copy2(COMMAND, resurrected),
                                           os.chmod(resurrected, 0o755))),
        ("a DANGLING symlink", lambda: os.symlink("/nonexistent/backend-rust",
                                                  resurrected)),
    ):
        try:
            plant()
            errs, _ = evaluate(cmd, wf)
            if not any(R_RESURRECTED in e for e in errs):
                raise SystemExit(
                    f"SELF-TEST FAILED: {label} at {RETIRED_PATH} did not turn "
                    "the gate red. The claim that it fails when the executable "
                    "reappears would be false for that form."
                )
            print(f"  self-test  filesystem: {label} at the retired path is caught")
        finally:
            _cleanup()

    errs, _ = evaluate(cmd, wf)
    if errs:
        raise SystemExit(
            f"SELF-TEST INVALID: the tree did not come back clean after the "
            f"filesystem mutants: {errs}"
        )


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
        f"        run: admin/rust/scripts/backend-rust new-phase\n",
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
    step = f"run: admin/rust/scripts/backend-rust {victim}"
    macos_at = wf.index("  build-and-test-macos:")

    cases: list[tuple[str, str, str, str]] = [
        ("function defined but absent from PHASES", cmd.replace(f"  {victim}\n)", ")"), wf, R_ORPHAN),
        ("PHASES entry with no function", re.sub(rf"{fn}\(\) \{{.*?\n\}}\n", "", cmd, flags=re.S), wf, R_UNDEFINED),
        ("workflow invokes a non-member", cmd, wf.replace(step, "run: admin/rust/scripts/backend-rust ghost-phase", 1), R_NONMEMBER),
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

    assert_retired_path_absent(cmd, wf)
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
