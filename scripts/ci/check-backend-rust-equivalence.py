#!/usr/bin/env python3
"""Prove that extracting the Rust pipeline into a command lost nothing.

The predicate is **containment**: every line that lived inside a `run:` block of
`build-and-test-linux` or `build-and-test-macos` at the base revision must still
exist, verbatim after whitespace normalisation, somewhere in the pair

    .github/workflows/backend-ci.yml   (what stayed: provisioning)
    scripts/ci/backend-rust            (what moved: the pipeline)

Comments are included in the check on purpose. The comments in this workflow are
load-bearing — they carry measurements, dates and the reasons a flag exists — so
"the commands moved" is not the claim. The claim is that the commands moved
**with their justifications attached**, and a checker that skipped comments could
not tell the two apart.

    check-backend-rust-equivalence.py --base <rev>       compare against <rev>
    check-backend-rust-equivalence.py --self-test        run the negative control

## Why this is a one-shot instrument, and not a gate

Its input is the *old* text of the workflow. Once the change lands, that text is
gone from the repository, so a committed gate would have no baseline left to
compare against. What survives the merge is this file's receipt, not its verdict.

A durable gate over the same subject needs a different predicate — one whose
referent still exists afterwards, e.g. "every phase in PHASES is invoked by
exactly one workflow step, and every step invokes a phase that exists". That is
worth building and it is not this.

## Declared limit: a needle whose text is a bare shell token proves little

Containment is line-level, so a needle like `fi`, `done` or `else` is satisfied
by any occurrence anywhere in either file. Measured on the real change: 4 of the
242 needles are exactly those tokens, matching the provisioning blocks that
stayed in the workflow as readily as the script's own harness.

This is not a hole to patch — control-flow keywords carry no meaning to lose, and
requiring them to move would be requiring the wrong thing. It is stated because
the checker's number is "242 lines survive", and 4 of those 242 would survive an
extraction that never happened. The 238 that carry text are the load-bearing
ones.

## Why the negative control is not optional

A containment checker that has never been observed to fail is indistinguishable
from one that returns success unconditionally, and this one is being used to
authorise deleting code from a required CI job. `--self-test` mutilates one line
of the new pair in memory and requires the checker to report that exact line as
missing; if it does not, the run aborts before any real verdict is printed.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/backend-ci.yml"
COMMAND = "scripts/ci/backend-rust"

# The two jobs whose `run:` bodies are the subject. Named rather than discovered
# so that a job appearing or disappearing is a visible edit to this file, not a
# silent change in what the proof covers.
JOBS = ("build-and-test-linux", "build-and-test-macos")


def git_show(rev: str, path: str) -> str:
    proc = subprocess.run(
        ("git", "-C", str(REPO_ROOT), "show", f"{rev}:{path}"),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(f"cannot read {path} at {rev}: {proc.stderr.strip()}")
    return proc.stdout


def job_block(workflow: str, job: str) -> str:
    """The YAML under `  <job>:`, up to the next job at the same indent."""
    start = re.search(rf"^  {re.escape(job)}:$", workflow, re.M)
    if not start:
        raise SystemExit(f"job {job} not found — the proof's subject moved")
    rest = workflow[start.end() :]
    nxt = re.search(r"^  [A-Za-z0-9_-]+:$", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def run_lines(block: str) -> list[str]:
    """Every line inside a `run:` scalar, normalised for indentation only.

    Interior whitespace is preserved: collapsing it would make two genuinely
    different commands compare equal, which is the failure this exists to catch.

    Both spellings are collected. A first version matched only the block form
    `run: |` and silently dropped every single-line `run: <command>` — which in
    this workflow is where `cargo clippy --workspace`, `cargo build`,
    `cargo fetch --locked`, the compile-fail proofs and the APNS lint live. It
    reported 46 lines for a subject that has far more, and the shortfall looked
    exactly like a clean measurement.
    """
    out: list[str] = []
    lines = block.split("\n")
    i = 0
    while i < len(lines):
        # Step-level comments. In this workflow they are the bulk of the
        # content and the whole reason the extraction is delicate: the
        # `Excluded workspace members` step is 72 non-blank lines, of which
        # 64 are comments sitting ABOVE `run:` — the measurements, the dates,
        # and the reason each flag exists. A first version of this file
        # collected only run-scalar lines while its own docstring claimed
        # comments were covered, and would have certified an extraction that
        # deleted every justification.
        if lines[i].strip().startswith("#"):
            out.append(lines[i].strip())
            i += 1
            continue
        block_open = re.match(r"^(\s+)run: [|>]", lines[i])
        inline = re.match(r"^\s+run: (?![|>])(.+)$", lines[i])
        if inline:
            out.append(inline.group(1).strip())
            i += 1
            continue
        if not block_open:
            i += 1
            continue
        indent = len(block_open.group(1))
        i += 1
        while i < len(lines):
            line = lines[i]
            if line.strip() and (len(line) - len(line.lstrip())) <= indent:
                break
            if line.strip():
                out.append(line.strip())
            i += 1
    return out


def step_env(block: str) -> list[tuple[str, str]]:
    """Every `KEY: value` bound under a step-level `env:`.

    A SECOND predicate, because containment above is structurally blind here: an
    `env:` line is neither a comment nor part of a `run:` scalar, so it is not in
    the needle set and deleting one costs nothing in that proof.

    The blindness is not academic. The two bindings in these jobs are

        THEYOS_REQUIRE_NOISE_INTEROP=1        turns the Noise interop test's two
                                              skip paths into failures
        THEYOS_PHASE3_RECOVERY_TIMEOUT_SECS=1 the only reason three ~300s tests
                                              fit inside the job budget

    Drop the first and the test still runs, still passes, and silently stops
    checking — the exact shape the step's own comment says it exists to prevent.
    Every step would exit 0 and the containment proof would print OK.
    """
    out: list[tuple[str, str]] = []
    lines = block.split("\n")
    for i, line in enumerate(lines):
        if not re.match(r"^        env:$", line):
            continue
        j = i + 1
        while j < len(lines) and re.match(r"^          \S", lines[j]):
            k, _, v = lines[j].strip().partition(":")
            out.append((k.strip(), v.strip().strip('"').strip("'")))
            j += 1
    return out


def env_bound(key: str, value: str, workflow: str, command: str) -> bool:
    """Is KEY still bound to VALUE, in either surface and either spelling?

    The binding may legitimately stay in the workflow step (`KEY: "1"`) or move
    into the command (`export KEY=1`, or a `KEY=1 cmd` prefix). All three are the
    same guarantee, so the predicate accepts all three and cares only that the
    guarantee still exists somewhere. What it refuses is the binding vanishing.
    """
    v = re.escape(value)
    k = re.escape(key)
    if re.search(rf'^\s*{k}:\s*["\']?{v}["\']?\s*$', workflow, re.M):
        return True
    if re.search(rf'^\s*(export\s+)?{k}=["\']?{v}["\']?\s*$', command, re.M):
        return True
    return bool(re.search(rf'(?:^|\s){k}=["\']?{v}["\']?(?:\s|$)', command, re.M))


def haystack(read) -> set[str]:
    """Every line of the new pair, plus the payload of inline `run:` lines.

    The extra form is not cosmetic. A needle taken from `run: cargo build` is
    stored as `cargo build`, but the same text sitting in a workflow reads
    `run: cargo build` after stripping indentation — so the two never match and
    the checker reports nine perfectly-present commands as lost. The self-test
    caught exactly that: it wounded one line and the checker named ten.
    """
    text = read(WORKFLOW) + "\n" + read(COMMAND)
    out: set[str] = set()
    for raw in text.split("\n"):
        line = raw.strip()
        if not line:
            continue
        out.add(line)
        inline = re.match(r"^run: (?![|>])(.+)$", line)
        if inline:
            out.add(inline.group(1).strip())
    return out


def missing(needles: list[str], hay: set[str]) -> list[str]:
    return [n for n in needles if n not in hay]


def self_test(needles: list[str], hay: set[str]) -> None:
    """Mutilate one line and require the checker to name it.

    The victim is the LAST needle rather than the first: a checker that returns
    on its first match would pass a mutation applied to the first element.
    """
    if not needles:
        raise SystemExit("self-test impossible: the extractor found no lines")
    victim = needles[-1]
    if victim not in hay:
        raise SystemExit(f"self-test invalid: victim already missing: {victim!r}")
    wounded = set(hay)
    wounded.discard(victim)
    caught = missing(needles, wounded)
    if caught != [victim]:
        raise SystemExit(
            "SELF-TEST FAILED: removing a line the checker should have found "
            f"produced {caught!r} instead of exactly [{victim!r}]. The checker "
            "does not discriminate; its green verdict would mean nothing."
        )
    print(f"self-test: OK — the checker names the wounded line ({victim[:60]!r})")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    old = git_show(args.base, WORKFLOW)
    needles: list[str] = []
    envs: list[tuple[str, str]] = []
    for job in JOBS:
        block = job_block(old, job)
        needles += run_lines(block)
        envs += step_env(block)
    envs = sorted(set(envs))
    # Deduplicate while preserving order: the two jobs share 15 identical steps,
    # so a raw count would double most lines and make the total meaningless.
    seen: set[str] = set()
    needles = [n for n in needles if not (n in seen or seen.add(n))]

    def read_worktree(path: str) -> str:
        p = REPO_ROOT / path
        return p.read_text() if p.exists() else ""

    # PRECONDITION, not a check. Before the command file exists, the "new" pair
    # is just the unchanged workflow, so containment is trivially true and the
    # green means nothing. The first run of this checker printed
    # "OK: all 46 lines survive" with scripts/ci/backend-rust absent — a pass
    # about a transformation that had not happened.
    command_text = read_worktree(COMMAND).strip()
    if not command_text:
        raise SystemExit(
            f"{COMMAND} is missing or empty: there is nothing to compare against. "
            "Containment against an unchanged workflow is vacuously true."
        )

    hay = haystack(read_worktree)
    wf_now = read_worktree(WORKFLOW)

    print(f"base            {args.base}")
    print(f"lines to place  {len(needles)}  (deduplicated across both jobs)")
    print(f"env bindings    {len(envs)}")

    self_test(needles, hay)

    # Negative control for the env predicate, and it needs its own: the two
    # predicates share no code, so the containment self-test says nothing about
    # whether this one can fail. Blank out the value everywhere and require the
    # binding to be reported as lost.
    if envs:
        k0, v0 = envs[0]
        if env_bound(k0, v0, wf_now.replace(v0, "\0"), command_text.replace(v0, "\0")):
            raise SystemExit(
                f"SELF-TEST FAILED: {k0} still read as bound after its value was "
                "destroyed in both surfaces. The env predicate cannot fail, so "
                "its pass means nothing."
            )
        print(f"self-test: OK — the env predicate reports {k0} lost when it is")

    unbound = [(k, v) for k, v in envs if not env_bound(k, v, wf_now, command_text)]
    gone = missing(needles, hay)

    if gone:
        print(f"\nMISSING {len(gone)} line(s) — the extraction lost them:\n")
        for g in gone:
            print(f"  {g}")
    if unbound:
        print(f"\nUNBOUND {len(unbound)} env binding(s) — the guarantee vanished:\n")
        for k, v in unbound:
            print(f"  {k}={v}")
    if gone or unbound:
        return 1

    print(f"OK: all {len(needles)} lines survive in {WORKFLOW} + {COMMAND}")
    print(f"OK: all {len(envs)} env bindings still bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
