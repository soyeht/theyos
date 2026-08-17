#!/usr/bin/env python3
"""Report branch/worktree sprawl and fail on branches that would revert shipped work.

Sprawl is untidy: merged-but-undeleted branches, husk branches with no unique
patch, disposable worktrees and unpushed local work are REPORTED and exit 0.

A branch that would delete work the main ref already has is a hazard and exits 1.

Any input this gate cannot read, parse or classify exits 2. A guard search that
finds nothing must never be reported as clean.

THE REVERTING PREDICATE, stated precisely.

  Let M be the main ref, B a branch, and A = merge-base(M, B).
  Let component(p) be the nearest ancestor directory of p that holds a package
  manifest in M's tree, else the first two path segments.
  Let owned(B) = { component(p) : p changed between A and B } -- the components
  the branch actually touches, i.e. the ones it presents itself as authoritative
  over.

  A path p is REVERTED by B when all of:
    (1) component(p) is in owned(B)                -- B claims this component;
    (2) p exists in M;
    (3) some line that M ADDED between A and M is absent from B's version of p.

  reverted_lines(B, p) is the multiset size of that absence.

  Condition (3) is what separates "the branch never had it" from "the branch
  deliberately deleted it". A line the branch deliberately removed existed at A,
  so it is not among M's additions since A and is never counted. A line M added
  after the fork cannot have been deliberately removed by a branch that never
  saw it -- that one is counted. Both sides of this distinction are covered by
  the co-located negative tests.

  Condition (1) is what separates a hazard from ordinary staleness. Every
  unrebased branch is behind M somewhere; a three-way merge resolves that
  correctly at paths the branch never touched. The hazard is a branch that looks
  like the current state of a component while missing that component's shipped
  work -- the shape that made a branch named for delivered work carry a
  four-figure pure deletion of the crate it was named after.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAMES = ("Cargo.toml", "package.json", "pyproject.toml", "go.mod")
PATH_CHUNK = 300
DEFAULT_MAIN_REF = "origin/main"
DEFAULT_GIT_TIMEOUT = 300
GH_PR_LIST_ATTEMPTS = 3
GH_PR_LIST_RETRY_SECONDS = 5.0
GH_HTTP_STATUS = re.compile(
    rb"(?:HTTP(?:/\d(?:\.\d)?)?[: ]+|status code:\s*)([45]\d\d)\b",
    re.IGNORECASE,
)
GH_NAMED_HTTP_STATUS = re.compile(
    rb"\b([45]\d\d)\s+(?:Bad Request|Unauthorized|Forbidden|Not Found|"
    rb"Service Unavailable|Bad Gateway|Gateway Timeout)\b",
    re.IGNORECASE,
)


class GateError(RuntimeError):
    """The gate could not complete its own analysis. Never a pass."""


@dataclass(frozen=True)
class RevertedPath:
    path: str
    reverted_lines: int
    branch_has_file: bool


@dataclass(frozen=True)
class BranchReport:
    ref: str
    name: str
    is_local: bool
    has_merge_base: bool
    unique_commits: int
    unpushed_commits: int
    pr_number: int | None
    pr_state: str | None
    reverted: tuple[RevertedPath, ...]

    @property
    def reverted_lines(self) -> int:
        return sum(item.reverted_lines for item in self.reverted)

    @property
    def label(self) -> str:
        """Ref without its namespace: 'feat/x' local, 'origin/feat/x' remote."""
        for prefix in ("refs/heads/", "refs/remotes/"):
            if self.ref.startswith(prefix):
                return self.ref[len(prefix) :]
        return self.ref


@dataclass(frozen=True)
class WorktreeReport:
    display: str
    branch: str | None
    on_disk: bool
    tracked_changes: int
    untracked_files: int
    is_primary: bool = False

    @property
    def dirty(self) -> bool:
        return self.tracked_changes > 0 or self.untracked_files > 0


# --------------------------------------------------------------------------
# git plumbing. Every non-zero exit, timeout or missing binary is a GateError.
# --------------------------------------------------------------------------


def run_git(repo: Path, *args: str, timeout: int = DEFAULT_GIT_TIMEOUT) -> tuple[int, str]:
    try:
        result = subprocess.run(
            ("git", "-C", str(repo), *args),
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:  # pragma: no cover - environment shaped
        raise GateError("git executable not found") from error
    except subprocess.TimeoutExpired as error:
        raise GateError(f"git {args[0]} timed out after {timeout}s") from error
    return result.returncode, result.stdout.decode("utf-8", "replace")


def git(repo: Path, *args: str, timeout: int = DEFAULT_GIT_TIMEOUT) -> str:
    code, out = run_git(repo, *args, timeout=timeout)
    if code != 0:
        raise GateError(f"git {' '.join(args[:2])} failed with exit {code}")
    return out


def resolve_ref(repo: Path, ref: str, timeout: int) -> str:
    for candidate in (ref, f"refs/heads/{ref}", f"refs/remotes/{ref}", f"refs/remotes/origin/{ref}"):
        code, out = run_git(repo, "rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}", timeout=timeout)
        if code == 0 and out.strip():
            return candidate
    raise GateError(f"ref could not be resolved: {ref}")


# --------------------------------------------------------------------------
# component scoping
# --------------------------------------------------------------------------


def manifest_roots(repo: Path, main_ref: str, timeout: int) -> tuple[str, ...]:
    listing = git(repo, "ls-tree", "-r", "--name-only", main_ref, timeout=timeout)
    roots: set[str] = set()
    for line in listing.splitlines():
        if "/" not in line:
            continue
        head, _, name = line.rpartition("/")
        if name in MANIFEST_NAMES and head:
            roots.add(head)
    return tuple(sorted(roots, key=lambda root: (-len(root), root)))


def component_of(path: str, roots: tuple[str, ...]) -> str:
    for root in roots:
        if path.startswith(root + "/"):
            return root
    parts = path.split("/")
    if len(parts) >= 3:
        return "/".join(parts[:2])
    if len(parts) == 2:
        return parts[0]
    return "<repo-root>"


def added_lines_by_path(
    repo: Path,
    old_ref: str,
    new_ref: str,
    paths: list[str],
    timeout: int,
) -> dict[str, Counter[str]]:
    """Lines present in new_ref and not matched in old_ref, per path."""
    result: dict[str, Counter[str]] = defaultdict(Counter)
    for start in range(0, len(paths), PATH_CHUNK):
        chunk = paths[start : start + PATH_CHUNK]
        out = git(repo, "diff", "-U0", "--no-color", old_ref, new_ref, "--", *chunk, timeout=timeout)
        current: str | None = None
        in_hunk = False
        for line in out.splitlines():
            if line.startswith("diff --git "):
                current, in_hunk = None, False
            elif line.startswith("@@"):
                in_hunk = True
            elif in_hunk and current is not None and line.startswith("+"):
                result[current][line[1:]] += 1
            elif line.startswith("+++ "):
                target = line[4:]
                current = target[2:] if target.startswith("b/") else None
    return result


def reverted_paths(
    repo: Path,
    main_ref: str,
    branch_ref: str,
    roots: tuple[str, ...],
    timeout: int,
) -> tuple[bool, tuple[RevertedPath, ...]]:
    code, base_out = run_git(repo, "merge-base", main_ref, branch_ref, timeout=timeout)
    base = base_out.strip()
    if code != 0 or not base:
        return False, ()

    own = [line for line in git(repo, "diff", "--name-only", base, branch_ref, timeout=timeout).splitlines() if line]
    advanced = [line for line in git(repo, "diff", "--name-only", base, main_ref, timeout=timeout).splitlines() if line]
    owned_components = {component_of(path, roots) for path in own}
    scope = sorted(path for path in advanced if component_of(path, roots) in owned_components)
    if not scope:
        return True, ()

    main_added = added_lines_by_path(repo, base, main_ref, scope, timeout)
    absent_from_branch = added_lines_by_path(repo, branch_ref, main_ref, scope, timeout)

    findings: list[tuple[str, int]] = []
    for path in scope:
        overlap = main_added.get(path, Counter()) & absent_from_branch.get(path, Counter())
        count = sum(overlap.values())
        if count:
            findings.append((path, count))
    if not findings:
        return True, ()

    branch_files = set(git(repo, "ls-tree", "-r", "--name-only", branch_ref, timeout=timeout).splitlines())
    reverted = tuple(
        RevertedPath(path=path, reverted_lines=count, branch_has_file=path in branch_files)
        for path, count in findings
    )
    return True, tuple(sorted(reverted, key=lambda item: (-item.reverted_lines, item.path)))


# --------------------------------------------------------------------------
# branch discovery and PR state
# --------------------------------------------------------------------------


def discover_branches(repo: Path, main_ref: str, timeout: int) -> list[tuple[str, str, bool]]:
    """(ref, short name, is_local) for every branch except the main ref itself."""
    out = git(
        repo,
        "for-each-ref",
        "--format=%(refname)",
        "refs/heads",
        "refs/remotes",
        timeout=timeout,
    )
    main_full = git(repo, "rev-parse", "--symbolic-full-name", main_ref, timeout=timeout).strip()
    branches: list[tuple[str, str, bool]] = []
    for ref in out.splitlines():
        ref = ref.strip()
        if not ref or ref == main_full or ref.endswith("/HEAD"):
            continue
        if ref.startswith("refs/heads/"):
            branches.append((ref, ref[len("refs/heads/") :], True))
        elif ref.startswith("refs/remotes/"):
            rest = ref[len("refs/remotes/") :]
            _, _, name = rest.partition("/")
            if name:
                branches.append((ref, name, False))
    return sorted(branches)


def gh_http_status(stderr: bytes) -> int | None:
    """Classify a GitHub CLI HTTP status without exposing raw stderr."""
    for pattern in (GH_HTTP_STATUS, GH_NAMED_HTTP_STATUS):
        match = pattern.search(stderr)
        if match is not None:
            return int(match.group(1))
    return None


def read_pr_state_from_github(repo: Path, timeout: int) -> bytes:
    """Read PR metadata, retrying only an explicitly classified HTTP 503."""
    command = (
        "gh",
        "pr",
        "list",
        "--state",
        "all",
        "--limit",
        "1000",
        "--json",
        "number,headRefName,state",
    )
    for attempt in range(1, GH_PR_LIST_ATTEMPTS + 1):
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                cwd=str(repo),
                timeout=timeout,
            )
        except FileNotFoundError as error:  # pragma: no cover - environment shaped
            raise GateError("gh executable disappeared during PR state read") from error
        except subprocess.TimeoutExpired as error:
            raise GateError(f"gh pr list timed out after {timeout}s") from error
        if result.returncode == 0:
            return result.stdout
        status = gh_http_status(result.stderr)
        if status != 503:
            category = f"HTTP {status}" if status is not None else "unclassified error"
            raise GateError(
                f"gh pr list failed with exit {result.returncode} ({category})"
            )
        if attempt == GH_PR_LIST_ATTEMPTS:
            raise GateError(
                f"gh pr list exhausted {GH_PR_LIST_ATTEMPTS} attempts after HTTP 503"
            )
        time.sleep(GH_PR_LIST_RETRY_SECONDS)
    raise GateError("gh pr list retry loop ended without a result")  # pragma: no cover


def load_pr_states(
    repo: Path,
    pr_state_file: str | None,
    allow_missing: bool,
    timeout: int,
) -> dict[str, tuple[int | None, str]] | None:
    """headRefName -> (number, STATE), or None when PR state is unavailable."""
    if pr_state_file:
        try:
            raw = Path(pr_state_file).read_text(encoding="utf-8")
        except OSError as error:
            raise GateError(f"could not read PR state file: {error.__class__.__name__}") from error
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as error:
            raise GateError("PR state file is not valid JSON") from error
    else:
        if shutil.which("gh") is None:
            if allow_missing:
                return None
            raise GateError("gh unavailable: PR state cannot be classified (see --allow-missing-pr-state)")
        try:
            raw = read_pr_state_from_github(repo, timeout)
        except GateError:
            if allow_missing:
                return None
            raise
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError as error:
            raise GateError("gh pr list did not return valid JSON") from error

    if not isinstance(data, list):
        raise GateError("PR state must be a JSON list of pull requests")
    states: dict[str, tuple[int | None, str]] = {}
    for entry in data:
        if not isinstance(entry, dict):
            raise GateError("PR state entry is not a JSON object")
        head = entry.get("headRefName")
        state = entry.get("state")
        if not isinstance(head, str) or not head.strip():
            raise GateError("PR state entry has no usable headRefName")
        if not isinstance(state, str) or not state.strip():
            raise GateError("PR state entry has no usable state")
        number = entry.get("number")
        number = number if isinstance(number, int) else None
        previous = states.get(head)
        # MERGED beats OPEN beats CLOSED when a head ref carries several PRs.
        rank = {"MERGED": 3, "OPEN": 2, "CLOSED": 1}
        if previous is None or rank.get(state.upper(), 0) > rank.get(previous[1], 0):
            states[head] = (number, state.upper())
    return states


# --------------------------------------------------------------------------
# worktrees
# --------------------------------------------------------------------------


def display_path(repo: Path, path: Path) -> str:
    """Never emit an absolute path: this repository is public."""
    try:
        return str(path.resolve().relative_to(repo.resolve()))
    except ValueError:
        return f"<external>/{path.name}"


def collect_worktrees(repo: Path, timeout: int) -> list[WorktreeReport]:
    out = git(repo, "worktree", "list", "--porcelain", timeout=timeout)
    reports: list[WorktreeReport] = []
    path: Path | None = None
    branch: str | None = None
    for line in out.splitlines() + [""]:
        if line.startswith("worktree "):
            path = Path(line[len("worktree ") :])
            branch = None
        elif line.startswith("branch "):
            ref = line[len("branch ") :]
            branch = ref[len("refs/heads/") :] if ref.startswith("refs/heads/") else ref
        elif line == "" and path is not None:
            # 'git worktree list' always emits the primary worktree first.
            reports.append(inspect_worktree(repo, path, branch, timeout, is_primary=not reports))
            path, branch = None, None
    return sorted(reports, key=lambda item: item.display)


def inspect_worktree(
    repo: Path,
    path: Path,
    branch: str | None,
    timeout: int,
    is_primary: bool = False,
) -> WorktreeReport:
    display = display_path(repo, path)
    if not path.is_dir():
        return WorktreeReport(
            display=display,
            branch=branch,
            on_disk=False,
            tracked_changes=0,
            untracked_files=0,
            is_primary=is_primary,
        )
    code, out = run_git(path, "status", "--porcelain=v1", "-uall", "--ignored=no", timeout=timeout)
    if code != 0:
        raise GateError(f"git status failed for worktree {display} with exit {code}")
    tracked = 0
    untracked = 0
    for line in out.splitlines():
        if not line.strip():
            continue
        if line.startswith("??"):
            untracked += 1
        else:
            tracked += 1
    return WorktreeReport(
        display=display,
        branch=branch,
        on_disk=True,
        tracked_changes=tracked,
        untracked_files=untracked,
        is_primary=is_primary,
    )


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------


def unique_commit_count(repo: Path, main_ref: str, branch_ref: str, timeout: int) -> int:
    code, out = run_git(repo, "cherry", main_ref, branch_ref, timeout=timeout)
    if code != 0:
        return -1  # unrelated history; reported, never silently treated as zero
    return sum(1 for line in out.splitlines() if line.startswith("+"))


def unpushed_commit_count(repo: Path, branch_ref: str, timeout: int) -> int:
    out = git(repo, "rev-list", "--count", branch_ref, "--not", "--remotes", timeout=timeout)
    text = out.strip()
    if not text.isdigit():
        raise GateError("git rev-list --count returned an unparseable value")
    return int(text)


def analyze(
    repo: Path,
    main_ref: str,
    timeout: int,
    pr_states: dict[str, tuple[int | None, str]] | None,
) -> list[BranchReport]:
    roots = manifest_roots(repo, main_ref, timeout)
    branches = discover_branches(repo, main_ref, timeout)
    if not branches:
        raise GateError("no branches discovered: refusing to report a repository as clean")

    reports: list[BranchReport] = []
    for ref, name, is_local in branches:
        has_base, reverted = reverted_paths(repo, main_ref, ref, roots, timeout)
        pr_number, pr_state = (None, None)
        if pr_states is not None and name in pr_states:
            pr_number, pr_state = pr_states[name]
        reports.append(
            BranchReport(
                ref=ref,
                name=name,
                is_local=is_local,
                has_merge_base=has_base,
                unique_commits=unique_commit_count(repo, main_ref, ref, timeout),
                unpushed_commits=unpushed_commit_count(repo, ref, timeout) if is_local else 0,
                pr_number=pr_number,
                pr_state=pr_state,
                reverted=reverted,
            )
        )
    return reports


def fail_scope_refs(
    repo: Path,
    scope: str,
    selected: list[str],
    reports: list[BranchReport],
    timeout: int,
) -> set[str]:
    if scope == "all":
        return {report.ref for report in reports}
    if scope == "open-pr":
        return {report.ref for report in reports if report.pr_state == "OPEN"}

    if not selected:
        code, out = run_git(repo, "symbolic-ref", "--short", "--quiet", "HEAD", timeout=timeout)
        if code != 0 or not out.strip():
            raise GateError("HEAD is detached and no --branch was given: cannot decide the fail scope")
        selected = [out.strip()]

    known = {report.ref for report in reports}
    resolved: set[str] = set()
    for name in selected:
        candidate = resolve_ref(repo, name, timeout)
        full = git(repo, "rev-parse", "--symbolic-full-name", candidate, timeout=timeout).strip()
        if full not in known:
            raise GateError(f"selected branch is not among the scanned branches: {name}")
        resolved.add(full)
    return resolved


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def print_section(title: str) -> None:
    print(f"==> {title}")


def report(
    reports: list[BranchReport],
    worktrees: list[WorktreeReport],
    pr_states: dict[str, tuple[int | None, str]] | None,
    graph_merged: set[str],
    top_paths: int,
) -> None:
    print_section("scope")
    remote = sum(1 for item in reports if not item.is_local)
    local = sum(1 for item in reports if item.is_local)
    print(f"INFO: branches scanned {len(reports)} (remote {remote}, local {local})")
    print(f"INFO: worktrees scanned {len(worktrees)}")
    if pr_states is None:
        print("WARN: PR state unavailable; merged-branch classification is INCOMPLETE, not clean")
    else:
        print(f"INFO: pull requests known {len(pr_states)}")

    print_section("merged-pr-branches-still-present")
    if pr_states is None:
        print("WARN: cannot classify: PR state unavailable")
    else:
        merged = [item for item in reports if item.pr_state == "MERGED"]
        for item in sorted(merged, key=lambda entry: entry.name):
            pr = f"#{item.pr_number}" if item.pr_number is not None else "#?"
            kind = "local" if item.is_local else "remote"
            print(f"REPORT: merged {pr} still present ({kind}): {item.label}")
        invisible = [item for item in merged if item.ref not in graph_merged]
        print(f"INFO: merged-PR branches still present: {len(merged)}")
        print(
            "INFO: 'git branch --merged' misses "
            f"{len(invisible)} of them -- squash merges leave no ancestry, "
            "so PR state and patch-id are the only sound classifiers"
        )

    print_section("zero-unique-commits-by-patch-id")
    husks = [item for item in reports if item.unique_commits == 0]
    for item in sorted(husks, key=lambda entry: entry.name):
        kind = "local" if item.is_local else "remote"
        print(f"REPORT: no unique patch ({kind}): {item.label}")
    print(f"INFO: husk branches: {len(husks)}")
    unrelated = [item for item in reports if item.unique_commits < 0 or not item.has_merge_base]
    for item in sorted(unrelated, key=lambda entry: entry.name):
        print(f"WARN: unrelated history, cannot be compared to the main ref: {item.label}")

    print_section("worktrees")
    husk_branches = {item.name for item in husks}
    disposable = 0
    for item in worktrees:
        if item.is_primary:
            print(f"INFO: primary worktree, never disposable: {item.display}")
            continue
        if not item.on_disk:
            print(f"REPORT: worktree directory is gone (prunable): {item.display}")
            continue
        if item.dirty:
            print(
                f"REPORT: worktree DIRTY, never disposable: {item.display} "
                f"(tracked changes {item.tracked_changes}, untracked files {item.untracked_files})"
            )
            continue
        if item.branch is not None and item.branch in husk_branches:
            disposable += 1
            print(f"REPORT: worktree clean and its branch has no unique patch: {item.display}")
    print(f"INFO: worktrees with no uncommitted work and no unique patch: {disposable}")
    print("INFO: untracked files are counted separately and make a worktree DIRTY")

    print_section("local-only-work-at-risk")
    at_risk = [item for item in reports if item.is_local and item.unpushed_commits > 0]
    for item in sorted(at_risk, key=lambda entry: entry.name):
        print(
            f"LOSS-RISK: {item.label}: {item.unpushed_commits} commit(s) exist on no remote. "
            "One 'git branch -D' from permanent loss."
        )
    print(f"INFO: local branches whose work exists on no remote: {len(at_risk)}")

    print_section("reverting-branches")
    reverting = [item for item in reports if item.reverted]
    for item in sorted(reverting, key=lambda entry: (-entry.reverted_lines, entry.name)):
        print(f"REPORT: {item.label}: would delete {item.reverted_lines} line(s) the main ref has")
        for path in item.reverted[:top_paths]:
            shape = "branch has no copy of this file" if not path.branch_has_file else "branch has an older copy"
            print(f"        {path.path}: {path.reverted_lines} line(s), {shape}")
    print(f"INFO: branches reverting work inside a component they touch: {len(reverting)}")


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Report branch and worktree sprawl, and fail on branches whose merge "
            "would delete work the main ref already has. Sprawl is reported; a "
            "reverting branch in the fail scope is an error. Anything unreadable "
            "or unclassifiable is an error too."
        )
    )
    parser.add_argument("--repo", default=str(REPO_ROOT), help="repository to inspect")
    parser.add_argument("--main-ref", default=DEFAULT_MAIN_REF, help="ref that carries shipped work")
    parser.add_argument(
        "--branch",
        action="append",
        default=[],
        help="branch to hold to the reverting predicate (repeatable); defaults to HEAD",
    )
    parser.add_argument(
        "--fail-scope",
        choices=("selected", "open-pr", "all"),
        default="selected",
        help="which branches may fail the gate (default: the --branch selection, else HEAD)",
    )
    parser.add_argument(
        "--max-reverted-lines",
        type=int,
        default=0,
        help="lines a branch in the fail scope may delete from the main ref before failing",
    )
    parser.add_argument("--pr-state-file", help="JSON in 'gh pr list --json number,headRefName,state' shape")
    parser.add_argument(
        "--allow-missing-pr-state",
        action="store_true",
        help="downgrade an unavailable gh to an explicit INCOMPLETE report instead of an error",
    )
    parser.add_argument("--skip-worktrees", action="store_true", help="skip the worktree scan")
    parser.add_argument("--top-paths", type=int, default=5, help="reverted paths to print per branch")
    parser.add_argument("--git-timeout-seconds", type=int, default=DEFAULT_GIT_TIMEOUT)
    args = parser.parse_args(argv)

    repo = Path(args.repo)
    timeout = args.git_timeout_seconds

    try:
        if not (repo / ".git").exists() and not repo.joinpath("HEAD").exists():
            code, _ = run_git(repo, "rev-parse", "--git-dir", timeout=timeout)
            if code != 0:
                raise GateError("not a git repository")
        main_ref = resolve_ref(repo, args.main_ref, timeout)
        pr_states = load_pr_states(repo, args.pr_state_file, args.allow_missing_pr_state, timeout)
        reports = analyze(repo, main_ref, timeout, pr_states)
        worktrees = [] if args.skip_worktrees else collect_worktrees(repo, timeout)
        graph_merged = {
            line.strip()
            for line in git(
                repo,
                "for-each-ref",
                "--format=%(refname)",
                "--merged",
                main_ref,
                "refs/heads",
                "refs/remotes",
                timeout=timeout,
            ).splitlines()
            if line.strip()
        }
        scope = fail_scope_refs(repo, args.fail_scope, args.branch, reports, timeout)
    except GateError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    report(reports, worktrees, pr_states, graph_merged, args.top_paths)

    print_section("gate")
    by_ref = {item.ref: item for item in reports}
    failures = [
        by_ref[ref]
        for ref in sorted(scope)
        if ref in by_ref and by_ref[ref].reverted_lines > args.max_reverted_lines
    ]
    unrelated_in_scope = [by_ref[ref] for ref in sorted(scope) if ref in by_ref and not by_ref[ref].has_merge_base]
    print(f"INFO: fail scope '{args.fail_scope}' covers {len(scope)} branch(es)")

    for item in unrelated_in_scope:
        print(
            f"ERROR: {item.label} shares no history with the main ref; it cannot be merged without loss",
            file=sys.stderr,
        )
    for item in failures:
        worst = item.reverted[0]
        print(
            f"ERROR: {item.label} would delete {item.reverted_lines} line(s) the main ref has "
            f"(worst: {worst.path}, {worst.reverted_lines} line(s)); rebase onto the main ref or delete the branch",
            file=sys.stderr,
        )
    if failures or unrelated_in_scope:
        return 1

    if pr_states is None:
        print("OK: no branch in the fail scope reverts the main ref (PR-state report was INCOMPLETE)")
    else:
        print("OK: no branch in the fail scope reverts the main ref")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
