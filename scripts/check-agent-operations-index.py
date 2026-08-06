#!/usr/bin/env python3
"""Check that the tracked agent operations index is reachable, resolvable and dated.

The index (`docs/agent-operations-index.md`) is the only copy of operational
knowledge that survives a context reset, a linked worktree or a fresh clone. This
gate fails when it stops being that:

* it is not tracked in git (an untracked map does not reach a worktree),
* it grew past the length an agent will actually read,
* it points at a file that does not exist,
* it names a gate script with no co-located test,
* it leaks a value into a public repository,
* it carries a `MEASURED` claim older than the maximum age, a `PENDING` promise
  whose date has passed, a malformed marker, or no marker at all.

Every failure mode is a failure. Unreadable input, missing input and an
unavailable git are exit 2, never a pass.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

INDEX_REL = "docs/agent-operations-index.md"
ENTRYPOINTS = ("CLAUDE.md", "AGENTS.md")

# An agent reads a map, not a manual.
DEFAULT_MAX_LINES = 200
# A claim older than this has outlived the tree it was measured against. The
# stale iOS pin found on 2026-08-06 was 42 days old; the stale status header 28.
DEFAULT_MAX_AGE_DAYS = 30
# How far into a file a "read this first" pointer still counts as prominent.
POINTER_WINDOW_LINES = 20

LOCAL_TREE_LABELS = frozenset({"origin/main", "main", "HEAD", "worktree"})
# Trees this repo cannot resolve. Allowlisted so a typo is still an error.
FOREIGN_TREE_LABELS = frozenset({"soyeht-ios"})

# A marker is a code span, so prose may still discuss the words. Any code span
# that OPENS with one of the keywords must then be well formed: a marker the
# strict pattern silently missed would leave the age check without a trace.
MARKER_SPAN_RE = re.compile(r"`(?P<body>(?:MEASURED|PENDING)[^`]*)`")
MEASURED_RE = re.compile(
    r"^MEASURED (?P<date>\d{4}-\d{2}-\d{2}) (?P<label>[A-Za-z0-9_./-]+)@(?P<sha>[0-9a-f]{7,40})$"
)
PENDING_RE = re.compile(r"^PENDING (?P<date>\d{4}-\d{2}-\d{2})$")

# Repo-relative paths are written in backticks and rooted at a known top level.
REPO_PATH_RE = re.compile(
    r"`((?:docs|scripts|admin|specs|tests|tools|harness|claws|deploy|distro|nix|\.github)"
    r"/[A-Za-z0-9_./*-]+)`"
)
GATE_SCRIPT_RE = re.compile(r"`(scripts/(?:check|validate)-[A-Za-z0-9._-]+\.py)`")

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ABSOLUTE_LOCAL_PATH_RE = re.compile(r"(?<![\w:/~])/[A-Za-z][A-Za-z0-9._-]*(?:/[^\s`|)<>,;:]+)*")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}")
SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(?:api[_-]?key|token|password|secret|private[_-]?key)\b\s*[:=]\s*\S+",
    re.IGNORECASE,
)
PRIVATE_KEY_BLOCK_RE = re.compile("BE" "GIN " + r"[A-Z0-9 -]*" + "PRIVATE KEY", re.IGNORECASE)


def documentation_ipv4_network(octets: tuple[int, int, int, int], prefix: int) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{'.'.join(str(octet) for octet in octets)}/{prefix}")


DOCUMENTATION_IPV4_NETWORKS = tuple(
    documentation_ipv4_network(octets, prefix)
    for octets, prefix in (
        ((192, 0, 2, 0), 24),
        ((198, 51, 100, 0), 24),
        ((203, 0, 113, 0), 24),
        ((198, 18, 0, 0), 15),
    )
)

REQUIRED_SECTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("the private operator store pointer", re.compile(r"~/\.soyeht-ops")),
    ("the reason this tracked file is the reliable one", re.compile(r"^##.*`CLAUDE\.md`", re.MULTILINE)),
    ("the iOS repository location", re.compile(r"soyeht-ios")),
    ("the cross-repo pin hazard", re.compile(r"contracts-cross-repo-sync\.yml")),
    ("the gates table", re.compile(r"^##.*\bGates\b", re.MULTILINE | re.IGNORECASE)),
    ("the measuring section", re.compile(r"^##.*\bMeasuring\b", re.MULTILINE | re.IGNORECASE)),
    ("the exclude-list warning", re.compile(r"\bexclude\b")),
    ("the compiles-versus-runs warning", re.compile(r"compiles?\b.*\bruns?\b", re.IGNORECASE)),
    ("the dating rule", re.compile(r"^##.*\bdating rule\b", re.MULTILINE | re.IGNORECASE)),
    ("the aliases table", re.compile(r"^##.*\bAliases\b", re.MULTILINE | re.IGNORECASE)),
    ("where authorization lives", re.compile(r"authorizations\.md")),
)


def parse_iso_date(value: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def contains_non_documentation_ipv4(text: str) -> bool:
    for match in IPV4_RE.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            return True
        if not any(address in network for network in DOCUMENTATION_IPV4_NETWORKS):
            return True
    return False


def privacy_errors(text: str) -> list[str]:
    errors: list[str] = []
    if contains_non_documentation_ipv4(text):
        errors.append("index must use only documentation-safe IPv4 addresses")
    if ABSOLUTE_LOCAL_PATH_RE.search(text):
        errors.append("index must not contain local absolute paths")
    if EMAIL_RE.search(text):
        errors.append("index must not contain account or email addresses")
    if PRIVATE_KEY_BLOCK_RE.search(text) or SECRET_ASSIGNMENT_RE.search(text):
        errors.append("index must not contain secrets or key material")
    return errors


def measured_markers(markdown: str) -> list[re.Match[str]]:
    return [m for span in MARKER_SPAN_RE.finditer(markdown) if (m := MEASURED_RE.match(span.group("body")))]


def any_pending(line: str) -> bool:
    """True when the line carries a well-formed PENDING marker."""
    return any(PENDING_RE.match(span.group("body")) for span in MARKER_SPAN_RE.finditer(line))


def marker_errors(markdown: str, today: dt.date, max_age_days: int) -> list[str]:
    """Age and shape of every dated claim. Zero claims is a failure, not a pass."""
    errors: list[str] = []
    measured_count = 0

    for span in MARKER_SPAN_RE.finditer(markdown):
        body = span.group("body")
        keyword = "MEASURED" if body.startswith("MEASURED") else "PENDING"
        match = (MEASURED_RE if keyword == "MEASURED" else PENDING_RE).match(body)
        if match is None:
            errors.append(f"index contains a malformed {keyword} marker")
            continue
        date = parse_iso_date(match.group("date"))
        if date is None:
            errors.append(f"{keyword} marker carries an unparseable date")
            continue
        if keyword == "PENDING":
            if date < today:
                errors.append("PENDING promise has expired; land it or restate it")
            continue

        measured_count += 1
        if date > today:
            errors.append("MEASURED marker is dated in the future")
            continue
        age = (today - date).days
        if age > max_age_days:
            errors.append(f"MEASURED claim is {age} days old; re-measure and restate the date")
        label = match.group("label")
        if label not in LOCAL_TREE_LABELS and label not in FOREIGN_TREE_LABELS:
            errors.append(f"MEASURED marker names an unknown tree: {label}")

    if measured_count == 0:
        errors.append("index must carry at least one MEASURED claim")
    return errors


def structure_errors(markdown: str, max_lines: int) -> list[str]:
    errors: list[str] = []
    if "\x00" in markdown:
        return ["index must be UTF-8 text without NUL bytes"]
    line_count = len(markdown.splitlines())
    if line_count > max_lines:
        errors.append(f"index is {line_count} lines; a map over {max_lines} lines is a manual nobody reads")
    for label, pattern in REQUIRED_SECTIONS:
        if pattern.search(markdown) is None:
            errors.append(f"index must carry {label}")
    return errors


def index_content_errors(markdown: str, today: dt.date, max_age_days: int, max_lines: int) -> list[str]:
    """Everything decidable from the text alone."""
    errors = structure_errors(markdown, max_lines)
    if errors and errors[0].startswith("index must be UTF-8"):
        return errors
    errors.extend(marker_errors(markdown, today, max_age_days))
    errors.extend(privacy_errors(markdown))
    return errors


def test_name_for(gate_rel: str) -> str:
    stem = Path(gate_rel).stem.replace("-", "_")
    return f"scripts/test_{stem}.py"


def link_errors(markdown: str, path_exists) -> list[str]:
    """Every mapped path resolves, and every landed gate has a co-located test.

    A line carrying a PENDING marker is a declared promise, not a dead link, so
    its paths are exempt until that date — which `marker_errors` enforces.
    """
    errors: list[str] = []
    for line in markdown.splitlines():
        if any_pending(line):
            continue
        for match in REPO_PATH_RE.finditer(line):
            rel = match.group(1)
            if "*" in rel:
                continue
            if not path_exists(rel):
                errors.append(f"index points at a path that does not exist: {rel}")
        for match in GATE_SCRIPT_RE.finditer(line):
            gate_rel = match.group(1)
            if "*" in gate_rel or not path_exists(gate_rel):
                continue
            test_rel = test_name_for(gate_rel)
            if not path_exists(test_rel):
                errors.append(f"gate {gate_rel} has no co-located test at {test_rel}")
    return errors


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", "-C", str(repo), *args),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def git_tracked(repo: Path, rel: str) -> bool:
    return git(repo, "ls-files", "--error-unmatch", "--", rel).returncode == 0


def git_ignored(repo: Path, rel: str) -> bool:
    return git(repo, "check-ignore", "-q", "--", rel).returncode == 0


def git_commit_exists(repo: Path, sha: str) -> bool:
    return git(repo, "cat-file", "-e", f"{sha}^{{commit}}").returncode == 0


def path_exists_in(repo: Path, also_in: str | None):
    """Resolve mapped paths against the working tree, optionally unioned with a rev.

    CI runs with no `--also-in`: its checkout IS the tree under test, so strict
    working-tree resolution is right. A developer whose checkout sits on an older
    branch should pass `--also-in origin/main`; the union is then "what the tree
    looks like once this lands", which is the tree the index actually ships in.
    Neither tree alone is that universe: the working tree is missing what landed
    on main, and main is missing what is about to land.
    """
    if also_in is None:
        return lambda rel: (repo / rel).exists()
    return lambda rel: (repo / rel).exists() or git(repo, "cat-file", "-e", f"{also_in}:{rel}").returncode == 0


def tracked_errors(tracked) -> list[str]:
    if not tracked(INDEX_REL):
        return [f"{INDEX_REL} is not tracked in git; an untracked map never reaches a worktree or CI"]
    return []


def entrypoint_errors(repo: Path, ignored) -> list[str]:
    """Present entrypoints must point here; absent ones must be provably ignored.

    An entrypoint that is simply gone, with no `.gitignore` entry explaining it,
    is an unexplained absence and therefore an error — not a skipped check.
    """
    errors: list[str] = []
    for name in ENTRYPOINTS:
        path = repo / name
        if path.exists():
            try:
                head = path.read_text(encoding="utf-8").splitlines()[:POINTER_WINDOW_LINES]
            except (OSError, UnicodeDecodeError):
                errors.append(f"{name} exists but could not be read as UTF-8")
                continue
            if not any(INDEX_REL in line for line in head):
                errors.append(f"{name} must point at {INDEX_REL} within its first {POINTER_WINDOW_LINES} lines")
        elif not ignored(name):
            errors.append(f"{name} is absent and not git-ignored; its absence is unexplained")
    return errors


def tree_ref_errors(markdown: str, commit_exists) -> list[str]:
    errors: list[str] = []
    for match in measured_markers(markdown):
        label = match.group("label")
        sha = match.group("sha")
        if label in LOCAL_TREE_LABELS and not commit_exists(sha):
            errors.append(f"MEASURED marker cites a commit this repo cannot resolve: {label}@{sha}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Check the tracked agent operations index. Failure output names the "
            "defect and the mapped path only; it never echoes private values."
        )
    )
    parser.add_argument("--repo", default=str(REPO_ROOT), help="repository root to check")
    parser.add_argument(
        "--also-in",
        dest="also_in",
        help="also accept mapped paths present in this rev (e.g. origin/main), for a pre-flight "
        "from a checkout that is behind. CI omits it and resolves the working tree only.",
    )
    parser.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS)
    parser.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES)
    parser.add_argument("--today", help="ISO date to evaluate ages against (tests only)")
    args = parser.parse_args(argv)

    repo = Path(args.repo)
    if args.today is None:
        today = dt.date.today()
    else:
        today = parse_iso_date(args.today)
        if today is None:
            print("ERROR: --today must be an ISO date", file=sys.stderr)
            return 2

    if git(repo, "rev-parse", "--git-dir").returncode != 0:
        print("ERROR: --repo is not a git repository, or git is unavailable", file=sys.stderr)
        return 2

    if args.also_in is not None and git(repo, "rev-parse", "--verify", f"{args.also_in}^{{commit}}").returncode != 0:
        print("ERROR: --also-in does not resolve to a commit in this repository", file=sys.stderr)
        return 2

    try:
        markdown = (repo / INDEX_REL).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        print(f"ERROR: {INDEX_REL} is not valid UTF-8", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"ERROR: could not read {INDEX_REL}: {error.__class__.__name__}", file=sys.stderr)
        return 2

    errors = index_content_errors(markdown, today, args.max_age_days, args.max_lines)
    errors.extend(link_errors(markdown, path_exists_in(repo, args.also_in)))
    errors.extend(tree_ref_errors(markdown, lambda sha: git_commit_exists(repo, sha)))
    errors.extend(tracked_errors(lambda rel: git_tracked(repo, rel)))
    errors.extend(entrypoint_errors(repo, lambda rel: git_ignored(repo, rel)))

    if errors:
        for error in dict.fromkeys(errors):
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("OK: agent operations index is tracked, resolvable, leak-free and current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
