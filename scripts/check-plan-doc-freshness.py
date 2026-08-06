#!/usr/bin/env python3
"""Fail when a plan document's dated measurements are older than the code it describes.

A document that states *measured* facts about code carries a machine-readable
freshness anchor naming two things: the commit the measurements were taken at,
and the pathspecs whose contents the document claims to describe.  The gate
fails when commits touching those pathspecs landed after the anchor commit.

The anchor is written as an HTML comment so it does not render, and it sits
beside the prose sentence that already names the tree, for example

    ## 0. Where the code actually is (measured 2026-08-06 @ `e60bad85`)

    <!-- doc-freshness-anchor
    measured: 2026-08-06
    sha: e60bad85313eb39c9a000a29852bde1a944e425e
    paths:
      - admin/rust/server-rs/src/claw_vpn_*
      - admin/rust/household-rs/src/claw_vpn*.rs
    -->

Two properties are the whole point:

  * **Editing the document does not make it fresh.**  Nothing in this gate looks
    at the document's mtime, its last commit, or its diff.  Only advancing the
    anchor SHA clears a finding, and advancing it is a deliberate act by whoever
    re-measured.
  * **The blast radius is the document's own claim.**  A VPN plan does not go red
    because the frontend moved; it goes red because the paths it named moved.

Everything unreadable, unparseable, absent or ambiguous is a failure.  In
particular a declared pathspec that matches no file in the measured tree is a
failure, not a pass: a typo'd path would otherwise make the gate permanently
and silently vacuous.

Exit codes follow the convention of the other scripts here:
  0  every enrolled document is anchored and fresh
  1  findings (stale anchor, missing anchor, malformed anchor, dead pathspec, ...)
  2  the gate could not run (no git, unreadable/unparseable enrollment, empty scope)
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_ENROLLMENT = "docs/doc-freshness-enrollment.json"
DEFAULT_SCAN_ROOT = "docs"

ENROLLMENT_SCHEMA = "doc_freshness_enrollment_v1"

ANCHOR_OPEN_RE = re.compile(r"<!--[ \t]*doc-freshness-anchor\b")
ANCHOR_CLOSE = "-->"
ANCHOR_KEYS = ("measured", "sha", "paths")

SHA_RE = re.compile(r"\A[0-9a-fA-F]{40}\Z")
DATE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")

STATUS_ANCHORED = "anchored"
STATUS_EXEMPT = "exempt"
STATUSES = (STATUS_ANCHORED, STATUS_EXEMPT)

# The floor.  These documents must be enrolled as "anchored"; dropping one from
# the enrollment file is itself a finding.  Widening the floor is a reviewable
# code change, which is the point -- an enrollment list that anyone can quietly
# shrink is a wish, not a mechanism.
REQUIRED_ANCHORED = (
    "docs/product-a-per-claw-vpn-plan.md",
    "docs/product-a-device-mesh-vpn-plan.md",
    "docs/product-a-mobile-claw-control-vpn-plan.md",
    "docs/soyeht-relay-vps-capacity-and-cost-plan.md",
    "docs/soyeht-tiers-and-entitlement-plan.md",
    "docs/branch-inventory-vpn.md",
)


class GitError(RuntimeError):
    """git could not answer the question, so the gate must not conclude anything."""


@dataclass(frozen=True)
class Anchor:
    measured: date
    sha: str
    paths: tuple[str, ...]


@dataclass(frozen=True)
class Entry:
    path: str
    status: str
    reason: str | None = None
    expires: date | None = None
    auto: bool = False


@dataclass(frozen=True)
class Commit:
    sha: str
    committed: str
    subject: str


# ---------------------------------------------------------------------------
# anchor parsing
# ---------------------------------------------------------------------------


def parse_iso_date(value: str) -> date | None:
    if not DATE_RE.match(value):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def pathspec_errors(spec: str) -> list[str]:
    errors: list[str] = []
    if not spec:
        errors.append("anchor path entry is empty")
        return errors
    if spec[0] == ":":
        errors.append(f"anchor path {spec!r} uses pathspec magic, which is not allowed")
    if spec.startswith("/"):
        errors.append(f"anchor path {spec!r} must be repository-relative")
    if "\\" in spec:
        errors.append(f"anchor path {spec!r} must use forward slashes")
    if any(part == ".." for part in spec.split("/")):
        errors.append(f"anchor path {spec!r} must not escape the repository")
    if any(character.isspace() for character in spec):
        errors.append(f"anchor path {spec!r} must not contain whitespace")
    return errors


def parse_anchor_body(body: str) -> tuple[Anchor | None, list[str]]:
    errors: list[str] = []
    seen: dict[str, str] = {}
    paths: list[str] = []
    current_key: str | None = None

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("-"):
            if current_key != "paths":
                errors.append(f"anchor list item {line!r} appears outside a 'paths:' list")
                continue
            item = line[1:].strip()
            errors.extend(pathspec_errors(item))
            if item:
                if item in paths:
                    errors.append(f"anchor path {item!r} is listed twice")
                else:
                    paths.append(item)
            continue
        if ":" not in line:
            errors.append(f"unparseable anchor line {line!r}")
            current_key = None
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key not in ANCHOR_KEYS:
            errors.append(f"unknown anchor key {key!r} (allowed: {', '.join(ANCHOR_KEYS)})")
            current_key = None
            continue
        if key in seen:
            errors.append(f"anchor key {key!r} appears twice")
            continue
        if key == "paths" and value:
            errors.append("anchor 'paths:' must be a list, one '- <pathspec>' per line")
        seen[key] = value
        current_key = key

    for key in ANCHOR_KEYS:
        if key not in seen:
            errors.append(f"anchor is missing required key {key!r}")

    measured = parse_iso_date(seen.get("measured", ""))
    if "measured" in seen and measured is None:
        errors.append("anchor 'measured:' must be a real calendar date as YYYY-MM-DD")

    sha = seen.get("sha", "")
    if "sha" in seen and not SHA_RE.match(sha):
        errors.append("anchor 'sha:' must be a full 40-character commit SHA")

    if "paths" in seen and not paths:
        errors.append("anchor 'paths:' must list at least one pathspec")

    if errors:
        return None, errors
    assert measured is not None
    return Anchor(measured=measured, sha=sha.lower(), paths=tuple(paths)), []


def parse_anchor(text: str) -> tuple[Anchor | None, list[str]]:
    """Return (anchor, errors).  (None, []) means the document carries no anchor."""
    opens = list(ANCHOR_OPEN_RE.finditer(text))
    if not opens:
        return None, []
    if len(opens) > 1:
        return None, [f"document contains {len(opens)} doc-freshness anchor blocks; exactly one is allowed"]
    start = opens[0].end()
    end = text.find(ANCHOR_CLOSE, start)
    if end < 0:
        return None, ["doc-freshness anchor block is not terminated with '-->'"]
    return parse_anchor_body(text[start:end])


def strip_anchor_blocks(text: str) -> str:
    """Remove every anchor comment, opener through closer, leaving only visible text."""
    out: list[str] = []
    cursor = 0
    for match in ANCHOR_OPEN_RE.finditer(text):
        if match.start() < cursor:
            continue
        close = text.find(ANCHOR_CLOSE, match.end())
        out.append(text[cursor : match.start()])
        cursor = len(text) if close < 0 else close + len(ANCHOR_CLOSE)
    out.append(text[cursor:])
    return "".join(out)


def anchor_sha_in_prose(text: str, sha: str) -> bool:
    """Is the anchored commit also named in the reader-visible prose?

    The anchor block is an HTML comment and does not render.  Requiring the
    visible text to name the same commit keeps the invisible machine fact and the
    visible human claim from drifting apart: bumping one without the other is a
    finding.  The short form is accepted because that is how the documents
    already write it.

    The whole anchor block -- not just its opening marker -- has to come out
    first, or this check finds the SHA it just wrote and is vacuously true.
    """
    body = strip_anchor_blocks(text)
    for length in (40, 12, 10, 8):
        if sha[:length] in body:
            return True
    return False


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._tree_cache: dict[str, frozenset[str]] = {}

    def _run(self, args: tuple[str, ...], allowed_returncodes: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[bytes]:
        try:
            proc = subprocess.run(
                ("git", "-C", str(self.root), *args),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError as error:
            raise GitError(f"could not run git: {error.__class__.__name__}") from error
        if proc.returncode not in allowed_returncodes:
            raise GitError(f"git {args[0]} failed with exit code {proc.returncode}")
        return proc

    def _text(self, args: tuple[str, ...]) -> str:
        return self._run(args).stdout.decode("utf-8", "surrogateescape")

    def _nul_list(self, args: tuple[str, ...]) -> list[str]:
        raw = self._run(args).stdout.decode("utf-8", "surrogateescape")
        return [item for item in raw.split("\0") if item]

    def assert_repository(self) -> None:
        proc = self._run(("rev-parse", "--is-inside-work-tree"), allowed_returncodes=(0, 128))
        if proc.returncode != 0 or proc.stdout.strip() != b"true":
            raise GitError("path is not a git work tree")

    def resolve_commit(self, rev: str) -> str | None:
        proc = self._run(("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"), allowed_returncodes=(0, 1, 128))
        if proc.returncode != 0:
            return None
        resolved = proc.stdout.decode("ascii", "replace").strip()
        return resolved or None

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        proc = self._run(("merge-base", "--is-ancestor", ancestor, descendant), allowed_returncodes=(0, 1))
        return proc.returncode == 0

    def commit_date(self, sha: str) -> date:
        raw = self._text(("show", "-s", "--format=%ct", sha)).strip()
        try:
            epoch = int(raw)
        except ValueError as error:
            raise GitError("git returned an unparseable commit timestamp") from error
        return datetime.fromtimestamp(epoch, tz=timezone.utc).date()

    def tree_files(self, ref: str) -> frozenset[str]:
        cached = self._tree_cache.get(ref)
        if cached is None:
            cached = frozenset(self._nul_list(("ls-tree", "-r", "-z", "--name-only", "--full-tree", ref)))
            self._tree_cache[ref] = cached
        return cached

    def files_matching(self, ref: str, spec: str) -> list[str]:
        """Files present in ref's tree that match spec, using git's own pathspec engine.

        `git ls-tree` silently ignores wildcards in a pathspec -- it does prefix
        matching only -- so using it here would report every glob as dead and
        every dead glob as alive depending on the spelling.  `git ls-files` and
        `git log` share the real pathspec engine, so ls-files does the matching
        and the ref's tree listing filters out anything the index contributed.
        """
        matched = self._nul_list(("ls-files", "-z", "--full-name", f"--with-tree={ref}", "--", spec))
        in_tree = self.tree_files(ref)
        return sorted(path for path in matched if path in in_tree)

    def commits_touching(self, since_sha: str, ref: str, specs: tuple[str, ...]) -> list[Commit]:
        raw = self._text(
            (
                "log",
                "--format=%H%x09%cs%x09%s",
                f"{since_sha}..{ref}",
                "--",
                *specs,
            )
        )
        commits: list[Commit] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t", 2)
            if len(parts) != 3:
                raise GitError("git log returned an unparseable record")
            commits.append(Commit(sha=parts[0], committed=parts[1], subject=parts[2]))
        return commits


# ---------------------------------------------------------------------------
# enrollment
# ---------------------------------------------------------------------------


def entry_path_errors(path: str) -> list[str]:
    errors: list[str] = []
    if not path:
        errors.append("enrollment entry has an empty 'path'")
        return errors
    if path.startswith("/"):
        errors.append(f"enrollment path {path!r} must be repository-relative")
    if any(part == ".." for part in path.split("/")):
        errors.append(f"enrollment path {path!r} must not escape the repository")
    if not path.endswith(".md"):
        errors.append(f"enrollment path {path!r} must name a markdown document")
    return errors


def load_enrollment(path: Path) -> tuple[dict[str, Entry], list[str]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return {}, ["enrollment file is not valid UTF-8"]
    except OSError as error:
        return {}, [f"could not read enrollment file: {error.__class__.__name__}"]

    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        return {}, ["enrollment file is not valid JSON"]

    if not isinstance(document, dict):
        return {}, ["enrollment file must be a JSON object"]
    if document.get("schema") != ENROLLMENT_SCHEMA:
        return {}, [f"enrollment file must declare schema {ENROLLMENT_SCHEMA!r}"]

    documents = document.get("documents")
    if not isinstance(documents, list) or not documents:
        return {}, ["enrollment file must declare a non-empty 'documents' list"]

    errors: list[str] = []
    entries: dict[str, Entry] = {}
    for index, item in enumerate(documents):
        if not isinstance(item, dict):
            errors.append(f"enrollment entry {index} is not an object")
            continue
        unknown = sorted(set(item) - {"path", "status", "reason", "expires"})
        if unknown:
            errors.append(f"enrollment entry {index} has unknown keys: {', '.join(unknown)}")
        doc_path = item.get("path")
        if not isinstance(doc_path, str):
            errors.append(f"enrollment entry {index} has a non-string 'path'")
            continue
        doc_path = doc_path.strip()
        path_errors = entry_path_errors(doc_path)
        if path_errors:
            errors.extend(path_errors)
            continue
        if doc_path in entries:
            errors.append(f"enrollment lists {doc_path} twice")
            continue
        status = item.get("status")
        if status not in STATUSES:
            errors.append(f"enrollment entry for {doc_path} must declare status in {STATUSES}")
            continue
        reason = item.get("reason")
        expires: date | None = None
        if status == STATUS_EXEMPT:
            if not isinstance(reason, str) or not reason.strip():
                errors.append(f"exempt entry for {doc_path} must carry a non-empty 'reason'")
            raw_expires = item.get("expires")
            if not isinstance(raw_expires, str):
                errors.append(f"exempt entry for {doc_path} must carry an 'expires' date")
            else:
                expires = parse_iso_date(raw_expires.strip())
                if expires is None:
                    errors.append(f"exempt entry for {doc_path} has an unparseable 'expires' date")
        elif reason is not None and not isinstance(reason, str):
            errors.append(f"enrollment entry for {doc_path} has a non-string 'reason'")
        entries[doc_path] = Entry(
            path=doc_path,
            status=status,
            reason=reason if isinstance(reason, str) else None,
            expires=expires,
        )

    if errors:
        return {}, errors
    return entries, []


def discover_anchored_documents(
    repo_root: Path, scan_root: Path, already_enrolled: frozenset[str]
) -> tuple[list[str], list[tuple[str, str]], str | None]:
    """Find markdown files that carry an anchor, so opting in never needs a second edit.

    Returns (discovered, findings, fatal).  A file that cannot be read is a
    finding, not a skip: "we could not tell whether it is anchored" must never
    resolve to "it is fine".
    """
    if not scan_root.is_dir():
        return [], [], f"scan root {relative(repo_root, scan_root)} is not a directory"
    found: list[str] = []
    findings: list[tuple[str, str]] = []
    for candidate in sorted(scan_root.rglob("*.md")):
        name = relative(repo_root, candidate)
        if name in already_enrolled:
            continue  # the enrolled path reads and reports on it already
        try:
            text = candidate.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append((name, "markdown file under the scan root is not valid UTF-8"))
            continue
        except OSError as error:
            findings.append((name, f"markdown file under the scan root is unreadable ({error.__class__.__name__})"))
            continue
        if ANCHOR_OPEN_RE.search(text):
            found.append(name)
    return found, findings, None


def relative(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root).as_posix()
    except ValueError:
        return path.name


# ---------------------------------------------------------------------------
# the check
# ---------------------------------------------------------------------------


def check_document(repo: Repo, entry: Entry, ref: str, ref_sha: str, max_commits: int) -> list[str]:
    doc_file = repo.root / entry.path
    try:
        text = doc_file.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ["enrolled document is not valid UTF-8"]
    except OSError as error:
        return [f"enrolled document is missing or unreadable ({error.__class__.__name__})"]

    anchor, errors = parse_anchor(text)
    if errors:
        return errors
    if anchor is None:
        return [
            "enrolled document carries no doc-freshness anchor block "
            "(add '<!-- doc-freshness-anchor ... -->' naming the measured sha and the paths it describes)"
        ]

    findings: list[str] = []

    resolved = repo.resolve_commit(anchor.sha)
    if resolved is None:
        return [
            f"anchor sha {anchor.sha[:12]} is not a commit in this repository "
            "(a shallow clone cannot answer this question; fetch full history)"
        ]
    if resolved != anchor.sha:
        return [f"anchor sha {anchor.sha[:12]} does not resolve to itself"]

    if not repo.is_ancestor(anchor.sha, ref_sha):
        return [
            f"anchor sha {anchor.sha[:12]} is not an ancestor of {ref} "
            f"({ref_sha[:12]}); the document was measured on a tree this branch does not contain"
        ]

    anchored_on = repo.commit_date(anchor.sha)
    if anchor.measured < anchored_on:
        findings.append(
            f"anchor claims it was measured on {anchor.measured.isoformat()} "
            f"but sha {anchor.sha[:12]} was only committed on {anchored_on.isoformat()}"
        )

    if not anchor_sha_in_prose(text, anchor.sha):
        findings.append(
            f"anchor sha {anchor.sha[:12]} is never named in the document's visible text; "
            "the machine anchor and the prose disagree about which tree was read"
        )

    dead: list[str] = []
    for spec in anchor.paths:
        if not repo.files_matching(ref, spec):
            dead.append(spec)
    if dead:
        findings.append(
            "anchor path(s) match no file at "
            f"{ref}: {', '.join(dead)} -- a pathspec that matches nothing makes this gate vacuous"
        )
        # A dead pathspec means the drift question below cannot be answered for
        # it.  Report and stop rather than concluding "fresh" from a search that
        # found nothing.
        return findings

    commits = repo.commits_touching(anchor.sha, ref_sha, anchor.paths)
    if commits:
        shown = commits[:max_commits]
        lines = [
            f"code the document describes moved after its anchor: {len(commits)} commit(s) "
            f"touched the anchored paths between {anchor.sha[:12]} and {ref} ({ref_sha[:12]})",
        ]
        for commit in shown:
            lines.append(f"    {commit.sha[:12]}  {commit.committed}  {commit.subject[:88]}")
        if len(commits) > len(shown):
            lines.append(f"    ... and {len(commits) - len(shown)} more")
        lines.append(
            "    re-measure the document against the newer tree and advance 'sha:' in its anchor; "
            "editing the prose alone does not clear this."
        )
        findings.append("\n".join(lines))

    return findings


def check_exempt_document(repo_root: Path, entry: Entry, today: date) -> list[str]:
    findings: list[str] = []
    doc_file = repo_root / entry.path
    try:
        text = doc_file.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ["exempt document is not valid UTF-8"]
    except OSError as error:
        return [f"exempt document is missing or unreadable ({error.__class__.__name__})"]
    if ANCHOR_OPEN_RE.search(text):
        findings.append("document is enrolled as exempt but carries an anchor; drop the exemption")
    if entry.expires is None:
        findings.append("exemption has no usable expiry date")
    elif entry.expires < today:
        findings.append(f"exemption expired on {entry.expires.isoformat()}; anchor the document or re-date the exemption")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail when a plan document's measured claims are older than the code it "
            "describes. The document declares the commit it was measured at and the "
            "pathspecs it claims to describe; the gate reports commits that landed on "
            "those paths afterwards. Editing a document does not make it fresh."
        )
    )
    parser.add_argument("--repo-root", default=str(REPO_ROOT), help="repository root to measure in")
    parser.add_argument("--ref", default="HEAD", help="the tree to measure against (default: HEAD)")
    parser.add_argument("--enrollment", default=None, help=f"enrollment file (default: {DEFAULT_ENROLLMENT})")
    parser.add_argument("--scan-root", default=None, help=f"directory scanned for stray anchors (default: {DEFAULT_SCAN_ROOT})")
    parser.add_argument("--today", default=None, help="override today's date (YYYY-MM-DD) for exemption expiry")
    parser.add_argument("--max-commits", type=int, default=10, help="how many drifting commits to print per document")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    enrollment_path = repo_root / (args.enrollment or DEFAULT_ENROLLMENT)
    scan_root = repo_root / (args.scan_root or DEFAULT_SCAN_ROOT)

    if args.max_commits < 1:
        print("ERROR: --max-commits must be at least 1", file=sys.stderr)
        return 2

    if args.today is None:
        today = datetime.now(tz=timezone.utc).date()
    else:
        today = parse_iso_date(args.today.strip())
        if today is None:
            print("ERROR: --today must be a real calendar date as YYYY-MM-DD", file=sys.stderr)
            return 2

    repo = Repo(repo_root)
    try:
        repo.assert_repository()
        ref_sha = repo.resolve_commit(args.ref)
    except GitError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    if ref_sha is None:
        print(f"ERROR: could not resolve --ref {args.ref} to a commit", file=sys.stderr)
        return 2

    entries, enrollment_errors = load_enrollment(enrollment_path)
    if enrollment_errors:
        for error in enrollment_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 2

    findings: list[tuple[str, str]] = []

    for required in REQUIRED_ANCHORED:
        entry = entries.get(required)
        if entry is None:
            findings.append((required, "required document is missing from the enrollment file"))
        elif entry.status != STATUS_ANCHORED:
            findings.append((required, f"required document must be enrolled as {STATUS_ANCHORED!r}, not {entry.status!r}"))

    discovered, scan_findings, scan_fatal = discover_anchored_documents(
        repo_root, scan_root, frozenset(entries)
    )
    if scan_fatal is not None:
        print(f"ERROR: {scan_fatal}", file=sys.stderr)
        return 2
    findings.extend(scan_findings)
    for path in discovered:
        if path not in entries:
            entries[path] = Entry(path=path, status=STATUS_ANCHORED, auto=True)

    if not entries:
        print("ERROR: no documents are in scope; a freshness gate with nothing to check is not a pass", file=sys.stderr)
        return 2

    checked = 0
    exempt = 0
    try:
        for path in sorted(entries):
            entry = entries[path]
            if entry.status == STATUS_EXEMPT:
                exempt += 1
                for finding in check_exempt_document(repo_root, entry, today):
                    findings.append((path, finding))
                continue
            checked += 1
            for finding in check_document(repo, entry, args.ref, ref_sha, args.max_commits):
                findings.append((path, finding))
    except GitError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    if checked == 0:
        print("ERROR: every document is exempt; a freshness gate that checks nothing is not a pass", file=sys.stderr)
        return 2

    if findings:
        for path, finding in findings:
            print(f"ERROR: {path}: {finding}", file=sys.stderr)
        print(f"ERROR: {len(findings)} doc-freshness finding(s) across {checked} anchored document(s)", file=sys.stderr)
        return 1

    print(f"OK: {checked} anchored document(s) fresh against {args.ref} ({ref_sha[:12]}); {exempt} exempt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
