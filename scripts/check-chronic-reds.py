#!/usr/bin/env python3
"""Fail when a check is chronically red on `main` and nobody owns it.

Phase 3.5 of the CI plan: "todo vermelho na tela tem DONO + DATA de expiração,
e existe um gate que lista os expirados." A red that lingers without an owner
and an expiry is a red nobody acts on -- it teaches ignore-by-default, and (the
plan's warning) a periodic report nobody reads is hidden red, not resolved.

This gate is the tooth, not the resolution:

  * It reads declarations from scripts/chronic-reds-enrollment.json. A failing
    check matched there (and before its expiry) is DECLARED -- owned, dated, no
    issue opened.
  * A failing check NOT matched is ORPHAN. For each orphan the gate opens (or
    re-pings) a deduped GitHub issue carrying an assignee and a deadline. The
    issue IS the forced declaration -- the owner is paged, not the report read.
  * A declaration past its expiry is EXPIRED -- a finding; the gate fails.
  * The blocking tooth (promote the check to required after expiry) is a
    DECLARED admin escalation. The gate never fabricates a block by editing
    branch protection -- that is an action a human takes and owns.

Notification contract (the part the plan calls most dangerous):
  * one issue per orphan check (deduped by check name, never one-per-run);
  * a re-ping comment every sla_hours (default 24h) while the orphan persists;
  * an orphan issue is closed the moment its check goes green.

Exit codes (matching the other scripts here):
  0  every failing check is DECLARED and unexpired; no orphans
  1  findings: at least one orphan or expired-declaration
  2  the gate could not run (no enrollment, no main SHA, API failure, ...)

The decision logic is pure (classify()) and is unit-tested in
test_check_chronic_reds.py, including the negative control the plan demands:
plant an orphan -> prove a create action is produced with assignee+deadline;
advance the clock past sla -> prove a re-ping fires; turn the check green ->
prove the issue is closed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENROLLMENT = "scripts/chronic-reds-enrollment.json"
MARKER_LABEL = "chronic-red"
ISSUE_TITLE_PREFIX = "[chronic-red] "

EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)


class GateCannotRun(Exception):
    pass


# --------------------------------------------------------------------------- #
# Declarations + pure classification.
# --------------------------------------------------------------------------- #


@dataclass
class Declared:
    check: str  # exact name or prefix matched against a failing context
    owner: str
    expires: datetime
    issue: int | None
    reason: str


@dataclass
class OrphanIssue:
    number: int
    context: str
    created_at: datetime
    last_ping: datetime | None  # time of the latest re-ping comment, or None


@dataclass
class Action:
    kind: str  # "create" | "reping" | "close"
    context: str
    number: int | None = None
    assignee: str | None = None
    deadline: datetime | None = None


@dataclass
class Classification:
    declared_ok: list[str]
    expired: list[tuple[str, datetime]]
    orphans: list[str]
    actions: list[Action]


def parse_date(s: str) -> datetime:
    # ISO date or datetime; the enrollment uses bare dates (YYYY-MM-DD), taken
    # as end-of-day UTC so an expiry of 2026-08-09 covers that whole day.
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            if fmt == "%Y-%m-%d":
                dt = dt.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            elif dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    raise GateCannotRun(f"cannot parse date/time: {s!r}")


def load_enrollment(path: Path) -> tuple[str, timedelta, list[Declared]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise GateCannotRun(f"cannot read enrollment {path}: {e}")
    except json.JSONDecodeError as e:
        raise GateCannotRun(f"enrollment {path} is not valid JSON: {e}")
    if data.get("schema") != "chronic_reds_enrollment_v1":
        raise GateCannotRun(f"enrollment {path} schema is not chronic_reds_enrollment_v1")
    oncall = data.get("oncall")
    if not oncall:
        raise GateCannotRun("enrollment has no 'oncall' (default orphan assignee)")
    sla = timedelta(hours=float(data.get("sla_hours", 24)))
    declared = []
    for r in data.get("reds", []):
        declared.append(
            Declared(
                check=r["check"],
                owner=r["owner"],
                expires=parse_date(r["expires"]),
                issue=r.get("issue"),
                reason=r.get("reason", ""),
            )
        )
    return oncall, sla, declared


def _declared_for(context: str, declared: list[Declared]) -> Declared | None:
    # A declaration's `check` may be an exact name or a prefix (so one entry
    # covers a matrix like "Published-target candidate (aarch64-...)"). Prefix
    # match is intentional and is itself a thing the gate reports on.
    best: Declared | None = None
    for d in declared:
        if context == d.check or context.startswith(d.check):
            if best is None or len(d.check) > len(best.check):
                best = d  # longest (most specific) prefix wins
    return best


def classify(
    failing: list[str],
    declared: list[Declared],
    orphans_issues: list[OrphanIssue],
    now: datetime,
    oncall: str,
    sla: timedelta,
) -> Classification:
    """Pure decision logic. Given the currently-failing check contexts, the
    declarations, and the existing orphan issues, produce findings + actions.

    This is the unit the negative control exercises: orphan->create(assignee,
    deadline=now+sla); existing orphan whose last ping is older than sla->
    reping; orphan whose check went green->close.
    """
    failing_set = set(failing)
    declared_ok: list[str] = []
    expired: list[tuple[str, datetime]] = []
    orphan_ctxs: list[str] = []

    for ctx in sorted(failing_set):
        d = _declared_for(ctx, declared)
        if d is None:
            orphan_ctxs.append(ctx)
        elif now > d.expires:
            expired.append((ctx, d.expires))
        else:
            declared_ok.append(ctx)

    actions: list[Action] = []

    # Index open orphan issues by the context parsed from their title.
    issues_by_ctx: dict[str, list[OrphanIssue]] = {}
    for oi in orphans_issues:
        issues_by_ctx.setdefault(oi.context, []).append(oi)

    # Orphan -> create or re-ping.
    for ctx in orphan_ctxs:
        open_for_ctx = sorted(issues_by_ctx.get(ctx, []), key=lambda x: x.number)
        if not open_for_ctx:
            actions.append(Action("create", ctx, assignee=oncall, deadline=now + sla))
            continue
        oi = open_for_ctx[0]
        # last_ping falls back to the issue's creation time: the opening of the
        # issue is itself the first page, so the sla clock starts there.
        since = oi.last_ping or oi.created_at
        if (now - since) >= sla:
            actions.append(Action("reping", ctx, number=oi.number))

    # Close orphan issues whose check is no longer failing (went green). A red
    # that became DECLARED is left for the human to reconcile with the registry.
    for oi in orphans_issues:
        if oi.context not in failing_set:
            actions.append(Action("close", oi.context, number=oi.number))

    return Classification(declared_ok, expired, orphan_ctxs, actions)


# --------------------------------------------------------------------------- #
# GitHub layer (thin; monkeypatched in tests).
# --------------------------------------------------------------------------- #


def _gh(args: list[str], **kwargs) -> str:
    env = dict(os.environ)
    env.setdefault("GH", "gh")
    try:
        out = subprocess.run(
            ["gh", *args], check=True, capture_output=True, text=True, env=env, **kwargs
        )
        return out.stdout
    except subprocess.CalledProcessError as e:
        raise GateCannotRun(f"gh {' '.join(args)} failed: {e.stderr.strip() or e.stdout.strip()}") from e


def main_tip_sha(repo: str) -> str:
    return _gh(["api", f"repos/{repo}/branches/main", "-q", ".commit.sha"]).strip()


def fetch_failing_contexts(repo: str, sha: str) -> list[str]:
    """Return the set of check-context names whose latest completed run on `sha`
    concluded 'failure'. Dedup by name, latest completed_at wins (re-runs don't
    double-count a red -- a green re-run clears it)."""
    # Paginate the check-runs endpoint, keep only completed, latest per name.
    runs: dict[str, dict] = {}
    page = 1
    while True:
        js = _gh(
            [
                "api",
                f"repos/{repo}/commits/{sha}/check-runs",
                "-q",
                ".check_runs",
                "--method", "GET",
                "-f", "per_page=100",
                "-F", f"page={page}",
            ]
        )
        try:
            batch = json.loads(js) if js.strip() else []
        except json.JSONDecodeError:
            raise GateCannotRun("could not parse check-runs response")
        if not batch:
            break
        for cr in batch:
            if cr.get("status") != "completed":
                continue
            name = cr.get("name")
            completed = cr.get("completed_at") or ""
            cur = runs.get(name)
            if cur is None or completed >= (cur.get("completed_at") or ""):
                runs[name] = cr
        if len(batch) < 100:
            break
        page += 1
        if page > 20:  # hard cap; 2000 check-runs is well beyond any real SHA
            break
    return sorted(name for name, cr in runs.items() if cr.get("conclusion") == "failure")


def _parse_context_from_title(title: str) -> str | None:
    if title.startswith(ISSUE_TITLE_PREFIX):
        return title[len(ISSUE_TITLE_PREFIX):]
    return None


def fetch_orphan_issues(repo: str) -> list[OrphanIssue]:
    """Open issues carrying the marker label. last_ping is the latest comment
    timestamp authored by the gate's re-ping marker, else None."""
    js = _gh(
        [
            "issue", "list", "--repo", repo, "--state", "open",
            "--label", MARKER_LABEL, "--json", "number,title,createdAt",
            "--limit", "100",
        ]
    )
    out: list[OrphanIssue] = []
    try:
        rows = json.loads(js) if js.strip() else []
    except json.JSONDecodeError:
        raise GateCannotRun("could not parse orphan issue list")
    for row in rows:
        ctx = _parse_context_from_title(row.get("title", ""))
        if ctx is None:
            continue
        created = parse_date(row["createdAt"])
        last_ping = _latest_ping(repo, row["number"])
        out.append(OrphanIssue(row["number"], ctx, created, last_ping))
    return out


def _latest_ping(repo: str, number: int) -> datetime | None:
    js = _gh(
        [
            "api", "--paginate", "--slurp",
            f"repos/{repo}/issues/{number}/comments",
        ]
    )
    try:
        pages = json.loads(js)
    except json.JSONDecodeError as e:
        raise GateCannotRun("could not parse issue-comments response") from e
    if not isinstance(pages, list) or not pages:
        raise GateCannotRun("issue-comments response is not a paginated array")

    latest: datetime | None = None
    for page in pages:
        if not isinstance(page, list):
            raise GateCannotRun("issue-comments page is not an array")
        for comment in page:
            if not isinstance(comment, dict):
                raise GateCannotRun("issue-comments entry is not an object")
            body = comment.get("body")
            created_at = comment.get("created_at")
            if not isinstance(body, str) or not isinstance(created_at, str):
                raise GateCannotRun("issue-comments entry lacks string body or created_at")
            if "chronic-red re-ping" in body:
                t = parse_date(created_at)
                if latest is None or t > latest:
                    latest = t
    return latest


def execute(actions: list[Action], repo: str, dry_run: bool, out=sys.stdout) -> None:
    for a in actions:
        title = f"{ISSUE_TITLE_PREFIX}{a.context}"
        if a.kind == "create":
            body = (
                f"chronic-red orphan: `{a.context}` is failing on `main` and has no owner+expiry "
                f"declaration in scripts/chronic-reds-enrollment.json.\n\n"
                f"- Default owner (oncall): @{a.assignee}\n"
                f"- SLA: resolve, declare (add to the enrollment with owner+expiry), or fix by "
                f"{a.deadline:%Y-%m-%d %H:%M}Z ({a.deadline:%Z}).\n\n"
                f"To declare: add an entry to the enrollment and this gate stops paging. "
                f"To close: make the check green; the gate closes this issue automatically."
            )
            if dry_run:
                print(f"[dry-run] CREATE issue '{title}' assignee=@{a.assignee} deadline={a.deadline}", file=out)
                continue
            _gh(
                [
                    "issue", "create", "--repo", repo, "--title", title,
                    "--label", MARKER_LABEL, "--assignee", a.assignee, "--body", body,
                ]
            )
            print(f"created orphan issue for `{a.context}` -> @{a.assignee}", file=out)
        elif a.kind == "reping":
            body = (
                "chronic-red re-ping: this check is still failing on `main` with no declaration. "
                "Resolve, declare, or fix. (auto-comment from the chronic-red gate)"
            )
            if dry_run:
                print(f"[dry-run] RE-PING #{a.number} ({a.context})", file=out)
                continue
            _gh(["issue", "comment", str(a.number), "--repo", repo, "--body", body])
            print(f"re-pinged #{a.number} for `{a.context}`", file=out)
        elif a.kind == "close":
            body = "chronic-red auto-close: the check is no longer failing on `main`. (auto-comment)"
            if dry_run:
                print(f"[dry-run] CLOSE #{a.number} ({a.context})", file=out)
                continue
            _gh(["issue", "close", str(a.number), "--repo", repo, "--comment", body])
            print(f"closed #{a.number} for `{a.context}` (went green)", file=out)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def run(repo: str, enrollment: Path, dry_run: bool, out=sys.stdout) -> int:
    oncall, sla, declared = load_enrollment(enrollment)
    sha = main_tip_sha(repo)
    failing = fetch_failing_contexts(repo, sha)
    orphan_issues = fetch_orphan_issues(repo)
    now = datetime.now(timezone.utc)

    c = classify(failing, declared, orphan_issues, now, oncall, sla)

    print(f"main tip: {sha} @ {now:%Y-%m-%d %H:%M:%SZ}", file=out)
    print(f"failing check contexts on main: {len(failing)}", file=out)
    if c.declared_ok:
        print("\nDECLARED (owned + within expiry):", file=out)
        for ctx in c.declared_ok:
            print(f"  OK   {ctx}", file=out)
    if c.expired:
        print("\nEXPIRED declarations (lapsed owner+date):", file=out)
        for ctx, exp in c.expired:
            print(f"  EXP  {ctx}  (expired {exp:%Y-%m-%d})", file=out)
    if c.orphans:
        print("\nORPHAN (no declaration -> paging):", file=out)
        for ctx in c.orphans:
            print(f"  ORPH {ctx}", file=out)

    if c.actions:
        print(f"\nactions ({len(c.actions)}):", file=out)
        execute(c.actions, repo, dry_run, out=out)

    findings = bool(c.orphans) or bool(c.expired)
    if findings:
        print(
            f"\nresult: FAIL ({len(c.orphans)} orphan, {len(c.expired)} expired)",
            file=out,
        )
        return 1
    print(
        f"\nresult: PASS ({len(c.declared_ok)} declared; no orphans, no expired)",
        file=out,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=None, help="owner/repo (default: autodetect from origin)")
    ap.add_argument("--enrollment", type=Path, default=REPO_ROOT / DEFAULT_ENROLLMENT)
    ap.add_argument("--dry-run", action="store_true", help="compute actions but do not write to GitHub")
    args = ap.parse_args(argv)

    repo = args.repo or _autodetect_repo()
    if not args.enrollment.is_file():
        print(f"error: enrollment not found: {args.enrollment}", file=sys.stderr)
        return 2

    try:
        return run(repo, args.enrollment, args.dry_run)
    except GateCannotRun as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def _autodetect_repo() -> str:
    url = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "config", "--get", "remote.origin.url"],
        capture_output=True, text=True,
    ).stdout.strip()
    # https://github.com/OWNER/REPO(.git) or git@github.com:OWNER/REPO(.git)
    import re

    m = re.search(r"github\.com[:/]([^/]+/[^/.\s]+)", url)
    if not m:
        raise GateCannotRun(f"cannot autodetect owner/repo from {url!r}; pass --repo")
    return m.group(1)


if __name__ == "__main__":
    sys.exit(main())
