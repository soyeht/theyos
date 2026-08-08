#!/usr/bin/env python3
"""Measure CI health from the GitHub Actions API — the plan's Fase 0 ruler.

This instrument exists because a metric without a denominator is a vibe, and a
denominator measured two different ways is a fight. It computes the numbers the
8.5 plan asserts against, under the invariants that plan fixed after two of us
measured the same week and disagreed by 23%:

  1. FROZEN WINDOW — measurement happens over an explicit list of run ids
     (--window). Two people measuring must measure the same set. A run list
     that grows under the measurement is not a window, it is a moving target.
  2. EXACT JOB COUNTS — jobs are counted by JOB ID, never by name. The docs
     shim and the real build publish IDENTICAL job names; summing by name
     double-counts. A count that does not reconcile exactly is not "within
     tolerance", it is a missing job to find.
  3. ALL ATTEMPTS — `GET runs/{id}/jobs` without filter returns only the LAST
     attempt, which erases exactly the reruns a flake produces. Every count
     here uses filter=all and counts every attempt.
  4. QUEUE VS EXECUTION — run_started_at minus created_at is queue; the job
     wall clock is execution. The two are never summed into one number.
  5. LAST ATTEMPT FOR SIGNAL, ALL ATTEMPTS FOR COST — the merge-deciding
     signal closes when the LAST attempt closes (a rerun makes a flake cost
     real latency); runner-cost sums EVERY attempt, because every attempt
     burned a runner. A cancelled attempt never counts as "closed".
  6. A/B RECONCILIATION PER RUN — method A sums step durations from the API,
     method B uses the job wall clock. They are reconciled per workflow-run,
     never in aggregate: a total can hide a compensated error.

Cause buckets for red: flake, defeito-real, infra, gate-quebrado, ungated,
unexplained. Classification is HUMAN input (--classifications, a JSON map of
job id -> bucket): this instrument counts and lists; it never guesses a cause.
A failure nobody classified is reported as `unclassified` beside the rate,
never folded into a bucket silently and never dropped.

Contamination lock: runs whose branch starts with zz-inj- or zz-probe- are
excluded from every rate and listed as excluded — injection PRs must not pollute
the metric they exist to test.

Speed is reported per PR class, code and docs-only SEPARATELY: aggregating lets
a pile of tiny docs PRs improve the average while nothing got faster. The
decisive signal is the last of the FOUR baseline required contexts to close —
the set is fixed here, so demoting a slow context later cannot improve the
metric without an explicit plan change.

Exit codes: 0 measurement produced; 2 input could not be read or evaluated.
This is a measurement, not a gate: it does not fail because the numbers are bad.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_DEFAULT = "soyeht/theyos"

# Fixed by the plan ("as quatro fechaduras"): the metric measures the last of
# THESE to close, whatever branch protection says afterwards. Changing this set
# is a plan decision with before/after numbers, never a silent metric tweak.
REQUIRED_CONTEXTS = (
    "Build & Test (Rust / Linux)",
    "Build & Test (Rust / macOS)",
    "No-Bash Policy Check",
    "Install/Uninstall Smoke",
)

BACKEND_WORKFLOW_PATH = ".github/workflows/backend-ci.yml"
SHIM_WORKFLOW_PATH = ".github/workflows/backend-ci-docs-shim.yml"

# Injection and probe branches stay out of every rate (trava de contaminação).
EXCLUDED_BRANCH_PREFIXES = ("zz-inj-", "zz-probe-")

# Assertion ladder (rule of three, 95%): a rung is certifiable only when n
# reaches it AND the CI upper — (failures+3)/n, ~3/n at zero observed events —
# stays below the rung's bound. Below the first rung nothing is certifiable —
# report the observed rate and the bound, and say so.
CI_LADDER = ((300, 0.01), (150, 0.02), (60, 0.05))

DEFAULT_TIMEOUT = 120


class MeasureError(Exception):
    """Input this instrument cannot read, parse or evaluate."""


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def run_gh(args: list[str], timeout: int = DEFAULT_TIMEOUT, retries: int = 3) -> str:
    detail = ""
    for attempt in range(1, retries + 1):
        try:
            result = subprocess.run(
                ["gh", *args],
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as error:
            raise MeasureError("gh CLI not found; install it or put it on PATH") from error
        except subprocess.TimeoutExpired:
            detail = f"timed out after {timeout}s"
            continue
        if result.returncode == 0:
            return result.stdout.decode("utf-8", "replace")
        detail = result.stderr.decode("utf-8", "replace").strip()
        # Transient network failures are expected on long measurement runs;
        # retry them, but never retry a real API error into a fake success.
        if "dial tcp" in detail or "connection" in detail.lower() or "timeout" in detail.lower():
            continue
        raise MeasureError(f"gh {' '.join(args[:4])} failed with exit {result.returncode}: {detail}")
    raise MeasureError(f"gh {' '.join(args[:4])} failed after {retries} attempts: {detail}")


def gh_api_json(repo: str, path: str, timeout: int = DEFAULT_TIMEOUT):
    return json.loads(run_gh(["api", f"repos/{repo}/{path}"], timeout))


def gh_api_pages(repo: str, path: str, item_key: str, timeout: int = DEFAULT_TIMEOUT) -> list:
    """Fetch every page of a list endpoint. filter=all is the caller's job."""
    items: list = []
    page = 1
    while True:
        sep = "&" if "?" in path else "?"
        batch = gh_api_json(repo, f"{path}{sep}per_page=100&page={page}", timeout)
        items.extend(batch.get(item_key, []))
        if len(batch.get(item_key, [])) < 100:
            return items
        page += 1


def gh_api_list(repo: str, path: str, timeout: int = DEFAULT_TIMEOUT) -> list:
    """Endpoints that answer with a bare JSON array (issue timelines)."""
    items: list = []
    page = 1
    while True:
        sep = "&" if "?" in path else "?"
        batch = gh_api_json(repo, f"{path}{sep}per_page=100&page={page}", timeout)
        items.extend(batch)
        if len(batch) < 100:
            return items
        page += 1


def job_wall_seconds(job: dict) -> float | None:
    started = parse_time(job.get("started_at"))
    completed = parse_time(job.get("completed_at"))
    if started is None or completed is None:
        return None
    return (completed - started).total_seconds()


def steps_wall_seconds(job: dict) -> float | None:
    """Method A: sum of step durations. Gaps between steps are not counted,
    which is exactly why it is reconciled against method B, never merged."""
    total = 0.0
    for step in job.get("steps") or []:
        started = parse_time(step.get("started_at"))
        completed = parse_time(step.get("completed_at"))
        if started is None or completed is None:
            continue
        total += (completed - started).total_seconds()
    return total


def ci_upper_bound(n: int, failures: int) -> float | None:
    """Rule-of-three 95% upper bound for a rate: ~3/n at zero observed events,
    ~(failures+3)/n with observed ones. n=0 measures nothing."""
    if n <= 0:
        return None
    return (failures + 3) / n


def ladder_rung(n: int, failures: int = 0) -> tuple[int, float] | None:
    """The strongest claim the evidence can certify: the LARGEST rung that n
    reaches AND whose bound the 95% CI upper does not exceed. The plan's
    ladder was written for zero observed flakes (upper ~3/n, with the rung
    minimums exactly where 3/n meets the bound, so equality certifies); with
    observed failures the bound must absorb them ((failures+3)/n) or the rung
    overclaims the data — n alone gates eligibility, the CI clears the claim.
    Found on the first real operation of this instrument: 8 flakes in n=731
    reported a <1% rung while the CI upper sat at 1.5%."""
    upper = ci_upper_bound(n, failures)
    if upper is None:
        return None
    for threshold, bound in CI_LADDER:
        if n >= threshold and upper <= bound:
            return threshold, bound
    return None


def is_excluded_branch(branch: str | None) -> bool:
    if not branch:
        return False
    return any(branch.startswith(prefix) for prefix in EXCLUDED_BRANCH_PREFIXES)


def last_closed_attempt(attempts: list[dict]) -> dict | None:
    """The attempt that decides the signal: the latest one with a conclusive
    ending. Cancelled never closed — it has no verdict to close with. Ties on
    attempt number (two DIFFERENT runs of one head both number their attempts
    from 1) break on completion time: the last to close is what decided."""
    closed = [
        attempt
        for attempt in attempts
        if attempt.get("conclusion") in ("success", "failure", "timed_out", "skipped", "startup_failure")
    ]
    if not closed:
        return None
    return max(
        closed,
        key=lambda attempt: (attempt.get("run_attempt", 0), attempt.get("completed_at") or ""),
    )


def dedup_jobs_by_id(jobs: list[dict]) -> dict[int, dict]:
    """Jobs are counted BY ID. Two check runs publishing the same name are two
    jobs; one job listed twice by a paging bug is one."""
    unique: dict[int, dict] = {}
    for job in jobs:
        unique[int(job["id"])] = job
    return unique


def decisive_attempt(jobs: list[dict], context: str) -> dict | None:
    """The attempt that decides one required context for one head. The shim
    publishes the SAME context names as the real build: when real attempts
    exist, shim attempts never decide — the shim is the stand-in, never the
    authority over a build that actually happened."""
    attempts = [j for j in jobs if j.get("name") == context]
    real = [j for j in attempts if j.get("_workflow_path") != SHIM_WORKFLOW_PATH]
    return last_closed_attempt(real if real else attempts)


def classify_pr(jobs_by_id: dict[int, dict]) -> str:
    """code vs docs-only: did the REAL backend workflow run for this head, or
    only the shim? Identity is the workflow PATH, never the job name."""
    for job in jobs_by_id.values():
        if job.get("_workflow_path") == BACKEND_WORKFLOW_PATH:
            return "code"
    return "docs-only"


def reconcile_run(jobs_by_id: dict[int, dict]) -> dict:
    """A vs B per workflow-run: step sums vs job walls, with the delta. Exact
    counts; time sums carry the delta beside them, never hidden in a total."""
    method_a = 0.0
    method_b = 0.0
    timed = 0
    for job in jobs_by_id.values():
        wall = job_wall_seconds(job)
        steps = steps_wall_seconds(job)
        if wall is None or steps is None:
            continue
        method_a += steps
        method_b += wall
        timed += 1
    return {
        "jobs_timed": timed,
        "method_a_step_sum_seconds": round(method_a, 1),
        "method_b_job_wall_seconds": round(method_b, 1),
        "delta_seconds": round(method_b - method_a, 1),
    }


def fetch_run(repo: str, run_id: int, timeout: int) -> dict:
    run = gh_api_json(repo, f"actions/runs/{run_id}", timeout)
    jobs = gh_api_pages(repo, f"actions/runs/{run_id}/jobs?filter=all", "jobs", timeout)
    for job in jobs:
        job["_workflow_path"] = run.get("path")
        job["_run_id"] = run_id
    return {"run": run, "jobs": jobs}


def fetch_pr_heads(repo: str, timeout: int) -> dict[str, dict]:
    """head SHA -> PR facts, for classing heads and finding merge commits."""
    out = run_gh(
        [
            "pr", "list", "--repo", repo, "--state", "all", "--limit", "500",
            "--json", "number,headRefOid,headRefName,mergedAt,mergeCommit,createdAt",
        ],
        timeout,
    )
    prs = json.loads(out)
    by_sha: dict[str, dict] = {}
    for pr in prs:
        by_sha[pr["headRefOid"]] = pr
    return by_sha


def anchor_for_head(repo: str, pr: dict | None, head_sha: str, timeout: int) -> datetime | None:
    """Instant zero for a head: the event that PUT that sha on the PR (creation
    or synchronize), so stacking commits before review cannot shift the clock.
    Falls back to the commit's committer date when the event is unreadable."""
    if pr is not None:
        number = pr["number"]
        try:
            events = gh_api_list(repo, f"issues/{number}/timeline", timeout=timeout)
        except MeasureError:
            events = []
        candidates: list[datetime] = []
        for event in events:
            if event.get("event") in ("synchronize", "head_ref_force_pushed") and event.get("sha") == head_sha:
                at = parse_time(event.get("created_at"))
                if at is not None:
                    candidates.append(at)
        if candidates:
            return max(candidates)
        created = parse_time(pr.get("createdAt"))
        if created is not None and pr.get("headRefOid") == head_sha:
            return created
    try:
        commit = gh_api_json(repo, f"commits/{head_sha}", timeout)
    except MeasureError:
        return None
    return parse_time(((commit.get("commit") or {}).get("committer") or {}).get("date"))


def measure(repo: str, run_ids: list[int], classifications: dict[str, str], timeout: int) -> dict:
    fetched = []
    for run_id in run_ids:
        fetched.append(fetch_run(repo, run_id, timeout))

    all_jobs: list[dict] = []
    run_reports = []
    for item in fetched:
        run = item["run"]
        jobs_by_id = dedup_jobs_by_id(item["jobs"])
        all_jobs.extend(jobs_by_id.values())
        run_reports.append(
            {
                "run_id": run["id"],
                "name": run.get("name"),
                "workflow_path": run.get("path"),
                "event": run.get("event"),
                "head_sha": run.get("head_sha"),
                "head_branch": run.get("head_branch"),
                "conclusion": run.get("conclusion"),
                "created_at": run.get("created_at"),
                "run_started_at": run.get("run_started_at"),
                "queue_seconds": (
                    (parse_time(run.get("run_started_at")) - parse_time(run.get("created_at"))).total_seconds()
                    if parse_time(run.get("run_started_at")) and parse_time(run.get("created_at"))
                    else None
                ),
                "job_count_exact": len(jobs_by_id),
                "attempt_count": len(item["jobs"]),
                "reconcile": reconcile_run(jobs_by_id),
            }
        )

    job_count_by_id = len({int(job["id"]) for job in all_jobs})

    # Required-context attempts: every attempt of every job publishing one of
    # the four fixed names. Counted by id; classed by name only for membership.
    required_attempts = [
        job for job in all_jobs if job.get("name") in REQUIRED_CONTEXTS
    ]
    # Flake exposure lives in REAL builds. Shim attempts are deterministic 3s
    # stands-ins: counting them in the denominator dilutes the rate without
    # adding any roll of the dice — the exact "aggregada é diluível" hole the
    # plan warns about. The shim count is reported beside the rate, never in it.
    shim_attempts = [j for j in required_attempts if j.get("_workflow_path") == SHIM_WORKFLOW_PATH]
    rate_attempts = [j for j in required_attempts if j.get("_workflow_path") != SHIM_WORKFLOW_PATH]
    failures = [job for job in required_attempts if job.get("conclusion") == "failure"]

    buckets: dict[str, int] = {}
    unclassified_failures = []
    for job in failures:
        bucket = classifications.get(str(job["id"]))
        if bucket is None:
            unclassified_failures.append(
                {
                    "job_id": job["id"],
                    "run_id": job["_run_id"],
                    "attempt": job.get("run_attempt"),
                    "name": job.get("name"),
                    "head_branch": next(
                        (r["head_branch"] for r in run_reports if r["run_id"] == job["_run_id"]), None
                    ),
                }
            )
            bucket = "unclassified"
        buckets[bucket] = buckets.get(bucket, 0) + 1

    n_attempts = len(rate_attempts)
    n_flake = buckets.get("flake", 0)
    observed_rate = (n_flake / n_attempts) if n_attempts else None
    rung = ladder_rung(n_attempts, n_flake)
    # A rate computed while failures sit unclassified is a lie by omission:
    # "0% flake" with 28 unbucked failures is not a measurement, it is an
    # empty bucket. No rung is certifiable until every failure has a bucket.
    if unclassified_failures:
        rung = None

    # Per-head aggregation: class, cost (every attempt), signal (last attempt).
    by_head: dict[str, dict] = {}
    for job in all_jobs:
        run_report = next(r for r in run_reports if r["run_id"] == job["_run_id"])
        sha = run_report["head_sha"]
        head = by_head.setdefault(
            sha,
            {
                "head_sha": sha,
                "head_branch": run_report["head_branch"],
                "excluded": is_excluded_branch(run_report["head_branch"]),
                "jobs": {},
                "runner_seconds": 0.0,
            },
        )
        head["jobs"][int(job["id"])] = job
        wall = job_wall_seconds(job)
        if wall is not None:
            head["runner_seconds"] += wall

    head_reports = []
    for sha, head in by_head.items():
        pr = fetch_pr_heads_cached(repo, sha, timeout)
        klass = classify_pr(head["jobs"])
        signal = {}
        for context in REQUIRED_CONTEXTS:
            closed = decisive_attempt(list(head["jobs"].values()), context)
            signal[context] = {
                "closed": closed is not None,
                "conclusion": closed.get("conclusion") if closed else None,
                "completed_at": closed.get("completed_at") if closed else None,
            }
        head_reports.append(
            {
                "head_sha": sha,
                "head_branch": head["head_branch"],
                "excluded": head["excluded"],
                "class": klass,
                "pr_number": pr["number"] if pr else None,
                "merged_at": pr.get("mergedAt") if pr else None,
                "runner_minutes_all_attempts": round(head["runner_seconds"] / 60.0, 1),
                "signal": signal,
            }
        )

    # Decisive-signal latency per non-excluded head: last of the four to close
    # minus the anchor. p50 per class, never aggregated across classes.
    latency_by_class: dict[str, list[float]] = {}
    for head in head_reports:
        if head["excluded"]:
            continue
        endings = [s["completed_at"] for s in head["signal"].values() if s["closed"]]
        if len(endings) != len(REQUIRED_CONTEXTS):
            head["signal_minutes"] = None
            continue
        anchor = anchor_for_head(repo, fetch_pr_heads_cached(repo, head["head_sha"], timeout), head["head_sha"], timeout)
        end = max(parse_time(value) for value in endings)
        if anchor is None:
            head["signal_minutes"] = None
            continue
        minutes = (end - anchor).total_seconds() / 60.0
        head["signal_minutes"] = round(minutes, 1)
        latency_by_class.setdefault(head["class"], []).append(minutes)

    p50_by_class = {
        klass: round(statistics.median(values), 1) for klass, values in latency_by_class.items() if values
    }
    runner_minutes_by_class: dict[str, list[float]] = {}
    for head in head_reports:
        if head["excluded"]:
            continue
        runner_minutes_by_class.setdefault(head["class"], []).append(head["runner_minutes_all_attempts"])
    runner_p50_by_class = {
        klass: round(statistics.median(values), 1) for klass, values in runner_minutes_by_class.items() if values
    }

    # Divergence: PR green on its head, main red on the merge commit. Pushes to
    # main with no PR behind them are the ungated class, counted apart.
    merged_prs = {sha: fetch_pr_heads_cached(repo, sha, timeout) for sha in by_head}
    merge_commit_to_sha = {}
    for sha, pr in merged_prs.items():
        if pr and pr.get("mergedAt") and pr.get("mergeCommit"):
            merge_commit_to_sha[pr["mergeCommit"]["oid"]] = sha
    divergence = []
    ungated_main_runs = []
    for report in run_reports:
        if report["event"] != "push" or report["head_branch"] != "main":
            continue
        sha = report["head_sha"]
        jobs_by_id = {int(j["id"]): j for j in all_jobs if j["_run_id"] == report["run_id"]}
        verdicts = {}
        for context in REQUIRED_CONTEXTS:
            closed = decisive_attempt(list(jobs_by_id.values()), context)
            verdicts[context] = closed.get("conclusion") if closed else None
        red = any(v == "failure" for v in verdicts.values())
        if sha in merge_commit_to_sha:
            head_sha = merge_commit_to_sha[sha]
            pr_head = next((h for h in head_reports if h["head_sha"] == head_sha), None)
            pr_green = pr_head is not None and all(
                s["closed"] and s["conclusion"] == "success" for s in pr_head["signal"].values()
            )
            if pr_green and red:
                divergence.append({"pr_number": pr_head["pr_number"], "head_sha": head_sha, "main_run": report["run_id"]})
        else:
            ungated_main_runs.append({"run_id": report["run_id"], "head_sha": sha, "red": red})

    return {
        "repo": repo,
        "window_run_count": len(run_ids),
        "job_count_exact_by_id": job_count_by_id,
        "required_attempts": len(required_attempts),
        "required_attempts_rated": len(rate_attempts),
        "required_attempts_shim": len(shim_attempts),
        "required_failures": len(failures),
        "failure_buckets": buckets,
        "unclassified_failures": unclassified_failures,
        "flake_rate_observed": round(observed_rate, 4) if observed_rate is not None else None,
        "flake_rate_ci_upper_95": round(ci_upper_bound(n_attempts, n_flake), 4)
        if ci_upper_bound(n_attempts, n_flake) is not None
        else None,
        "certifiable_rung": {"n": rung[0], "claim_lt": rung[1]} if rung else None,
        "heads": head_reports,
        "p50_decisive_signal_minutes_by_class": p50_by_class,
        "p50_runner_minutes_per_pr_by_class": runner_p50_by_class,
        "divergence_green_pr_red_main": divergence,
        "ungated_main_runs": ungated_main_runs,
        "runs": run_reports,
    }


_PR_HEADS_CACHE: dict[str, dict | None] = {}


def fetch_pr_heads_cached(repo: str, head_sha: str, timeout: int) -> dict | None:
    if repo not in _PR_HEADS_CACHE:
        _PR_HEADS_CACHE[repo] = fetch_pr_heads(repo, timeout)
    table = _PR_HEADS_CACHE[repo]
    return table.get(head_sha) if isinstance(table, dict) else None


def render(result: dict) -> str:
    lines = []
    lines.append("== CI health measurement ==")
    lines.append(f"repo: {result['repo']}")
    lines.append(f"window runs: {result['window_run_count']}  (frozen list; same set for every measurer)")
    lines.append(f"jobs counted (by id, filter=all, all attempts): {result['job_count_exact_by_id']}")
    lines.append("")
    lines.append(
        f"required-context attempts: {result['required_attempts']} total — "
        f"{result['required_attempts_rated']} rated (real builds), "
        f"{result['required_attempts_shim']} shim (deterministic, out of the denominator)   "
        f"failures: {result['required_failures']}"
    )
    lines.append(f"failure buckets: {json.dumps(result['failure_buckets'], ensure_ascii=False)}")
    if result["unclassified_failures"]:
        lines.append("unclassified failures (never folded into a bucket silently):")
        for item in result["unclassified_failures"]:
            lines.append(
                f"  job {item['job_id']} run {item['run_id']} attempt {item['attempt']} "
                f"{item['name']} branch={item['head_branch']}"
            )
    rate = result["flake_rate_observed"]
    upper = result["flake_rate_ci_upper_95"]
    rung = result["certifiable_rung"]
    if rate is None:
        lines.append("flake rate: n=0, nothing measured")
    else:
        if result["unclassified_failures"]:
            claim = (
                f"NOT certifiable — {len(result['unclassified_failures'])} failure(s) "
                "await classification; the observed rate is not trustworthy until every "
                "failure has a bucket"
            )
        elif rung:
            claim = f"certifiable: <{rung['claim_lt']:.0%} (n≥{rung['n']})"
        else:
            claim = "NOT certifiable — observed rate only, below the n≥60 rung"
        lines.append(
            f"flake rate: observed {rate:.2%} with 95% CI upper {upper:.2%} — {claim}"
        )
    lines.append("")
    lines.append(f"p50 decisive-signal minutes by class: {json.dumps(result['p50_decisive_signal_minutes_by_class'])}")
    lines.append(f"p50 runner-minutes per PR by class: {json.dumps(result['p50_runner_minutes_per_pr_by_class'])}")
    lines.append(f"divergence green-PR -> red-main: {len(result['divergence_green_pr_red_main'])}")
    for item in result["divergence_green_pr_red_main"]:
        lines.append(f"  PR #{item['pr_number']} head {item['head_sha'][:10]} main run {item['main_run']}")
    lines.append(f"ungated pushes to main (no PR): {len(result['ungated_main_runs'])}")
    for item in result["ungated_main_runs"]:
        lines.append(f"  run {item['run_id']} sha {item['head_sha'][:10]} red={item['red']}")
    lines.append("")
    lines.append("per-run reconciliation (A=step sums, B=job walls; counts exact):")
    for run in result["runs"]:
        rec = run["reconcile"]
        lines.append(
            f"  run {run['run_id']} {run['workflow_path']} jobs={run['job_count_exact']} "
            f"attempts={run['attempt_count']} A={rec['method_a_step_sum_seconds']}s "
            f"B={rec['method_b_job_wall_seconds']}s delta={rec['delta_seconds']}s "
            f"queue={run['queue_seconds']}s"
        )
    excluded = [h for h in result["heads"] if h["excluded"]]
    if excluded:
        lines.append("")
        lines.append(f"excluded heads (injection/probe, out of every rate): {len(excluded)}")
        for head in excluded:
            lines.append(f"  {head['head_sha'][:10]} {head['head_branch']}")
    return "\n".join(lines)


def collect_window(repo: str, since_days: int, timeout: int) -> list[int]:
    horizon = datetime.now(tz=timezone.utc).timestamp() - since_days * 86400
    run_ids: list[int] = []
    page = 1
    while True:
        batch = gh_api_json(repo, f"actions/runs?per_page=100&page={page}", timeout)
        runs = batch.get("workflow_runs", [])
        if not runs:
            break
        for run in runs:
            created = parse_time(run.get("created_at"))
            if created is None:
                continue
            if created.timestamp() < horizon:
                return run_ids
            run_ids.append(int(run["id"]))
        page += 1
    return run_ids


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure CI health from the Actions API (Fase 0 ruler).")
    parser.add_argument("--repo", default=REPO_DEFAULT, help="owner/name to measure")
    parser.add_argument("--window", help="JSON file with a FROZEN list of run ids to measure")
    parser.add_argument("--since-days", type=int, help="collect runs newer than N days (when no --window)")
    parser.add_argument("--freeze-out", help="write the collected run-id list here, to freeze the window")
    parser.add_argument(
        "--classifications",
        help="JSON file mapping job id (string) to a cause bucket: "
        "flake, defeito-real, infra, gate-quebrado, ungated, unexplained",
    )
    parser.add_argument("--out", help="write the full JSON measurement here")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="per-gh-call timeout seconds")
    args = parser.parse_args(argv)

    if args.window is None and args.since_days is None:
        print("ERROR: give --window (frozen list) or --since-days N to collect one", file=sys.stderr)
        return 2

    classifications: dict[str, str] = {}
    if args.classifications:
        try:
            classifications = json.loads(Path(args.classifications).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"ERROR: cannot read classifications: {error}", file=sys.stderr)
            return 2

    try:
        if args.window:
            try:
                window = json.loads(Path(args.window).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                print(f"ERROR: cannot read window file: {error}", file=sys.stderr)
                return 2
            run_ids = [int(item) for item in window.get("run_ids", [])]
            if not run_ids:
                print("ERROR: window file carries no run_ids", file=sys.stderr)
                return 2
        else:
            run_ids = collect_window(args.repo, args.since_days, args.timeout)
            if not run_ids:
                print("ERROR: no runs found in the requested window", file=sys.stderr)
                return 2
            if args.freeze_out:
                payload = {
                    "repo": args.repo,
                    "collected_at": datetime.now(tz=timezone.utc).isoformat(),
                    "since_days": args.since_days,
                    "run_ids": run_ids,
                }
                Path(args.freeze_out).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
                print(f"window frozen: {len(run_ids)} run ids -> {args.freeze_out}")

        result = measure(args.repo, run_ids, classifications, args.timeout)
    except MeasureError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(render(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
