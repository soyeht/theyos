# CI preflight baseline

Baseline measurements for the internal disposable-VM preflight (`soyeht
check`), recorded **before** any acceleration work, so every later claim of
"faster" has a number to be compared against. Measurements only — this
document changes no required check, no coverage, and no workflow semantics.

Method: GitHub Actions API over completed runs, per-job wall clock
(`startedAt → completedAt`). Counting caveat carried from the workflow's own
history: job listings **via the REST endpoint** must use `?filter=all`,
because its default returns only the latest attempt and silently drops
superseded ones; single-attempt runs are unaffected.

## theyos — Backend CI

Sample: **one** completed successful `pull_request` run at measurement time
(2026-08-11, run `31512760824`, head `510ea5c9`). A single run is a data
point, not a median; the table below is the honest current baseline and
should be re-derived as the window accumulates.

All seven jobs of the run, exact context names as the API reports them:

| job | wall time |
|---|---|
| Build & Test (Rust / macOS) | **57.0 min** |
| Build & Test (Rust / Linux) | 53.0 min |
| ClawShareBridge (B3-0 slice) | 2.1 min |
| Quarantine isolation probes (macos-15, non-required) | 1.7 min |
| Quarantine isolation probes (ubuntu-latest, non-required) | 1.6 min |
| No-Bash Policy Check | 0.1 min |
| Installer Unit Tests | 0.1 min |
| **workflow total (wall)** | **57.1 min** |

Cost structure, anchored to measured statements already recorded in
`.github/workflows/backend-ci.yml`:

- The cold `--all-targets` compile measures into the low-20-minute range on
  `ubuntu-latest` and the high-20-minute range on `macos-15`; with the full
  suite on top both Rust jobs crossed a 50-minute ceiling and were cancelled
  mid-suite, so `timeout-minutes` was raised to 75 in `510ea5c9` (to be
  lowered again as its own measured change once the compile is cached or
  trimmed).
- The serialised suite runs under `--test-threads=1`; the three slow
  `phase3_atomic_rollback` tests already run in a dedicated step with the
  injectable 1s recovery budget, so the ~300s×3 wait no longer dominates.
- `concurrency` with `cancel-in-progress` (main exempt) is already in place,
  so superseded PR runs do not burn runners.

## soyeht-ios — Swift workflow

The larger measured fact first: **at measurement time (2026-08-11)**,
`actions/permissions` on the repository reported `enabled: false` and the
run count was **zero for every workflow**, not just `Swift`
(`/actions/runs` → `total_count: 0`). No workflow had ever executed
there; a first run requires a separate admin decision, tracked outside
this document. Until that decision lands, the iOS baseline remains
**unmeasured for this snapshot**, and no number is invented here.

A canonical command (`scripts/ci/test-ios`, proposed in a separate PR and
not yet on main at measurement time) would print per-phase timing so this
table could be derived from any run log once runs exist — no run is
promised while Actions is disabled.

Duplicate work already visible in the workflow definition (candidate for a
later, separately-measured change; not altered now): the package tests
execute twice on every run — once in the test phase and again in the
coverage phase via `swift test --enable-code-coverage`.

## Reproduction

```sh
gh run list --repo soyeht/theyos --workflow backend-ci.yml \
  --status completed --json databaseId,event,conclusion,headSha
gh run view <run-id> --repo soyeht/theyos --json jobs
```

Per-job wall = `completedAt - startedAt` of each entry in `jobs`. The
`?filter=all` caveat applies to the **REST** jobs endpoint, whose default
returns only the latest attempt; the `gh run view` command above is
sufficient for this particular run, which has a single attempt.
