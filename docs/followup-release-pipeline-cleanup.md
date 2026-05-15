# Follow-up: Release pipeline cleanup (R9-A, R9-B)

Two low-priority design cleanups identified in code review R9 of PR #51.
Non-blocking — PR merged at 9c91b2c with zero actionable findings.

## R9-A: Legacy `notarize_macos()` is now a dead path for the release flow

**Symptom / issue:** The top-level `notarize_macos()` function in `scripts/make.sh`
(around line 209) is called only by the legacy `package()` function. The release
pipeline now goes through `package_soyeht_mac`, which has its own inline
notarization block added in R8-B. `notarize_macos()` is therefore dead code for
any release flow and its comment no longer accurately describes the architecture.

**What works:** Everything — R9-A is cosmetic only.

**Cleanup options:**
- Delete `notarize_macos()` and update the call site comment in `package()`, OR
- Keep as a utility available for future use but mark it explicitly as "used by
  legacy `package()` only, not the Soyeht.app release path."

**Files of interest:** `scripts/make.sh` — `notarize_macos()` (~line 209),
`package()` (~line 256), `package_soyeht_mac()` (~line 315).

---

## R9-B: `.notarize-soyeht-engine.zip` not cleaned up on notarytool failure

**Symptom / issue:** In `package_soyeht_mac`, the inline notarization block
creates `${REPO_ROOT}/.notarize-soyeht-engine.zip` and removes it after a
successful `notarytool submit`. If `notarytool` exits non-zero (submission
rejected, network error, etc.), the `set -euo pipefail` in the shell causes
the script to abort before the `rm -f "${notarize_zip}"` cleanup line runs.
The stale zip remains on disk.

**Impact:** Dev hygiene only. On CI the runner is ephemeral; on local dev the
zip sits at the repo root until manually removed or next successful run.

**Fix (trivial):** Wrap the block in a `trap` or restructure with a dedicated
cleanup function:

```bash
trap 'rm -f "${notarize_zip:-}"' EXIT
```

Or use a subshell + explicit cleanup:

```bash
rm -f "${notarize_zip}"  # cleanup regardless — runs even on error
xcrun notarytool submit ... --wait
# rm already done above
```

**Files of interest:** `scripts/make.sh` — `package_soyeht_mac()` notarization
block (~line 365–390).
