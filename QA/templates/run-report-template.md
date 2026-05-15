# QA Report: <Gate Level / Domain Name>

**Date**: YYYY-MM-DD
**Tester**: Claude Code (Chrome MCP + SSH)
**Target**: <canary-host> (Tailscale: https://<your-host>.<your-tailnet>.ts.net)
**Server Version**: <commit hash from `ssh <canary-host> "cd ~/theyos && git rev-parse --short HEAD"`>
**Platform**: <from /healthz response>
**Plan Reference**: QA/domains/<domain>.md

---

## Executive Summary

**X test cases planned, Y executed, Z skipped.**
**Result: A/Y PASS, B/Y FAIL (C% pass rate)**

<1-3 sentence summary of findings>

---

## Test Results

### <Domain Name> (X/Y PASS)

| ID | Description | Status | Notes |
|----|-------------|--------|-------|
| SRV-Q-XXX-001 | <test description> | PASS/FAIL/SKIP | <evidence or explanation> |

---

## Backend Cross-Check

### Resource Leases
- Active leases before test: N
- Active leases after test: N (expected: same as before)
- Orphaned leases found: 0

### Instance Events
- Events recorded correctly: Yes/No
- resource_snapshot present: Yes/No
- Event ordering correct: Yes/No

### Desired State Consistency
- All test instances: desired_state matches observed_state
- Soft-deleted instances excluded from API: Yes/No

---

## Bugs Found

### BUG-XXX: <title> [Severity: P0/P1/P2/P3]

**Steps**: <repro steps>
**Expected**: <expected>
**Actual**: <actual>
**Screenshot**: `screenshots/<filename>.png`
**Backend Evidence**: <SQLite query result or API response>

---

## Gate Verdict

| Category | Result |
|----------|--------|
| Health & Boot | PASS/FAIL (X/Y) |
| Auth & Session | PASS/FAIL (X/Y) |
| Instance Lifecycle | PASS/FAIL (X/Y) |
| Resource Capacity | PASS/FAIL (X/Y) |
| Audit Lifecycle | PASS/FAIL (X/Y) |
| **Overall** | **PASS / BLOCKED** |

**BLOCKED** if any P0/P1 failed. **PASS WITH WARNINGS** if only P2/P3.

---

## Cleanup

- [ ] `test-qa-*` instances deleted (or soft-deleted for audit)
- [ ] No active leases for `test-qa-*` owners
- [ ] Resources returned to baseline
- [ ] No leftover test data

## Test Artifacts

Screenshots saved to: `QA/runs/YYYY-MM-DD/screenshots/`
Only the textual report is intended to be committed to the repo.
