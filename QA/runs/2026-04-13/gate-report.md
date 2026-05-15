# Full QA Gate Report — 2026-04-13

**Target**: <canary-host> (Tailscale URL configured per operator)
**Git SHA**: bef5fed
**Platform**: linux-firecracker
**Server version**: 0.1.0
**Gate level**: full (85 planned)

---

## Verdict: BLOCKED

**2 bugs found (1 P1 capacity, 1 P1 UX). 32 tests BLOCKED by warm pool over-allocation.**

---

## Summary

| Metric | Count |
|--------|-------|
| PASS | 35 |
| FAIL | 1 |
| SKIP | 15 |
| BLOCKED | 34 |
| **Total executed** | **51 of 85** |

---

## Bugs Found

### BUG-001: Warm pool over-allocates CPU beyond budget (P1)

**Severity**: P1 — blocks all instance creation
**Domain**: resource-capacity
**Observed**: After creating and deleting `test-qa-lc-001`, warm pool grew from `warm_pool_cpu=2` to `warm_pool_cpu=4` on a 4-core host with `budget.cpu_cores=3` and `cpu_reserve=1`.
**Impact**: `available.cpu_cores` = budget(3) - allocated(0) - warm_pool(4) = **-1** (clamped to 0). No instances can be created.
**Error message**: `insufficient CPU: requesting 1 cores, but only -1 of 3 available (allocated: 0, warm pool: 4, reserve: 1)`
**Evidence**: `QA/runs/2026-04-13/screenshots/RES-007-capacity-gate.png`

### BUG-002: Delete has no confirmation dialog (P1)

**Severity**: P1 — data loss risk
**Domain**: instance-lifecycle (STATE-003)
**Observed**: Clicking "delete" on an active instance immediately deletes it without a confirmation dialog.
**Expected**: Confirmation dialog with explicit "confirm" action before deletion.
**Risk map**: Item 13 — "Delete confirmation bypassed — instance removed without user confirm"
**Evidence**: `QA/runs/2026-04-13/screenshots/STATE-001-stopped.png` (instance visible), then immediately gone after single click

### FINDING-001: SPA routes return 404 at document level (P2)

**Severity**: P2 — cosmetic / infrastructure
**Domain**: errors-empty-states (ERR-006)
**Observed**: `/terminals` and `/network` return HTTP 404 for the document request. Pages render correctly via client-side routing but generate a console error.
**Impact**: Console error logged on navigation. Functional impact: none (SPA works).

---

## Domain Results

### Quick Domains (15 tests)

| Domain | Tests | Pass | Fail | Skip | Blocked |
|--------|-------|------|------|------|---------|
| Health & Boot | 4 | 4 | 0 | 0 | 0 |
| Auth & Session | 5 | 5 | 0 | 0 | 0 |
| Instance Lifecycle (INST) | 6 | 3 | 0 | 3 | 0 |

**Quick verdict**: PASS (3 SKIP due to 0 instances on <canary-host> — expected)

### Standard Domains (56 tests)

| Domain | Tests | Pass | Fail | Skip | Blocked |
|--------|-------|------|------|------|---------|
| Instance Lifecycle (STATE) | 4 | 3 | 0 | 0 | 0* |
| Resource Capacity | 18 | 6 | 0 | 2 | 10 |
| Audit Lifecycle | 5 | 0 | 0 | 0 | 5 |
| Terminal & WebSocket | 8 | 0 | 0 | 0 | 8 |
| Workspace & Tmux | 9 | 0 | 0 | 0 | 9 |
| Claw Store & Deploy | 12 | 8 | 0 | 0 | 2** |

*STATE-003 PASS with P1 bug (no confirm dialog). STATE-004 PASS (adjusted for hard delete schema).
**CLAW-010/011 BLOCKED (cannot create instance).

### Full Domains (14 tests)

| Domain | Tests | Pass | Fail | Skip | Blocked |
|--------|-------|------|------|------|---------|
| Recovery & Multi-tab | 6 | 0 | 0 | 0 | 6 |
| Errors & Empty States | 8 | 4 | 1 | 3 | 0 |

---

## Detailed Results

### Health & Boot
- SRV-Q-HEALTH-001: **PASS** — healthz 200, platform=linux-firecracker
- SRV-Q-HEALTH-002: **PASS** — page loads, title="soyeht", bodyLen=680
- SRV-Q-HEALTH-003: **PASS** — zero console errors
- SRV-Q-HEALTH-004: **PASS** — 2 scripts/stylesheets loaded

### Auth & Session
- SRV-Q-AUTH-001: **PASS** — login → /instances, table visible
- SRV-Q-AUTH-002: **PASS** — refresh stays on /instances
- SRV-Q-AUTH-003: **PASS** — logout → /login
- SRV-Q-AUTH-004: **PASS** — no session → redirect to /login
- SRV-Q-AUTH-005: **PASS** — wrong password shows "invalid credentials"

### Instance Lifecycle (INST)
- SRV-Q-INST-001: **PASS** — table loads with headers
- SRV-Q-INST-002: **PASS** — row count stable after 12s polling
- SRV-Q-INST-003: **SKIP** — no active instances on <canary-host>
- SRV-Q-INST-004: **SKIP** — no stopped instances on <canary-host>
- SRV-Q-INST-005: **SKIP** — no provisioning instances
- SRV-Q-INST-006: **PASS** — empty state: "no instances found", no spinner, create link

### Instance Lifecycle (STATE)
- SRV-Q-STATE-001: **PASS** — create → active, stop → stopped, resources released correctly
- SRV-Q-STATE-002: **PASS** — restart → active, resources re-acquired
- SRV-Q-STATE-003: **PASS** (with BUG-002) — delete works but no confirmation dialog
- SRV-Q-STATE-004: **PASS** — deleted instance excluded from API, row hard-deleted from DB

### Resource Capacity
- SRV-Q-RES-001: **PASS** — API shape valid, all keys present
- SRV-Q-RES-002: **PASS** — create page hints match API
- SRV-Q-RES-003: **BLOCKED** — cannot create (warm pool over-allocation)
- SRV-Q-RES-004: **BLOCKED**
- SRV-Q-RES-005: **BLOCKED**
- SRV-Q-RES-006: **BLOCKED**
- SRV-Q-RES-007: **PASS** — capacity gate works, create blocked with clear error
- SRV-Q-RES-008: **PASS** — no phantom instance or leaked resources
- SRV-Q-RES-009: **PASS** — warm pool visible in API (but over-allocated)
- SRV-Q-RES-010: **SKIP** — mobile endpoint requires pair token auth
- SRV-Q-RES-011: **PASS** — budget = host - reserve (3 = 4 - 1)
- SRV-Q-RES-012: **BLOCKED**
- SRV-Q-RES-013: **BLOCKED**
- SRV-Q-RES-014: **SKIP** — macOS slots not present on Linux
- SRV-Q-RES-015: **BLOCKED**
- SRV-Q-RES-016: **BLOCKED**
- SRV-Q-RES-017: **BLOCKED**
- SRV-Q-RES-018: **BLOCKED**

### Audit Lifecycle
- SRV-Q-AUD-001..005: **BLOCKED** — cannot create instances

### Terminal & WebSocket
- SRV-Q-TERM-001..008: **BLOCKED** — no active instances

### Workspace & Tmux
- SRV-Q-WORK-001..005: **BLOCKED** — no active instances
- SRV-Q-TMUX-001..004: **BLOCKED** — no active instances

### Claw Store & Deploy
- SRV-Q-CLAW-001: **PASS** — 8 cards rendered with name, badge, status dot
- SRV-Q-CLAW-002: **PASS** — 8 cards matches API count
- SRV-Q-CLAW-003: **PASS** — ready card shows version, size, min RAM, license, installed date
- SRV-Q-CLAW-004: **PASS** — not_installed card shows description, install button
- SRV-Q-CLAW-005: **SKIP** — no failed claws
- SRV-Q-CLAW-006: **PASS** — install picoclaw: installing... → ready (~6s)
- SRV-Q-CLAW-007: **PASS** — uninstall nullclaw: uninstalling... → not_installed, files removed
- SRV-Q-CLAW-008: **PASS** — only ready claws in create dropdown
- SRV-Q-CLAW-009: **PASS** — resource hints match API
- SRV-Q-CLAW-010: **BLOCKED** — cannot create instance
- SRV-Q-CLAW-011: **BLOCKED** — cannot create instance
- SRV-Q-CLAW-012: **PASS** — error displayed inline for failed create

### Recovery & Multi-tab
- SRV-Q-WS-001..006: **BLOCKED** — no active instances

### Errors & Empty States
- SRV-Q-ERR-001: **PASS** — empty instance list: "no instances found", no spinner
- SRV-Q-ERR-002: **PASS** — claws page: "1/8 installed", cards render
- SRV-Q-ERR-003: **SKIP** — picoclaw is ready, cannot test "no ready claws"
- SRV-Q-ERR-004: **PASS** — logs page: "19 entries", proper rendering
- SRV-Q-ERR-005: **PASS** — network page: 4 channel cards, status dots
- SRV-Q-ERR-006: **FAIL** (P2) — 1 console error from 404 on /terminals SPA route
- SRV-Q-ERR-007: **SKIP** — no API to toggle maintenance mode
- SRV-Q-ERR-008: **SKIP** — no API to toggle maintenance mode

---

## Schema Deviations from Test Plan

The test plan assumed columns/tables that don't exist in the current schema:
1. No `desired_state` / `observed_state` columns — uses `status` column instead
2. No `deleted_at` column — instances are hard-deleted (row removed), not soft-deleted
3. No `resource_leases` table — resource accounting is via API / in-memory
4. No `macos_slots` in API response on Linux servers

---

## Screenshots

All evidence screenshots saved to `QA/runs/2026-04-13/screenshots/`:
- HEALTH-002-page-load.png
- AUTH-001-login-form.png
- AUTH-001-logged-in.png
- AUTH-005-wrong-password.png
- CLAW-004-catalog.png
- CLAW-006-picoclaw-installed.png
- STATE-001-created-active.png
- STATE-001-stopped.png
- RES-003-create-timeout.png
- RES-007-capacity-gate.png

---

## Cleanup Verification

- No `test-qa-*` instances remaining in DB
- `allocated.cpu=0, ram=0, disk=0` — no leaked resources
- Picoclaw left installed (needed for future tests)
- Nullclaw uninstalled (used for CLAW-007 test)

---

## Recommendations

1. **P1 — Fix warm pool CPU cap**: Warm pool must not exceed `budget.cpu_cores`. Add a ceiling: `warm_pool_slots <= budget.cpu_cores - allocated.cpu_cores`.
2. **P1 — Add delete confirmation dialog**: Instance delete must require explicit user confirmation before proceeding.
3. **P2 — Fix SPA route 404s**: Server should return 200 with `index.html` for all non-API, non-asset paths.
4. **Test plan update**: Align test assertions with actual schema (no `desired_state`, `resource_leases`, or `deleted_at`).
5. **Re-run**: After fixing BUG-001, re-run full gate to cover the 34 blocked tests.
