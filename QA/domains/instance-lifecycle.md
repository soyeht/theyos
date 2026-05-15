---
id: instance-lifecycle
ids: SRV-Q-INST-001..006, SRV-Q-STATE-001..004
profile: quick (INST), standard (STATE)
automation: auto
requires_browser: true
requires_ssh: true
target: canary
destructive: true
cleanup_required: true
---

# Instance Lifecycle

## Objective
Verify instance list display, polling stability, and the full lifecycle: create → stop → restart → delete. Validates desired_state, soft delete behavior, and lease transitions.

## Risk
- If polling duplicates rows, the UI becomes unreliable.
- If desired_state doesn't update on stop/delete, the lifecycle model is broken.
- If soft delete makes the instance reappear in the list, it's a P0.
- If leases aren't released on stop/delete, capacity accounting is wrong.

## Preconditions
- canary server running with at least one existing instance (for INST tests)
- Chrome MCP connected + SSH to <canary-host>
- For STATE tests: ability to create `test-qa-lc-*` instances

## Fixtures
- STATE tests create: `test-qa-lc-001`
- Prefix: `test-qa-lc-*`

## Test Cases — Quick Subset (INST)

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-INST-001 | Chrome: navigate `/instances`, `wait_for({ selector: ".instances-table", timeout: 10000 })` | Table loads. `evaluate_script("[...document.querySelectorAll('.instance-id-col')].length")` > 0 OR empty state visible | P0 | Yes |
| SRV-Q-INST-002 | Chrome: record row count, wait 12s (polling cycle), record row count again | Row count stable (no duplicates). `evaluate_script` returns same count ±0 | P1 | Yes |
| SRV-Q-INST-003 | Chrome: find row where status text = "active" | At least one row shows "active" status (if any active instances exist on <canary-host>) | P1 | Yes |
| SRV-Q-INST-004 | Chrome: find row where status text = "stopped" | Row shows "stopped" status correctly (if any stopped instances exist) | P1 | Yes |
| SRV-Q-INST-005 | Chrome: find row with `.provision-msg` or `.spinner-inline` | Provisioning indicator visible (if any provisioning instances exist). SKIP if none | P2 | Yes |
| SRV-Q-INST-006 | Chrome: if zero instances, check for empty state | No infinite spinner. Useful message or link to /create visible | P2 | Yes |

## Test Cases — Standard Subset (STATE)

These tests exercise the desired_state / soft delete / lease lifecycle.

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-STATE-001 | **Setup**: Create instance `test-qa-lc-001` via `/create` page (picoclaw, 1 CPU, 512MB). Wait until active. **Action**: Click "stop" button on instance row. **Verify UI**: Status changes to "stopped". **Verify SSH**: `sqlite3 DB "SELECT desired_state, observed_state FROM instances WHERE name='test-qa-lc-001'"` → `stopped|stopped`. **Verify leases**: runtime lease has `released_at` set, storage lease has `released_at IS NULL` | UI shows stopped. DB desired_state=stopped. Runtime lease released, storage kept | P0 | Yes |
| SRV-Q-STATE-002 | **Action**: Click "restart" on stopped `test-qa-lc-001`. **Verify UI**: Status returns to "active". **Verify SSH**: desired_state=`running`. **Verify leases**: new runtime lease acquired (`released_at IS NULL`), storage lease unchanged | UI shows active. DB desired_state=running. New runtime lease active | P0 | Yes |
| SRV-Q-STATE-003 | **Action**: Click "delete" on `test-qa-lc-001`. **Verify UI**: Confirmation dialog appears. Click confirm. Instance disappears from list. **Verify SSH**: `desired_state='deleted'`, `deleted_at IS NOT NULL`, **row still exists in DB**. Both leases have `released_at` set | UI: gone from list. DB: soft-deleted, both leases released | P0 | Yes |
| SRV-Q-STATE-004 | **Verify API**: `curl /api/v1/instances` — `test-qa-lc-001` does NOT appear in response. **Verify DB**: row exists with `deleted_at` set | Soft-deleted instance excluded from API but preserved in DB | P0 | Yes |

## How to Automate

**INST tests**: Navigate, wait_for, evaluate_script for DOM counts. Pure Chrome MCP, no SSH needed.

**STATE tests**:
1. STATE-001: Create via /create page (fill #claw-type, #cpu-cores, #ram-mb, #instance-name, submit). Wait for `.create-result` with status "active" (poll every 2s, timeout 120s). Then navigate to /instances, find row, click stop button. Wait for status change. SSH verify.
2. STATE-002: Find stopped instance row, click restart. Wait for active. SSH verify leases.
3. STATE-003: Click delete, wait_for confirmation dialog, click confirm. Wait for instance to disappear. SSH verify soft delete.
4. STATE-004: SSH curl + SQLite query.

Screenshot after each state transition.

## Cleanup

Delete any remaining `test-qa-lc-*` instances via the UI (click delete + confirm) or API:
```bash
ssh <canary-host> "curl -s -X DELETE localhost:8892/api/v1/instances/{id}"
```

Verify cleanup:
```bash
ssh <canary-host> "sqlite3 ~/theyos/.run/theyos.db \"SELECT name, desired_state, deleted_at IS NOT NULL AS deleted FROM instances WHERE name LIKE 'test-qa-lc-%'\""
```

All should show `deleted=1`. Verify no active leases remain.

## Out of Scope
- Rebuild action (V2)
- QR modal behavior (V2)
- Multi-instance concurrent operations
