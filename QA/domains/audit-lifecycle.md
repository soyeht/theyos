---
id: audit-lifecycle
ids: SRV-Q-AUD-001..005
profile: standard
automation: auto
requires_browser: true
requires_ssh: true
target: canary
destructive: true
cleanup_required: true
---

# Audit Lifecycle

## Objective
Verify that instance lifecycle events are recorded in `instance_events` with correct event types, ordering, actor attribution, and resource_snapshot payloads.

## Risk
If events are missing or snapshots aren't recorded, post-incident analysis is blind. If event ordering is wrong, the audit trail is misleading.

## Preconditions
- canary server running
- SSH access to <canary-host> with SQLite query capability
- Chrome MCP connected
- At least 1 claw installed and ready on <canary-host>

## Fixtures
- Instance: `test-qa-aud-001`
- Prefix: `test-qa-aud-*`

## Test Cases

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-AUD-001 | **Create** `test-qa-aud-001` via /create page. Immediately after submit, SSH: `sqlite3 DB "SELECT event_type, resource_snapshot IS NOT NULL AS has_snap FROM instance_events WHERE instance_id = (SELECT id FROM instances WHERE name = 'test-qa-aud-001') ORDER BY created_at"` | `create_started` event exists. `has_snap` = 1 (resource_snapshot is non-null JSON) | P1 | Yes |
| SRV-Q-AUD-002 | Wait for instance to reach "active" status. SSH query events again | `create_completed` event exists with `has_snap = 1`. Event `created_at` is after `create_started` | P1 | Yes |
| SRV-Q-AUD-003 | Trigger a create failure: attempt to create with an invalid configuration (e.g., claw type that doesn't exist or name conflict). SSH query events for the failed instance | `create_failed` event exists with `has_snap = 1` and `detail` field containing error description | P1 | Yes |
| SRV-Q-AUD-004 | **Delete** `test-qa-aud-001` (click delete + confirm). SSH query events | `delete_started` event exists. `delete_completed` event exists. `delete_started.created_at` < `delete_completed.created_at` (correct chronological ordering) | P1 | Yes |
| SRV-Q-AUD-005 | SSH: comprehensive event validation for `test-qa-aud-001` | All events have: `instance_id` is NOT NULL, `actor` is non-empty string, `resource_snapshot` where present is valid JSON (`json_valid() = 1`). No duplicate event types for single operations | P1 | Yes |

## How to Automate

**AUD-001**: Create instance, wait 2s for event to be recorded, then SSH query.

**AUD-002**: Poll instance status via Chrome MCP (check `.create-result .status-line` text) until "active", then SSH query.

**AUD-003**: Navigate to /create, fill form with invalid claw type (e.g., "nonexistent-claw") or duplicate name. Submit. If create page shows error immediately, query events for any job that was created. If the job fails asynchronously, wait for failure status then query. This test may SKIP if there's no easy way to trigger a failure.

**AUD-004**: Navigate to /instances, find `test-qa-aud-001`, click delete, confirm. Wait for removal from list. SSH query events with ordering check:
```bash
ssh <canary-host> "sqlite3 ~/theyos/.run/theyos.db \"SELECT e1.event_type, e2.event_type, CASE WHEN e1.created_at < e2.created_at THEN 'CORRECT' ELSE 'WRONG' END FROM instance_events e1 JOIN instance_events e2 ON e1.instance_id = e2.instance_id WHERE e1.event_type = 'delete_started' AND e2.event_type = 'delete_completed' AND e1.instance_id = (SELECT id FROM instances WHERE name = 'test-qa-aud-001')\""
```

**AUD-005**: Run comprehensive validation query:
```bash
ssh <canary-host> "sqlite3 ~/theyos/.run/theyos.db \"SELECT event_type, instance_id IS NOT NULL AS has_inst, actor != '' AS has_actor, CASE WHEN resource_snapshot IS NOT NULL THEN json_valid(resource_snapshot) ELSE 1 END AS snap_ok FROM instance_events WHERE instance_id = (SELECT id FROM instances WHERE name = 'test-qa-aud-001') ORDER BY created_at\""
```
All rows should show `has_inst=1, has_actor=1, snap_ok=1`.

## Cleanup

Soft-deleted instances from AUD-004 stay in the database as part of the audit trail. Verify:
```bash
ssh <canary-host> "sqlite3 ~/theyos/.run/theyos.db \"SELECT name, desired_state, deleted_at IS NOT NULL AS deleted FROM instances WHERE name LIKE 'test-qa-aud-%'\""
```
All should show `deleted=1`.

No active leases should remain:
```bash
ssh <canary-host> "sqlite3 ~/theyos/.run/theyos.db \"SELECT * FROM resource_leases WHERE owner_id IN (SELECT id FROM instances WHERE name LIKE 'test-qa-aud-%') AND released_at IS NULL\""
```
Expected: empty.

## Out of Scope
- Stop/start/restart events (covered by instance-lifecycle STATE tests)
- Provisioning timeout events (covered by RES-018)
- Cross-server event replication
