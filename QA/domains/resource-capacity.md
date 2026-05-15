---
id: resource-capacity
ids: SRV-Q-RES-001..018
profile: standard
automation: auto (001-011, 013-017), assisted (012, 018)
requires_browser: true
requires_ssh: true
target: canary
destructive: true
cleanup_required: true
---

# Resource Capacity

## Objective
Verify that resource accounting via resource_leases is correct: runtime leases are acquired on create/start, released on stop, and both runtime + storage leases are released on delete. Validate that the API, UI, and SQLite all agree on capacity numbers.

## Risk
This is the highest-priority QA domain. Capacity bugs cause:
- Phantom resources: leases stuck after failed creates or crashes
- Overselling: more instances than host can support
- Underselling: available shows 0 when resources exist
- Data loss: disk not reserved (storage lease missing)

## Preconditions
- canary server running, not in maintenance mode
- SSH access to <canary-host> with SQLite query capability
- Chrome MCP connected
- At least 1 claw installed and ready on <canary-host> (for create tests)
- Note baseline resources before starting (record via SSH)

## Fixtures
- Instances: `test-qa-res-001`, `test-qa-res-002`
- Prefix: `test-qa-res-*`

## Test Cases

### Contract & Shape (001-002)

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-RES-001 | SSH: `curl -s localhost:8892/api/v1/admin/resources \| python3 -m json.tool` | Response has `host`, `allocated`, `budget`, `available`, `macos_slots` top-level keys. All numeric values are non-negative integers | P0 | Yes |
| SRV-Q-RES-002 | Chrome: navigate `/create`. Read CPU/RAM/disk option values. SSH: `curl /api/v1/admin/resources` | Create page resource hints are consistent with `available` from API. CPU options don't exceed `available.cpu_cores`. RAM options don't exceed `available.ram_mb` | P1 | Yes |

### Lifecycle Accounting (003-006)

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-RES-003 | **Baseline**: SSH record `allocated` values. **Create** `test-qa-res-001` (1 CPU, 512MB, 5GB). Wait active. **After**: SSH record `allocated` again. SSH query leases | `allocated.cpu_cores` increased by 1, `ram_mb` by 512, `disk_gb` by 5. SQLite: 2 active leases for this instance (runtime + storage), both `released_at IS NULL` | P0 | Yes |
| SRV-Q-RES-004 | **Stop** `test-qa-res-001`. SSH query resources + leases | `allocated.cpu_cores` decreased by 1, `ram_mb` decreased by 512. `allocated.disk_gb` unchanged. SQLite: runtime lease has `released_at` set, storage lease still `released_at IS NULL` | P0 | Yes |
| SRV-Q-RES-005 | **Delete** `test-qa-res-001`. SSH query resources + leases | `allocated.cpu_cores`, `ram_mb`, `disk_gb` all return to baseline. SQLite: both leases have `released_at` set | P0 | Yes |
| SRV-Q-RES-006 | **Create** `test-qa-res-002` (1 CPU, 512MB). Wait active. **Stop** it. **Start** it. SSH query leases after each step | After stop: runtime released, storage kept. After start: **new** runtime lease acquired (`released_at IS NULL`). `available` decreased again | P0 | Yes |

### Capacity Gate (007-008)

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-RES-007 | If possible: fill capacity on <canary-host> until `available.cpu_cores` = 0. Try to start a stopped instance. SSH verify | Start fails with clear error message in UI (`.form-error` or alert). Instance stays stopped. No orphaned lease created. `available` unchanged | P0 | Yes |
| SRV-Q-RES-008 | If possible: with capacity full, try to create a new instance via /create | Create fails with clear error message. No phantom resources allocated. SQLite: no active lease for the failed instance | P0 | Yes |

### Infrastructure (009-011)

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-RES-009 | SSH: `sqlite3 DB "SELECT owner_id, lease_kind, cpu_cores, ram_mb FROM resource_leases WHERE owner_type='warm_pool' AND released_at IS NULL"` | Warm pool leases exist. Their CPU/RAM are included in the total `allocated` reported by the resources API | P1 | Yes |
| SRV-Q-RES-010 | SSH: `curl /api/v1/admin/resources` + `curl /api/v1/mobile/resource-options` | Both return consistent available CPU/RAM/disk values | P1 | Yes |
| SRV-Q-RES-011 | SSH: compare `budget.cpu_cores` vs `host.cpu_cores - budget.cpu_reserve` | Budget = host - reserve. No artificial caps below actual host capacity | P1 | Yes |

### Assisted / Edge Cases (012-018)

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-RES-012 | **Assisted**: SSH `sudo systemctl restart soyeht-admin-host`. Wait 10s for startup. SSH query resources + leases | No phantom resources stuck in provisioning. Active lease count matches running instance count. `available` is coherent | P1 | Assisted |
| SRV-Q-RES-013 | Create instance that hits warm pool (check if warm pool has a slot). SSH compare `allocated` before/after | Warm pool slot consumed (warm pool lease released, instance lease acquired). Net `allocated.cpu/ram` unchanged or minimal delta | P1 | Yes |
| SRV-Q-RES-014 | SSH: `curl /api/v1/admin/resources \| python3 -c "import sys,json; r=json.load(sys.stdin); print(r['macos_slots'])"` | `macos_slots.used` >= 0, `macos_slots.total` >= 0, `used` <= `total` | P1 | Yes |
| SRV-Q-RES-015 | Stop `test-qa-res-002`. SSH query resources | `allocated.cpu_cores` decreased, `allocated.ram_mb` decreased, `allocated.disk_gb` unchanged | P0 | Yes |
| SRV-Q-RES-016 | With budget near full: try restart on stopped `test-qa-res-002` | If budget full: fails with clear message, no extra lease consumed. If budget available: succeeds normally | P1 | Yes |
| SRV-Q-RES-017 | Trigger create failure (e.g., specify invalid claw type or name conflict). SSH query leases | No leaked lease. Resources back to pre-create baseline | P0 | Yes |
| SRV-Q-RES-018 | **Assisted**: Create instance, SSH kill the provisioning job before completion. SSH query leases + events | Runtime lease released (or never fully acquired). `provisioning_timeout` or `create_failed` event recorded with `resource_snapshot`. No phantom resource stuck | P1 | Assisted |

## How to Automate

**Baseline recording**: Before any action, SSH `curl /api/v1/admin/resources` and parse JSON. Store `allocated.cpu_cores`, `allocated.ram_mb`, `allocated.disk_gb` as baseline.

**Instance creation**: Chrome navigate to /create, fill form (#claw-type, #cpu-cores=1, #ram-mb=512, #disk-gb=5, #instance-name=test-qa-res-001), click submit. Wait for `.create-result` status to show "active" (poll, timeout 120s).

**Lease verification**: After each action, run SSH SQLite queries from `references/backend-verification.md`. Compare lease states with API response.

**Capacity filling (007-008)**: These tests may SKIP if the canary doesn't have enough instances to fill capacity. Record as SKIP with note "capacity not exhaustible on <canary-host>".

**Assisted tests (012, 018)**: Print explanation, wait for user "sim", execute, verify immediately.

## Cleanup

1. Delete all `test-qa-res-*` instances (UI or API)
2. SSH verify: no active leases for test-qa-res-* owners
3. SSH verify: `allocated` values return to pre-test baseline (within warm pool variance)

```bash
ssh <canary-host> "sqlite3 ~/theyos/.run/theyos.db \"SELECT rl.owner_id, rl.lease_kind FROM resource_leases rl JOIN instances i ON rl.owner_id = i.id WHERE i.name LIKE 'test-qa-res-%' AND rl.released_at IS NULL\""
```
Expected: empty result.

## Out of Scope
- macOS guest VM creation (limited to 2, don't consume slots in QA)
- Warm pool refill timing
- Cross-server capacity isolation
