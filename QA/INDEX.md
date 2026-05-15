# QA Master Index

Source of truth para QA do theyOS admin panel web. Regra: **arquivo com data = execucao; arquivo sem data = plano**.

**Placeholders nos comandos SSH abaixo:**
- `<prod-host>` — seu servidor de produção (ex: `ssh <prod-host>` → `ssh myprod`)
- `<canary-host>` — seu servidor canary/staging (ex: `ssh <canary-host>` → `ssh mycanary`)
- Substitua pelos hostnames reais do seu deploy (configurados em `~/.ssh/config`).

---

## Release Gate

Para fazer deploy, os seguintes niveis devem estar verdes:

| Nivel | Obrigatorio para | O que roda |
|-------|-------------------|------------|
| `quick` | Qualquer deploy | Preflight + health-boot + auth-session + instance-lifecycle (INST subset) |
| `standard` | Deploy normal | quick + instance-lifecycle (STATE) + resource-capacity + audit-lifecycle |
| `full` | Feature grande | standard + terminal-websocket + workspace-tmux + claw-store-deploy + recovery-multitab + errors-empty-states |

---

## Domain Test Plans (V1)

| Domain | File | IDs | Profile | Automation | Browser | SSH |
|--------|------|-----|---------|------------|---------|-----|
| Health & Boot | [health-boot.md](domains/health-boot.md) | SRV-Q-HEALTH-001..004 | quick | auto | Yes | Yes |
| Auth & Session | [auth-session.md](domains/auth-session.md) | SRV-Q-AUTH-001..005 | quick | auto | Yes | No |
| Instance Lifecycle | [instance-lifecycle.md](domains/instance-lifecycle.md) | SRV-Q-INST-001..006, SRV-Q-STATE-001..004 | quick+standard | auto+assisted | Yes | Yes |
| Resource Capacity | [resource-capacity.md](domains/resource-capacity.md) | SRV-Q-RES-001..018 | standard | auto+assisted | Yes | Yes |
| Audit Lifecycle | [audit-lifecycle.md](domains/audit-lifecycle.md) | SRV-Q-AUD-001..005 | standard | auto | Yes | Yes |

**Total V1: 42 test cases** (15 quick + 27 standard)

### V2 Domains

| Domain | File | IDs | Profile | Automation | Browser | SSH |
|--------|------|-----|---------|------------|---------|-----|
| Terminal & WebSocket | [terminal-websocket.md](domains/terminal-websocket.md) | SRV-Q-TERM-001..008 | standard | auto+assisted | Yes | Yes |
| Workspace & Tmux | [workspace-tmux.md](domains/workspace-tmux.md) | SRV-Q-WORK-001..005, SRV-Q-TMUX-001..004 | standard | auto | Yes | Yes |
| Claw Store & Deploy | [claw-store-deploy.md](domains/claw-store-deploy.md) | SRV-Q-CLAW-001..012 | standard | auto+assisted | Yes | Yes |
| Recovery & Multi-tab | [recovery-multitab.md](domains/recovery-multitab.md) | SRV-Q-WS-001..006 | full | auto+assisted | Yes | Yes |
| Errors & Empty States | [errors-empty-states.md](domains/errors-empty-states.md) | SRV-Q-ERR-001..008 | full | auto+assisted | Yes | Yes |
| Conversation History | [conversation-history.md](domains/conversation-history.md) | SRV-Q-CONV-001..005 | standard | assisted | Yes | Yes |

**Total V2: 44 test cases** (TERM 8 + WORK 5 + TMUX 4 + CLAW 12 + WS 6 + ERR 8 + CONV 5 - 4 overlap with V1 empty states)

**Grand Total (V1 + V2): 90 test cases** (15 quick + 61 standard + 14 full)

---

## Severity Guide

| Severity | Description | Example |
|----------|-------------|---------|
| **P0 - Blocker** | Core flow completely broken, data corruption | Capacity leak, login fails, soft-deleted instance reappears |
| **P1 - Critical** | Major feature broken, no data loss | Events missing snapshots, macos_slots wrong, polling duplicates |
| **P2 - Major** | Feature partially broken | Provisioning status not shown, empty state missing |
| **P3 - Minor** | Cosmetic or edge case | Deprecated endpoint still used in UI |

---

## Regression Risk Map

Areas most likely to break, ordered by risk:

1. Capacity leak — runtime lease not released on stop/fail (P0)
2. Soft delete reappears — deleted instance shows in instance list (P0)
3. desired_state desync — desired_state != observed_state after operation (P0)
4. Create leaks lease — failed create leaves orphaned resource_lease (P0)
5. Auth session lost on refresh — cookie not persisted (P0)
6. Healthz down after deploy — server didn't restart cleanly (P0)
7. Login form broken — selector changed or auth endpoint broken (P0)
8. macos_slots accounting wrong — used > total or negative (P1)
9. Warm pool not counted in capacity — available overreported (P1)
10. instance_events missing resource_snapshot — audit trail incomplete (P1)
11. Console JS errors on page load — asset load failure (P1)
12. Provisioning stuck without timeout — no provisioning_timeout event (P1)
13. Delete confirmation bypassed — instance removed without user confirm (P1)
14. Event ordering wrong — delete_completed before delete_started (P1)
15. Deprecated claw-types used — UI calls /api/v1/claw-types instead of /api/v1/claws (P2)

---

## Quick Smoke Test (8 steps, ~2 min)

1. **SSH healthz** — `curl localhost:8892/healthz` → 200
2. **Page loads** — navigate to root, not blank
3. **Console clean** — zero JS errors
4. **Login** — fill form, submit → redirected to /instances
5. **Instance list** — table has rows or useful empty state
6. **Claw catalog** — navigate /claws, cards appear
7. **Create page** — navigate /create, claw dropdown populated
8. **Resources API** — `curl /api/v1/admin/resources` → available values non-negative

---

## QA Runs (most recent first)

| Date | Focus | Pass/Fail | Report |
|------|-------|-----------|--------|
| 2026-04-13 | Full gate (bef5fed) | 35/1/15/34 BLOCKED | [gate-report.md](runs/2026-04-13/gate-report.md) |

---

## Fixtures & Cleanup

- Test instances use prefix `test-qa-` (e.g., `test-qa-res-001`, `test-qa-lc-001`)
- **NEVER destroy instances without `test-qa-` prefix**
- Cleanup after each run; mandatory for `standard` level
- Destructive suites: target canary only. production is read-only.
- After cleanup, verify via SSH: no active leases for `test-qa-*` instances
