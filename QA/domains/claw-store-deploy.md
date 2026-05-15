---
id: claw-store-deploy
ids: SRV-Q-CLAW-001..012
profile: standard
automation: auto (001-009), assisted (010-012)
requires_browser: true
requires_ssh: true
target: canary
destructive: true
cleanup_required: true
---

# Claw Store & Deploy

## Objective
Verify claw catalog display, install/uninstall lifecycle, create/deploy flow with provisioning polling, and error handling for unavailable or failed claws.

## Risk
- Install shows no progress → user thinks it's frozen
- Uninstall leaves orphaned files → disk waste
- Create with failed claw → broken instance
- Polling doesn't stop → performance drain
- "Not available yet" missing → user tries to install non-buildable claw

## Preconditions
- Chrome MCP connected, logged in
- SSH to <canary-host>
- At least one claw in "ready" status on <canary-host>

## Fixtures
- Instances: `test-qa-deploy-001`
- Prefix: `test-qa-deploy-*`
- Claw install/uninstall: may modify claw state (restore in cleanup)

## Test Cases — Claw Catalog

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-CLAW-001 | Chrome: navigate `/claws`. Wait for `.network-grid` to have children | Cards render. Each `.network-card` has: name in `strong`, `.claw-lang-badge` with text, `.network-status-dot` | P1 | Yes |
| SRV-Q-CLAW-002 | Chrome: count cards. SSH: `curl localhost:8892/api/v1/claws` count data array | Card count matches API claw count | P1 | Yes |
| SRV-Q-CLAW-003 | Chrome: find a card with status "ready" (`.network-status-dot` green, text "ready") | Card shows: version, size (MB/GB), min RAM, license, installed date. Button says "uninstall" | P1 | Yes |
| SRV-Q-CLAW-004 | Chrome: find a card with status "not_installed" | Card shows: description, no installed date. If buildable: button says "install". If not buildable: text "not available yet", no button | P1 | Yes |
| SRV-Q-CLAW-005 | Chrome: check for failed claw card (if any). SSH: `curl /api/v1/claws` filter status=failed | If exists: error message visible (red text), button says "retry install". If none: SKIP | P2 | Yes |

## Test Cases — Install / Uninstall

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-CLAW-006 | Chrome: click "install" on a not_installed claw. Watch card for 15s | Button disabled, shows "installing...". Status dot changes to amber. `.provider-save-btn` header shows updated count. Polling every 3s (card updates). Eventually reaches "ready" or "failed" | P1 | Yes |
| SRV-Q-CLAW-007 | Chrome: click "uninstall" on a ready claw. Watch card for 15s | Button disabled, shows "uninstalling...". Eventually reaches "not_installed". SSH: verify claw files removed | P1 | Yes |

## Test Cases — Deploy (Create Instance)

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-CLAW-008 | Chrome: navigate `/create`. Check `#claw-type` dropdown | Only claws with status "ready" appear as options. If no claws ready: `.muted` message with link to /claws | P0 | Yes |
| SRV-Q-CLAW-009 | Chrome: check resource availability hints | `.resources-fieldset` shows available CPU/RAM/disk numbers. These match `GET /api/v1/admin/resources` available values | P1 | Yes |
| SRV-Q-CLAW-010 | Chrome: fill form — select claw, CPU=1, RAM=512, name="test-qa-deploy-001". Submit | `.create-result` appears. Status shows "provisioning" with spinner. Polling every 2s. Eventually reaches "active" | P0 | Yes |
| SRV-Q-CLAW-011 | Chrome: during provisioning, check `.status-line` text updates | Job messages update in real-time (not stuck on "Waiting to start..."). `.job-info` shows job ID | P1 | Yes |
| SRV-Q-CLAW-012 | **Assisted**: Trigger create failure (invalid config or name conflict). Check error display | `.form-error` shows error message (ANSI codes stripped). No phantom instance created. Resources unchanged (SSH verify) | P1 | Assisted |

## How to Automate

**CLAW-001..005**: Navigate to /claws. Use `evaluate_script` to count cards, read status dots, check button text.

**CLAW-006**: Click install button. Poll via `evaluate_script` every 3s checking card status text. Timeout 120s.

**CLAW-007**: Click uninstall button. Same polling approach. SSH verify: `ssh <canary-host> "ls ~/theyos/claws/data/{claw_name}/ 2>/dev/null"`.

**CLAW-008..011**: Navigate to /create. Fill form via `fill` (select elements) and `fill` (text input). Click submit. Poll `.create-result .status-line` text every 2s.

**CLAW-012**: Fill form with duplicate name or nonexistent claw. Submit. Check `.form-error` visibility and text.

## Cleanup

1. Delete `test-qa-deploy-*` instances
2. If a claw was uninstalled for testing (CLAW-007), re-install it
3. SSH verify: no active leases for test instances, claw states restored

## Out of Scope
- Guest OS selection (macOS vs Linux) — canary is Linux-only
- AI coding tools checkbox behavior
- Maintenance mode blocking deploy (covered by errors-empty-states.md)
