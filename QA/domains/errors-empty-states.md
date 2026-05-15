---
id: errors-empty-states
ids: SRV-Q-ERR-001..008
profile: full
automation: auto (001-006), assisted (007-008)
requires_browser: true
requires_ssh: true
target: canary
destructive: false
cleanup_required: false
---

# Errors & Empty States

## Objective
Verify that error responses, empty states, and maintenance mode are handled gracefully across all pages — no blank screens, no unhandled JS exceptions, clear user feedback.

## Risk
- 404 for deleted instance → blank page or crash
- Maintenance mode active → creates fail silently without explanation
- Empty instance list → infinite spinner
- Network error → no feedback, user thinks app is frozen

## Preconditions
- Chrome MCP connected, logged in
- SSH to <canary-host>

## Test Cases

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-ERR-001 | Chrome: navigate to `/instances` (invalid hash or after deleting all test instances) with zero instances | No infinite spinner. `.instances-table` shows "no instances found" row or similar empty state. No JS console errors | P1 | Yes |
| SRV-Q-ERR-002 | Chrome: navigate to `/claws` when all claws are not_installed | Cards render with "not available yet" or "install" buttons. No blank grid. Header counter shows "0/N installed" | P1 | Yes |
| SRV-Q-ERR-003 | Chrome: navigate to `/create` when no claws are in "ready" status | `.muted` message visible: "no claws installed" with link to `/claws`. Form fields disabled. No submit possible | P1 | Yes |
| SRV-Q-ERR-004 | Chrome: navigate to `/logs`. Check loading and empty state | If no logs: page shows count "0 entries" (not infinite "loading..."). If logs exist: entries render with level badges (`.level-info`, `.level-warn`, `.level-error`) | P2 | Yes |
| SRV-Q-ERR-005 | Chrome: navigate to `/network`. Check channel cards | At least "local" channel card appears. Cards show status dots. If Caddy not running: `.network-caddy` shows appropriate message. No JS errors | P2 | Yes |
| SRV-Q-ERR-006 | Chrome: `list_console_messages` after visiting all pages (/instances, /claws, /create, /logs, /terminals, /network) in sequence | Zero messages with severity "error". Warnings acceptable but no errors | P1 | Yes |
| SRV-Q-ERR-007 | **Assisted**: SSH enter maintenance mode (if mechanism available). Chrome: navigate to `/instances` | `.maintenance-banner` visible with `role="alert"`. Banner shows reason/state text. `.maintenance-banner-retry` shows countdown if `retry_after_secs > 0`. Attempting to create instance shows 503-related error | P1 | Assisted |
| SRV-Q-ERR-008 | **Assisted**: SSH exit maintenance mode. Chrome: refresh page | `.maintenance-banner` disappears within 15s (polling interval). Instance list loads normally | P1 | Assisted |

## How to Automate

**ERR-001**: Navigate to /instances. `evaluate_script("document.querySelector('.instances-table')?.textContent?.includes('no instances') || document.querySelectorAll('.instance-id-col').length === 0")`. Check for spinner absence.

**ERR-002**: Navigate to /claws. Count cards with install buttons vs "not available yet" text. Verify header counter format.

**ERR-003**: Navigate to /create. Check for `.muted` text containing "no claws installed". Verify `#claw-type` has no options or is empty.

**ERR-004**: Navigate to /logs. Wait 5s (one poll cycle). Check `.logs-head` counter text.

**ERR-005**: Navigate to /network. Wait for `.network-grid` children. Check `.network-caddy` text.

**ERR-006**: Navigate to each page in sequence. After all, call `list_console_messages()` and filter severity "error".

**ERR-007/008**: Requires SSH mechanism to toggle maintenance mode. If `soyeht` CLI has a maintenance command, use it. Otherwise SKIP.

## Out of Scope
- Backend 500 error injection (would need to crash a specific handler)
- Rate limiting / 429 responses
- Token expiration mid-session
