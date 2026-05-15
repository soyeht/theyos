---
id: health-boot
ids: SRV-Q-HEALTH-001..004
profile: quick
automation: auto
requires_browser: true
requires_ssh: true
target: canary
destructive: false
cleanup_required: false
---

# Health & Boot

## Objective
Verify that the admin panel server is running, the web frontend loads correctly, and no critical errors are present on initial page load.

## Risk
If healthz is down or assets fail to load, every other test will fail. This is the pre-flight gate.

## Preconditions
- canary server running (`ssh <canary-host>` reachable)
- Chrome MCP connected (browser open)

## Test Cases

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-HEALTH-001 | SSH: `curl -s -w '\nHTTP:%{http_code}' localhost:8892/healthz` | HTTP 200, body contains `"platform"` field | P0 | Yes |
| SRV-Q-HEALTH-002 | Chrome: `navigate_page({ url: "$BASE_URL" })` (Tailscale HTTPS URL resolved at preflight) | Page loads: `document.title` is not empty, `document.body.innerHTML.length > 100` | P0 | Yes |
| SRV-Q-HEALTH-003 | Chrome: `list_console_messages()` | Zero messages with severity `"error"` | P0 | Yes |
| SRV-Q-HEALTH-004 | Chrome: `evaluate_script({ expression: "document.querySelectorAll('script[src], link[rel=stylesheet]').length" })` | Result > 0 (at least 1 script and 1 stylesheet loaded) | P1 | Yes |

## How to Automate

1. HEALTH-001: Run SSH curl, parse HTTP status and body
2. HEALTH-002: Navigate via Chrome MCP, evaluate_script to check title and body length
3. HEALTH-003: Call list_console_messages, filter by severity === "error"
4. HEALTH-004: evaluate_script with querySelectorAll count

Screenshot after HEALTH-002 (full page).

## Out of Scope
- Deep endpoint validation (covered by contract mode)
- Backend restart recovery (covered by RES-012)
