---
id: auth-session
ids: SRV-Q-AUTH-001..005
profile: quick
automation: auto
requires_browser: true
requires_ssh: false
target: canary
destructive: false
cleanup_required: false
---

# Auth & Session

## Objective
Verify web login, session persistence via HttpOnly cookie, logout, and error handling for invalid credentials.

## Risk
If the `soyeht_session` cookie isn't set or persisted correctly, every authenticated page will redirect to login. If error handling is broken, a wrong password can crash the UI.

## Preconditions
- canary server running
- Chrome MCP connected
- `SOYEHT_ADMIN_PASSWORD` env var available (or user provides password)

## Fixtures
- User: `admin`
- Password: from `SOYEHT_ADMIN_PASSWORD` env var

## Test Cases

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-AUTH-001 | Chrome: navigate to `$BASE_URL/login`. `fill({ selector: "#username", value: "admin" })`. `fill({ selector: "#password", value: "$PASSWORD" })`. `click({ selector: "button[type=submit]" })` | URL changes to `/instances`. `evaluate_script("!!document.querySelector('.instances-table')")` returns true | P0 | Yes |
| SRV-Q-AUTH-002 | Chrome: `navigate_page` to current URL (page refresh) | Still on `/instances`. `.instances-table` still present in DOM | P0 | Yes |
| SRV-Q-AUTH-003 | Chrome: `click({ selector: ".logout-btn" })` | URL changes to `/login`. `evaluate_script("!!document.querySelector('#username')")` returns true | P0 | Yes |
| SRV-Q-AUTH-004 | Chrome: `navigate_page({ url: "$BASE_URL/instances" })` (no session) | Redirected to `/login`. URL contains `/login` | P0 | Yes |
| SRV-Q-AUTH-005 | Chrome: navigate to `/login`. Fill username="admin", password="wrong-password-test". Click submit | `.form-error` element visible with non-empty text. URL still contains `/login` | P1 | Yes |

## How to Automate

1. AUTH-001: fill_form or sequential fill + click. Wait 2s for redirect. Check URL and DOM.
2. AUTH-002: navigate_page to same URL. Check DOM unchanged.
3. AUTH-003: click logout button. Wait for redirect. Check URL.
4. AUTH-004: Navigate directly. Check final URL after redirect.
5. AUTH-005: Fill wrong password, click submit. Check .form-error visibility.

Screenshot after AUTH-001 (logged-in state) and AUTH-005 (error state).

## Out of Scope
- Mobile auth / pair token flow (covered by iOS QA)
- Multi-user session isolation
- Token expiration edge cases
