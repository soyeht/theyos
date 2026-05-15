---
id: terminal-websocket
ids: SRV-Q-TERM-001..008
profile: standard
automation: auto (001-006), assisted (007-008)
requires_browser: true
requires_ssh: true
target: canary
destructive: false
cleanup_required: false
---

# Terminal & WebSocket

## Objective
Verify terminal connection via WebSocket, command execution, display name rendering, reconnect behavior, commander/mirror mode, and font size controls.

## Risk
- WebSocket fails to connect → core feature broken
- Commander/mirror ping-pong between tabs → session corruption
- Reconnect loop floods the server
- Font size changes not applied → accessibility issue

## Preconditions
- At least one active instance on <canary-host> (non-`test-qa-*`)
- Chrome MCP connected, logged in
- SSH to <canary-host> for backend verification

## Test Cases

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-TERM-001 | Chrome: navigate `/terminals`. Select a container from the dropdown (`select` in `.terminal-toolbar`). Wait 5s | `.terminal-view` element exists. `conn-status` class is `conn-connected`. Terminal content visible (not blank placeholder) | P0 | Yes |
| SRV-Q-TERM-002 | Chrome: `type_text` into terminal: `echo qa-test-ok` + Enter. Wait 2s. `evaluate_script` to read xterm buffer | Terminal output contains "qa-test-ok". No garbled characters | P0 | Yes |
| SRV-Q-TERM-003 | Chrome: check workspace display name in `.session-display-name` or `.terminal-label` | Name shown is human-readable (not raw 16-char hex UUID). Either user-given name or "session {first8chars}" | P1 | Yes |
| SRV-Q-TERM-004 | Chrome: click `.toolbar-reconnect` button. Wait 3s | Connection drops briefly (`conn-reconnecting`), then reconnects (`conn-connected`). Terminal content preserved (tmux session persists) | P1 | Yes |
| SRV-Q-TERM-005 | Chrome: click font increase button (`button[title="Increase font size"]`). Check terminal font | Font size increases. `evaluate_script("document.querySelector('.terminal-view .xterm-viewport')?.style.fontSize")` changes or xterm options updated | P2 | Yes |
| SRV-Q-TERM-006 | Chrome: click font decrease button (`button[title="Decrease font size"]`) | Font size decreases. Visible change in terminal rendering | P2 | Yes |
| SRV-Q-TERM-007 | **Assisted**: Open same terminal in 2nd tab via `new_page`. Select same container + workspace. Check both tabs | Tab 1: `conn-connected` (commander). Tab 2: `conn-mirror` with `.commander-placeholder` visible. "Take command" button present in tab 2 | P0 | Assisted |
| SRV-Q-TERM-008 | **Assisted**: In tab 2, click "Take command" in `.commander-placeholder`. Check both tabs | Tab 2 becomes `conn-connected` (commander). Tab 1 switches to `conn-mirror` or `conn-disconnected`. No ping-pong loop (wait 10s, verify stable) | P0 | Assisted |

## How to Automate

**TERM-001**: Navigate to /terminals, select container from dropdown via `evaluate_script("document.querySelector('.terminal-toolbar select').value = '{container}'; document.querySelector('.terminal-toolbar select').dispatchEvent(new Event('change'))")`. Wait for `.terminal-view` to appear.

**TERM-002**: After connecting, use `type_text` to send `echo qa-test-ok\n`. Wait 2s. Read xterm buffer via `evaluate_script` accessing the terminal DOM.

**TERM-003**: Read `.session-display-name` text content or `.terminal-label` text. Verify it doesn't match `/^[0-9a-f]{16}$/` pattern.

**TERM-004**: Click reconnect button. Watch `conn-status` class transition: connected → reconnecting → connected.

**TERM-005/006**: Click font buttons, screenshot before and after.

**TERM-007/008**: Use `new_page` to open second tab. Navigate to same terminal. Check `conn-status` classes in both tabs via `select_page` + `evaluate_script`.

## Out of Scope
- Keyboard shortcuts (Ctrl+\ for split, etc.) — hard to test via Chrome MCP
- Tmux operations (covered by workspace-tmux.md)
- WebSocket reconnect after network loss (covered by recovery-multitab.md)
