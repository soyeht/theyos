---
id: workspace-tmux
ids: SRV-Q-WORK-001..005, SRV-Q-TMUX-001..004
profile: standard
automation: auto
requires_browser: true
requires_ssh: true
target: canary
destructive: true
cleanup_required: true
---

# Workspace & Tmux

## Objective
Verify workspace CRUD (create, rename, delete), workspace list consistency, and tmux window/pane operations via the web UI.

## Risk
- Workspace create fails silently → user stuck with no sessions
- Delete doesn't kill tmux sessions → resource leak in VM
- Rename returns 204 but UI doesn't update → stale display
- Phantom workspaces after delete → confusing workspace picker

## Preconditions
- At least one active instance on <canary-host>
- Chrome MCP connected, logged in, on /terminals page
- Container selected with terminal connected

## Fixtures
- Workspaces: `test-qa-ws-001`, `test-qa-ws-renamed`
- Prefix: `test-qa-ws-*`

## Test Cases — Workspace CRUD

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-WORK-001 | Chrome: click `[data-testid="new-session-btn"]`. Fill `[data-testid="new-session-name-input"]` with "test-qa-ws-001". Click `[data-testid="create-session-confirm"]` | New workspace appears in session picker with display name "test-qa-ws-001". Status dot is active (green) | P1 | Yes |
| SRV-Q-WORK-002 | Chrome: click `[data-testid="rename-{id}"]` on the created workspace. Fill `[data-testid="session-rename-input"]` with "test-qa-ws-renamed". Press Enter | Display name updates to "test-qa-ws-renamed" in picker. No page reload needed | P1 | Yes |
| SRV-Q-WORK-003 | Chrome: click `[data-testid="delete-{id}"]` on "test-qa-ws-renamed". Confirm with `[data-testid="confirm-delete-yes"]` | Workspace disappears from picker. No phantom entry. SSH: `tmux list-sessions` on <canary-host> doesn't show the deleted session | P1 | Yes |
| SRV-Q-WORK-004 | Chrome: count workspace items in `[data-testid="session-picker"]` before and after CRUD operations | Counts match: +1 after create, same after rename, -1 after delete. No duplicates at any point | P1 | Yes |
| SRV-Q-WORK-005 | Chrome: if 8+ workspaces exist, check for warning | `[data-testid="session-warning"]` visible with text containing "sessions" and a number. If <8 workspaces, SKIP | P2 | Yes |

## Test Cases — Tmux Operations

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-TMUX-001 | SSH: `curl -s localhost:8892/api/v1/terminals/{container}/tmux/windows?session={session_id}` | Response has `data` array with at least 1 window. Each window has `index`, `name`, `active`, `panes` fields | P1 | Yes |
| SRV-Q-TMUX-002 | SSH: `curl -s localhost:8892/api/v1/terminals/{container}/tmux/panes?session={session_id}&window=0` | Response has `data` array with at least 1 pane. Each pane has `index`, `pane_id`, `command`, `active`, `width`, `height` | P1 | Yes |
| SRV-Q-TMUX-003 | SSH: `curl -X POST localhost:8892/api/v1/terminals/{container}/tmux/new-window -H "Content-Type: application/json" -d '{"session":"{session_id}"}'`. Then query windows again | Window count increased by 1. New window appears in list | P1 | Yes |
| SRV-Q-TMUX-004 | SSH: `curl -X DELETE localhost:8892/api/v1/terminals/{container}/tmux/window/1?session={session_id}`. Then query windows again | Window removed from list. Window count decreased by 1 | P1 | Yes |

## How to Automate

**WORK-001**: Navigate to /terminals, select container, open session picker via `button.toolbar-workspace-switcher`. Click new session button. Fill name input. Confirm. Wait for picker to update.

**WORK-002**: Find the workspace item by data-testid. Click rename button. Clear input, type new name. Press Enter (via `press_key`). Verify display_name text changed.

**WORK-003**: Click delete button. Wait for confirmation dialog (`[data-testid="confirm-delete"]`). Click yes. Wait for item to disappear.

**TMUX tests**: All via SSH curl (no Chrome needed). These validate the API directly. Auth cookie needed — get from login response or use session header.

## Cleanup

Delete any `test-qa-ws-*` workspaces via the UI or API:
```bash
# List remaining test workspaces
ssh <canary-host> "curl -s localhost:8892/api/v1/terminals/{container}/workspaces | grep -o 'test-qa-ws-[^\"]*'"
# Delete each by ID
ssh <canary-host> "curl -s -X DELETE localhost:8892/api/v1/terminals/{container}/workspaces/{id}"
```

## Out of Scope
- Keyboard shortcuts for tmux (split, zoom, cycle layouts)
- Tmux capture-pane / scrollback
- Multi-container workspace isolation
