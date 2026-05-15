---
id: recovery-multitab
ids: SRV-Q-WS-001..006
profile: full
automation: auto (001-002), assisted (003-006)
requires_browser: true
requires_ssh: true
target: canary
destructive: false
cleanup_required: false
---

# Recovery & Multi-tab

## Objective
Verify WebSocket reconnection after page reload, multi-tab commander/mirror behavior, connection loss recovery, and terminal resize after reconnect.

## Risk
- Reconnect loop floods server with WebSocket connections
- Multi-tab creates ping-pong commander handoff (historical regression)
- Resize after reconnect sends wrong dimensions → garbled output
- Mirror mode auto-reconnects when it shouldn't

## Preconditions
- At least one active instance on <canary-host> with terminal connected
- Chrome MCP connected, logged in, on /terminals page
- For multi-tab tests: ability to open second browser tab

## Test Cases

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| SRV-Q-WS-001 | Chrome: on connected terminal, `navigate_page` to same URL (page reload). Wait 5s | Terminal reconnects. `conn-status` transitions: disconnected → reconnecting → connected. Terminal content visible (tmux session preserved) | P1 | Yes |
| SRV-Q-WS-002 | Chrome: after reconnect, `type_text` a command (`echo reconnect-ok`). Check output | Command executes correctly. Output shows "reconnect-ok". No garbled characters | P1 | Yes |
| SRV-Q-WS-003 | **Assisted**: Open same terminal in 2 tabs (Chrome `new_page`). Tab 1 = commander, Tab 2 = mirror. Wait 10s | Stable state: Tab 1 stays `conn-connected`, Tab 2 stays `conn-mirror`. No flip-flop. `evaluate_script` confirms status in both tabs | P0 | Assisted |
| SRV-Q-WS-004 | **Assisted**: SSH `sudo systemctl restart soyeht-admin-host` on <canary-host>. Wait 15s. Check Chrome terminal | Terminal shows `conn-disconnected` or `conn-reconnecting`. After server restarts, terminal eventually reconnects (may take up to 30s). No infinite reconnect loop (check `list_console_messages` for flood) | P1 | Assisted |
| SRV-Q-WS-005 | **Assisted**: After reconnect from WS-004, `type_text` a command | Command executes. Tmux session was preserved across server restart | P1 | Assisted |
| SRV-Q-WS-006 | Chrome: after reconnect, `resize_page({ width: 1200, height: 800 })`. Then `resize_page({ width: 1920, height: 1080 })`. Check terminal dimensions | Terminal re-renders at new size. SSH: `tmux display -t {session} -p '#{window_width}x#{window_height}'` shows updated dimensions. No garbled output | P2 | Assisted |

## How to Automate

**WS-001/002**: Simply reload the page via `navigate_page` to current URL. Wait for `conn-connected` class. Type command and verify output.

**WS-003**: Use `new_page({ url })` to open second tab. Use `select_page` to switch between tabs. Check `conn-status` class in each via `evaluate_script`. Wait 10s and re-check to confirm stability.

**WS-004/005**: User confirms before `ssh <canary-host> "sudo systemctl restart soyeht-admin-host"`. Wait 15s. Check Chrome terminal status. After reconnect, type command.

**WS-006**: Use `resize_page` to change viewport. Wait 2s. Check terminal dimensions via SSH tmux query.

## Out of Scope
- Mobile app reconnection (iOS QA)
- WiFi toggle simulation (not automatable via Chrome MCP)
- Cross-device handoff (iOS ↔ web) — requires physical device
