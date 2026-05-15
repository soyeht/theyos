---
id: conversation-history
ids: SRV-Q-CONV-001..005
profile: standard
automation: assisted
requires_browser: true
requires_ssh: true
target: canary
destructive: false
cleanup_required: false
---

# Conversation History Persistence

## Objective
Verify that conversation history (both the DB row and the on-disk log file) survives backend restarts, that deleting a conversation via the UI unlinks the log file, and that the per-conversation size cap (`THEYOS_CONV_LOG_MAX_BYTES`) closes the session cleanly when hit.

## Risk
- History is lost on backend restart → users lose scrollback across deploys (regression from persistence goal)
- Deleted conversation leaves log file on disk → disk fills silently
- Missing size cap enforcement → unbounded log growth can fill disk
- Manual file deletion crashes the backend → fragile persistence layer

## Preconditions
- Admin login to <canary-host> UI in Chrome
- SSH access to <canary-host> (`ssh <canary-host>`)
- At least one active instance on <canary-host> where terminals can be opened
- Backend running under systemd as `soyeht-admin-host`

## Test Cases

| ID | Step | Expected | Severity |
|----|------|----------|----------|
| SRV-Q-CONV-001 | Chrome: open `/terminals`, create a new conversation, type `echo persistent-history-check` + Enter, wait for output to appear. SSH: `sudo systemctl restart soyeht-admin-host`. Wait 5s. Chrome: reload `/terminals`, reopen the same conversation. | Replay shows the previous command **and its output** (`persistent-history-check`). A fresh prompt appears below, indicating the shell has been restarted as expected. No missing bytes between replay and live. | P0 |
| SRV-Q-CONV-002 | Chrome: create a conversation, run a short command (~50 bytes of output). SSH: `ls ~/theyos/.run/conversations/` — note the `.log` filename. Chrome: delete the conversation via the UI. SSH: rerun `ls ~/theyos/.run/conversations/`. | After delete, the corresponding `.log` file is absent. Other conversation logs (if any) remain untouched. | P0 |
| SRV-Q-CONV-003 | SSH: `sudo systemctl stop soyeht-admin-host`. Create a systemd drop-in setting `Environment=THEYOS_CONV_LOG_MAX_BYTES=1024`, then `sudo systemctl daemon-reload && sudo systemctl start soyeht-admin-host`. Chrome: create a new conversation and run `yes | head -c 4000; echo done`. | Session receives a `CTL:log_full` marker and closes before `done` appears. Backend log shows `WARN ... conversation log full, closing session` tagged with the `conv_id`. After removing the override and restarting, normal short output no longer triggers the marker. | P1 |
| SRV-Q-CONV-004 | Chrome: create 3 conversations with distinct user-given names (e.g. `conv-a`, `conv-b`, `conv-c`). SSH: `sudo systemctl restart soyeht-admin-host`. Wait 5s. Chrome: reload `/terminals`. | All 3 conversations appear in the sidebar list with the same names. Selecting each one replays the prior output. | P0 |
| SRV-Q-CONV-005 | SSH: `ls ~/theyos/.run/conversations/` — pick one existing `.log` file. With the backend running, `rm` that file manually. Chrome: open the corresponding conversation. | Backend does not crash; `systemctl status soyeht-admin-host` reports active. The UI opens the conversation (empty replay, immediate `CTL:replay_done`), spawns a fresh PTY, and the user can type and receive output normally. | P2 |

## How to Automate
These cases require restarting `soyeht-admin-host` and editing systemd drop-ins, which are best done by a human over SSH. Automation would need remote-exec credentials and systemd unit manipulation rights — out of scope for the current Chrome-MCP based automation.

- **CONV-001 / CONV-004**: could be partially automated if a test harness with SSH credentials were available — the Chrome portion (create, type, reload, verify replay text) is scriptable, but the `systemctl restart` step is not.
- **CONV-002**: the delete + file-disappears check is a straightforward SSH `ls` pair; easy if an exec channel exists.
- **CONV-003**: requires systemd drop-in editing and a sacrificial `yes | head -c N` command — assisted only.
- **CONV-005**: requires `rm` on a server file with the backend running — assisted only.

## Out of Scope
- Orphan cleanup: logs on disk without a DB row (or vice versa). The current design tolerates orphans (CONV-005 proves no crash); no automatic sweep is implemented.
- Behavior on **production** (production). This PR is validated on **canary** only; <prod-host> promotion is a separate decision.
- Concurrent multi-tab behavior when a log fills while two clients are subscribed. Covered implicitly by the `recovery-multitab.md` domain once expanded for v2.
- Cap-hit UI affordance ("delete to continue" hint). Backend emits the marker; UI response is tracked separately.
