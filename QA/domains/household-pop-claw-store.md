---
id: household-pop-claw-store
ids: HH-CLAW-001..010
profile: assisted-live
automation: assisted live with Rust e2e helper
requires_browser: false
requires_ssh: false
target: canary household endpoint
destructive: true
cleanup_required: true
---

# Household PoP Claw Store Flow

## Objective
Prove the live household Claw Store flow over the household surface:
catalog/list, install, create/status, attach-token and PTY boundary, cleanup,
and a visible guest-image-not-ready case when the target environment can expose
that state.

This domain exercises the household API only. It must not use admin cookies,
mobile Bearer auth, or query-string terminal tokens as a substitute for the
documented household PoP and attach-token boundaries.

## Privacy And Redaction
- Real endpoint URLs, hostnames, IPs, auth headers, PoP headers, attach tokens,
  p_id/hh_id values, host labels, and SSH output must stay out of committed
  docs, reports, and logs.
- Real values live only in ignored local files such as `.env.local` or
  `.env.*.local`, or in an operator-owned local secret store.
- Reports use aliases only, for example `mac-alpha` or `linux-alpha`.
- The e2e helper writes route ids, HTTP status codes, aliases, durations, and
  PASS/FAIL/SKIP/BLOCKED results. It does not write request URLs, credentials,
  tokens, headers, or raw response bodies.

## Local Configuration
Load ignored local values before running the helper:

```sh
set -a
source .env.local
set +a
cargo run -p e2e-rs --manifest-path admin/rust/Cargo.toml -- household-pop
```

Required for a full live pass:
- `THEYOS_HH_BASE_URL`: real household listener URL. Never commit it.
- `THEYOS_HH_TARGET_ALIAS`: public alias for the report, such as `mac-alpha`.
- `THEYOS_HH_POP_SIGNER_CMD`: local command that signs household PoP requests.
  The helper sends the request body on stdin and provides:
  - `THEYOS_HH_SIGN_METHOD`
  - `THEYOS_HH_SIGN_PATH`
  - `THEYOS_HH_SIGN_TARGET_ALIAS`

Optional:
- `THEYOS_HH_TEST_CLAW`: disposable claw name. Default: `picoclaw`.
- `THEYOS_HH_TEST_INSTANCE_NAME`: default is `test-qa-hh-pop-<unix-seconds>`.
- `THEYOS_HH_TEST_GUEST_OS`: `linux` or `macos`. Default: `linux`.
- `THEYOS_HH_EXPECT_GUEST_IMAGE_NOT_READY`: when `true`, the guest-image case is
  required to observe `GUEST_IMAGE_NOT_READY` instead of skipping.
- `THEYOS_HH_ALLOW_UNINSTALL_PREEXISTING`: default `false`. When false, the
  helper never uninstalls a claw that appeared installed before this gate ran.
- `THEYOS_HH_TIMEOUT_SECS`: default `300`.
- `THEYOS_HH_POLL_INTERVAL_SECS`: default `3`.

## Test Cases

| ID | Step | Expected | Severity | Auto |
|----|------|----------|----------|------|
| HH-CLAW-001 | Preflight `/bootstrap/status` | Listener is reachable. Report records only target alias and status. | P0 | Yes |
| HH-CLAW-002 | GET `/api/v1/household/claws` without PoP | `401` with empty body. | P0 | Yes |
| HH-CLAW-003 | Signed catalog and instance list | `GET /api/v1/household/claws` and `GET /api/v1/household/instances` return `200`. | P0 | Yes |
| HH-CLAW-004 | Guest-image-not-ready visibility | If observable, macOS create returns `409` with code `GUEST_IMAGE_NOT_READY`. If the environment is Linux, already ready, or not prepared for this state, SKIP with reason unless `THEYOS_HH_EXPECT_GUEST_IMAGE_NOT_READY=true`. | P1 | Assisted |
| HH-CLAW-005 | Install selected test claw | Install request is accepted or the claw is already ready. Polling observes an installed/creatable state. | P0 | Yes |
| HH-CLAW-006 | Create instance and poll status | Household create returns `202`; status polling reaches `active`. | P0 | Yes |
| HH-CLAW-007 | Attach-token query boundary | A minted attach token sent as `?token=` without the attach-token header gets `401`, then the same token still works with the header. | P0 | Yes |
| HH-CLAW-008 | Household PTY round trip | Header-authenticated PTY WebSocket echoes a generated marker. Marker text must not contain local identifiers. | P0 | Yes |
| HH-CLAW-009 | Cleanup | Test instance is deleted. The test claw is uninstalled only if this gate installed it, unless explicit local env allows preexisting uninstall. | P0 | Yes |
| HH-CLAW-010 | Final audit | No `test-qa-hh-pop-*` resources from this run remain visible through household list/status. | P1 | Yes |

## PASS/FAIL/SKIP/BLOCKED
- PASS: expected status/shape was observed.
- FAIL: target returned the wrong status/shape, cleanup failed, or a required
  case could not prove its boundary.
- SKIP: the environment cannot safely expose an optional state, for example
  guest-image-not-ready on a target that is already ready.
- BLOCKED: required local configuration is missing, for example no
  `THEYOS_HH_POP_SIGNER_CMD`.

Missing signer is BLOCKED, not PASS. Guest-image-not-ready may be SKIP with a
reason unless `THEYOS_HH_EXPECT_GUEST_IMAGE_NOT_READY=true`.

## Report
Default report path:

```text
QA/runs/YYYY-MM-DD-household-pop-claw-store/gate-report.md
```

The report should include:
- Date, target alias, platform/status summary, and git commit.
- A table with `HH-CLAW-*`, route/action, expected, observed, result, and a
  sanitized note.
- Cleanup status and explicit leftovers if any are visible by alias-safe route
  checks.

Do not commit screenshots, raw terminal transcripts, raw API bodies, URLs,
headers, tokens, hostnames, IPs, p_id/hh_id, host labels, or SSH output.

## Validation
CI can run the no-secret guards and unit tests:

```sh
cargo test -p server-rs --test claw_store_wire_contract --manifest-path admin/rust/Cargo.toml
cargo test -p server-rs --test household_pop_gate_completeness --manifest-path admin/rust/Cargo.toml
cargo test -p server-rs --test household_contract_cross_check --manifest-path admin/rust/Cargo.toml
cargo test -p server-rs --test admin_guest_image_gate_guard --manifest-path admin/rust/Cargo.toml
cargo test -p e2e-rs --test phase2_pop_auth --manifest-path admin/rust/Cargo.toml
cargo test -p e2e-rs --manifest-path admin/rust/Cargo.toml household_pop
```

The assisted-live pass additionally requires ignored local configuration and a
safe household canary target.

## Cleanup
1. Delete the created `test-qa-hh-pop-*` instance through the household delete
   route.
2. Uninstall the selected claw only if this gate installed it, unless explicit
   local env allowed uninstalling a preexisting claw.
3. Re-run signed household instance list and claw availability checks.
4. Record cleanup PASS/FAIL/SKIP with sanitized notes.

## Out Of Scope
- TLS or rustls changes.
- Runtime auth model changes.
- Contract JSON changes.
- Admin cookie or mobile Bearer fallback for household routes.
- Publishing local endpoint values or private infrastructure identifiers.
