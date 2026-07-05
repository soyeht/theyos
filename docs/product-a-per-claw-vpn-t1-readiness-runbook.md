# Product A per-Claw VPN T1 readiness runbook

This runbook is the pre-activation gate for the first live per-Claw VPN
wiring slice. It does not authorize activation by itself and it does not add a
product caller, flag, TUN/utun open path, relay dial, route install, or runtime
bootstrap. It makes the two remaining non-code gates explicit:

- owner authorization plus a rollback plan;
- hardware validation evidence for T1-T4 on dev hosts.

Use `docs/product-a-per-claw-vpn-t1-authorization-template.md` as the
copy/paste artifact for the authorization record, rollback readiness, hardware
evidence pack, and stop record. The template is not authorization by itself; it
only becomes evidence when filled for the exact artifact SHA by the owner and
reviewed with the hardware pack.

The code gates that must already be present in `main` are:

- source guard hardening for packet-pump/runtime spans
  (`#223`, merge `05281bd`);
- redacted `TunnelFrame` Debug output (`#224`, merge `12dca33`);
- e2e-rs source-guard coverage (`#225`, merge `695ed1b`);
- concrete Linux TUN and macOS utun packet-interface adapters
  (`#226`, merge `afb28e40`);
- bounded production packet-pump driver (`#227`, merge `65494922`).

If any of those code gates are absent or drifted, stop before using this
runbook.

## Boundary

- Dev hosts only. Production engines, production state, and the installed
  shipping app are out of scope.
- Neutral aliases only in public notes, PR bodies, commits, screenshots, logs,
  fixtures, and review messages: `Engine-dev`, `Claw-A`, `Device-D`,
  `Relay-R`, `Member-M`, and documentation-safe example addresses.
- Real hostnames, machine names, account names, LAN IPs, tailnet IPs, relay
  endpoints, secrets, tokens, private keys, APNs keys, notary keys, and local
  device identifiers must stay in ignored local files or the operator's secret
  store.
- A reviewer ACK is not owner authorization. A relayed GO is not owner
  authorization. The owner authorization record must be explicit and must name
  the exact artifact being authorized.
- This runbook cannot be used against production. Any production activation is
  a separate owner decision after the dev-host T1-T4 evidence is reviewed.

## Required Authorization Record

Before any wiring PR is marked ready for activation testing, the owner must
provide a durable authorization record in the review thread or PR. The record
must include all fields below, using neutral aliases in public text:

| field | required value |
|---|---|
| Artifact | Exact PR number and commit SHA to test |
| Scope | `dev-host T1-T4 only`; production explicitly excluded |
| Topology | Neutral aliases for engine, claw, device, relay, and member |
| Time window | Start and end time for the test window |
| Operator | Person responsible for starting, stopping, and rolling back |
| Rollback artifact | Prebuilt rollback artifact identifier and location |
| Data policy | Confirmation that logs and screenshots will be redacted |
| Stop authority | Confirmation that any reviewer or operator can stop the run |
| Owner sentence | `I authorize dev-host per-Claw VPN T1-T4 validation for <artifact>; I do not authorize production activation.` |

If the authorization omits any field, the test is not authorized. If the
artifact SHA changes, the authorization expires and must be reissued for the
new SHA.

The startup preflight status is only a classifier for these gates. A
`PreflightEvidencePresent` status means the caller supplied evidence for review;
it is not owner authorization by itself and it does not run the T1 datapath.
The startup classifier is target-side only: client-side `Dial` mode must report
an unsupported mode instead of `PreflightEvidencePresent`, even when all
preflight booleans are true.

## Rollback Plan

Rollback must be prepared before the first live run. It is not acceptable to
depend on compiling or designing rollback after a failed activation.

Required prebuilt material:

- previous known-good dev engine artifact or package;
- exact command or service operation the operator will use to restore that
  artifact on the dev host;
- saved dev-service environment snapshot with secrets removed or redacted;
- route cleanup procedure for Linux and macOS host-route entries;
- interface cleanup procedure for Linux TUN and macOS utun;
- relay/process stop procedure for the dev relay client/server components;
- verification checklist showing the interface is gone, host routes are gone,
  and the dev engine health check is back to baseline.

Rollback success criteria:

- no per-Claw VPN TUN/utun interface remains;
- no Claw-A `/32` host route remains through a tunnel interface;
- relay dial/session tasks are stopped;
- dev engine health returns to the pre-run baseline;
- no production process, service, state directory, or installed shipping app was
  touched.

If rollback leaves an interface, route, session, or unhealthy dev engine, stop
the run and record the failure as a blocker. Do not retry activation in the same
window.

## Hardware Evidence Pack

Each T1-T4 run must produce an evidence pack that can be reviewed without
exposing personal infrastructure. Store raw local details only in ignored local
files or the operator's private notes. Public evidence uses neutral aliases and
documentation-safe addresses.

Required metadata:

| field | required value |
|---|---|
| Artifact | PR number, commit SHA, build artifact hash |
| Host OS | Linux or macOS, plus kernel/OS major version without hostnames |
| Role | Engine-dev, Claw-A, Device-D, or Relay-R |
| Clock | Test start/end in UTC |
| Operator | Neutral operator label |
| Authorization | Link or reference to the owner authorization record |
| Rollback | Link or reference to the prebuilt rollback artifact |

Evidence rows:

| ID | evidence required |
|---|---|
| T1 interface up | Before/during/after interface snapshot proving TUN/utun creation, assigned documentation-safe addresses, and clean removal on exit |
| T2 tunnel plumbing | ICMP and TCP echo success from Device-D to Claw-A over Relay-R, with neutral endpoint labels only |
| T3 route scope | Before/during/after route snapshots proving only Claw-A `/32` uses the tunnel; LAN, engine, and other-claw routes do not |
| T4 fail-closed plumbing | Relay-R interruption followed by tunnel shutdown, route cleanup, no half-open interface, and dev engine health restored or rollback executed |

Evidence must include negative observations, not only successful packet output:

- no default route through the tunnel;
- no route to the claw host LAN through the tunnel;
- no route to another claw through the tunnel;
- no route to the engine address through the tunnel;
- no raw `TunnelFrame` payload bytes in logs;
- no real hostnames, account names, device names, LAN IPs, tailnet IPs, relay
  endpoints, secrets, or local file paths in public evidence.

## Stop Conditions

Stop immediately and rollback if any of the following occurs:

- production app, production engine, production state, or production relay is
  touched;
- a real identifier or secret appears in a public log, screenshot, PR comment,
  or review message;
- the tunnel installs a default route;
- any route broader than Claw-A `/32` goes through the tunnel;
- another claw, LAN peer, or engine address becomes reachable through the
  tunnel;
- cleanup fails to remove the interface or host route;
- packet pump reports an I/O error and cleanup does not complete;
- rollback cannot be executed from the prebuilt artifact;
- owner authorization is missing, stale, or no longer matches the artifact SHA.

After a stop condition, do not continue the run by patching live state. Capture
the sanitized evidence, restore the dev baseline, and open a follow-up or new
slice.

## Wiring Review Checklist

The wiring PR that follows this runbook must show, before merge:

- the source guard change that intentionally permits the new caller;
- the caller remains default-off and dev-profile scoped until explicit
  activation;
- the caller constructs the route plan, route executor, packet interface,
  relay, fixed-session pump, bounded production driver, and runtime coordinator
  from the same authenticated session;
- Linux and macOS platform checks remain explicit;
- route setup and cleanup keep the executor's `env_clear` and null-stdio
  behavior;
- packet interface reads preserve the MTU/oversize fail-closed behavior;
- the concrete relay stream/socket has an explicit read/idle timeout before it
  is handed to the relay adapter, so a peer cannot keep a partial frame open
  indefinitely;
- the production driver uses a finite `max_steps`, finite elapsed budget, and
  finite per-window quota, so the live caller also bounds byte-trickle peers
  that make progress just below the per-read timeout;
- if the target-session router adapter is used, its launcher is the reviewed
  execution boundary: the router may return a `TargetSession` only after that
  launcher accepts the synchronous wiring, and the live caller must still prove
  where and how the launcher runs it;
- if the T1 caller gate is used, disabled config, invalid config, missing owner
  authorization, missing rollback, and missing hardware evidence must all return
  before any caller-owned handles are built, and the gate must use an
  exhaustive mode check that rejects client-side `Dial` mode before constructing
  any caller; downstream code may consume a ready caller through `into_ready()`
  but must not be able to fabricate or restamp a ready status directly because
  the ready payload and gate-owned seal stay encapsulated; the live caller must
  run the gate fresh for the exact artifact/test window and consume the ready
  payload immediately, never treating a stored ready payload or seal as a
  durable authorization token after owner authorization, rollback, hardware
  evidence, or config state changes; if the gate returns a target-session router
  factory, the factory must be minted only after those same gates pass and
  calling it must not call `build_runtime`, execute the launcher, or open a
  target session; the post-gate builder that supplies `build_runtime`/launcher
  closure parts must be lazy and must not capture concrete device, route, or
  relay handles opened before the blockers; gate statuses and entrypoints must
  stay `#[must_use]` so warning-deny builds catch accidental bare-call discards,
  while any intentional discard such as an underscore binding remains a review
  item at the future caller site;
- the `IpTunnel` relay-stream offer path must stay member-scoped: Device/Public
  audiences must fail before the `IpTunnel` backend, no public/anonymous VPN
  offer may be accepted, and the live caller must derive the VPN ACL key from
  the authenticated Group member identity rather than from caller-controlled
  target metadata; the backend must implement the target-aware
  `RelayStreamIpTunnelRouter` seam instead of a string-only target router that
  can ignore group/member/device context;
- if the relay-stream mount injects the T1 `IpTunnel` backend, the reviewed
  mount path must still pass through the T1 caller gate and must remain
  unavailable with `PerClawVpnT1PreflightEvidence::missing`; no TUN/utun open,
  route install, runtime input build, launcher spawn, `run_until_stopped`, or
  packet pump execution may occur until a later evidence loader and live-run
  record are reviewed for the exact artifact SHA;
- the T1 `IpTunnel` backend must not drop the typed session-open audit event:
  it must hand the `open_with_audit` event to a reviewed audit sink, and sink
  failure must fail closed before runtime inputs are built, the launcher runs,
  or a target session is returned; if that reject path closes the in-memory
  session, the rollback `SessionClose` event must also be routed through the
  sink on a best-effort basis. The T1 router module may provide reviewed audit
  sink helpers that force owner-only log-file permissions, walk parent
  components with fd-relative `openat`/`mkdirat`, reject parent/intermediate
  symlinks and `..` components, open the log file relative to the validated
  parent fd with `O_NOFOLLOW`, create or require a real, current-user-owned,
  mode `0700` final parent directory, flush plus `sync_data` each accepted
  event from the worker, rotate before a new record would exceed the reviewed
  byte cap, retain a bounded number of rotated files, and sync the parent
  directory after rotation metadata changes. The T1 router module may also
  provide a reviewed HMAC-SHA-256 export redactor for off-host/shared audit
  export that emits keyed subject hashes instead of local pseudonymous hashes.
  It may also provide a reviewed fixed audit-log path selector that accepts
  only an absolute, canonical, current-user-owned, mode `0700` root directory
  and appends the fixed `claw-vpn-t1-audit/audit.jsonl` suffix.
  The current default-off mount may keep a placeholder sink only while missing
  preflight makes it unreachable, and a live activation slice must replace it
  with reviewed persistence policy and safe path selection for the exact
  artifact SHA, including the source of the owner-controlled canonical root,
  final
  retention/rotation limits, reviewed export key source/rotation, and the
  chosen best-effort-vs-durable authorization/in-flight semantics;
- no raw `TunnelFrame`, packet bytes, interface name, file descriptor, local
  path, or peer address is logged through Debug or error formatting;
- tests prove route cleanup runs after pump stop/error and that failure returns
  an error, not success.

The wiring PR may land as reviewed, default-off code. It still does not
authorize a live run unless the owner authorization and hardware evidence gates
above are satisfied for the exact artifact SHA.
