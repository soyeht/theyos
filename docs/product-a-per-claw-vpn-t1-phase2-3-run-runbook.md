# Product A per-Claw VPN T1 — Phase 2/3 dev-host run runbook

Concrete, owner-present run guide for the dev-host T1 `IpTunnel` datapath: the
exact commands, environment, and acknowledgements for the Phase-2 run, the
T1–T4 observation-capture checklist, and the Phase-3 evidence → #281 record
assembly. It is dev-profile only.

**Read [`product-a-per-claw-vpn-t1-readiness-runbook.md`](product-a-per-claw-vpn-t1-readiness-runbook.md)
first.** That runbook is the policy: the owner authorization record, the
prebuilt rollback plan, the hardware evidence-pack shape, the boundary, and the
stop conditions. This document is the executable procedure that produces that
evidence. It does not restate the policy; it references it.

## What is automated vs. gated

Everything buildable/testable is done and green off-host (Items A/B/C/E). The
**only** steps this runbook cannot perform autonomously — they require an
owner present at the dev host and are host mutations — are:

- **Phase 2 Step 3 (`--execute`)**: opens a real TUN/utun, installs a route,
  and runs the packet pump. A human runs this at the dev host.
- **Phase 4 (owner signature)**: the owner authorization record is signed with
  the owner's PersonCert key. Never done autonomously.

An agent may build the bins, run the **dry-run** (Step 2), and validate/assemble
the record shape (Phase 3 tooling) — none of those touch a host.

## Hard stops (unchanged from the readiness runbook)

1. **Dev profile only.** The dev app, the dev-suffixed engine bundle, the dev
   engine on loopback port `8101`, and the loopback relay `127.0.0.1:49152`.
   **Never** the production engine port, the production app bundle, the
   production mac bundle id, or the production household. The orchestration
   script's fail-closed `prod_guard` refuses any production indicator in env or
   args before it launches anything. (Neutral aliases only in public evidence,
   per the readiness runbook Boundary; the exact dev bundle ids live in the
   repo's dev-profile definition, not in public docs.)
2. **No fabricated evidence.** The evidence pack and the #281 refs come only
   from the real run and the owner. The tooling prepares shape, never truth.
3. **Prod mount stays `PerClawVpnT1PreflightEvidence::missing`.** This dev-host
   run never mounts the T1 backend into the production engine.

## Dev-profile pins (copy exactly)

| Pin | Value |
|---|---|
| Dev-host ack | `dev-host T1-T4 only; no production activation` |
| Public-relay ack (only if the relay endpoint is non-loopback) | `dev-host public relay dial allowed; no production activation` |
| Required env | `THEYOS_T1_DEV_DATAPATH=1` and `THEYOS_FORCE_SOFTWARE_KEYS=1` |
| Loopback relay endpoint | `127.0.0.1:49152` |
| IPv4 pool (doc range, RFC 2544) | `198.18.0.0/24` (device `.1`, claw `.2` for session index 0) |
| Claw route prefix | `/32` (host route only) |

## Phase 2 — the run

The orchestration script `scripts/run-t1-dev-datapath.sh` (Item C) is the driver.
It wires the four dev bins so both ends meet at the same rendezvous slot:

1. `relay_stream_relay_dev` — loopback blind splicer on `127.0.0.1:49152`.
2. `t1_iptunnel_claw_dev` — reverse-connects to the relay and **self-mints** the
   member-scoped `IpTunnel` offer (writes the offer file), then serves the
   claw-side datapath.
3. `t1-iptunnel-dev-runner gen-device-config` — derives the Device session
   config from the real `ClawVpnIpv4Pool` allocation (Item B).
4. `t1-iptunnel-dev-runner run-device-datapath` — opens the real Device datapath
   against the **same** offer the claw wrote.

### Step 0 — build the dev bins (no host mutation)

```sh
cd admin/rust
cargo build --features dev_t1_datapath \
  -p server-rs --bin t1_iptunnel_claw_dev --bin relay_stream_relay_dev
cargo build --features dev_t1_datapath -p t1-iptunnel-dev-runner-rs
```

Point the script at the built binaries with `--bin-dir` (defaults documented in
the script header).

### Step 1 — generate the Device session config (no host mutation)

```sh
target/debug/t1-iptunnel-dev-runner gen-device-config \
  --platform "$(uname | tr '[:upper:]' '[:lower:]' | sed 's/darwin/macos/')" \
  --pool-network 198.18.0.0/24 \
  --out /path/to/private/device-session.json
```

The generator re-runs the runner's own validator on its output before writing;
the private address values are never printed. Keep the file private (it is a
`device_session_config_ref` for the #281 record).

### Step 2 — dry-run the plan (SAFE default, no host mutation)

```sh
scripts/run-t1-dev-datapath.sh --dry-run \
  --claw-id <claw-id> --guest-device-pub <64-hex> \
  --device-secret-file /path/to/private/device-secret.hex \
  --config-file /path/to/private/device-session.json
```

The dry-run prints the exact relay/claw/gen/runner commands with their dev acks
and dev envs and exits `0` **without launching or mutating anything** (no offer
or config files are written). Review the printed plan against the pins above.

### Step 3 — the real run (GATED: owner-present, host mutation)

> A human runs this at the dev host. It opens a real TUN/utun, installs the
> claw `/32` route, and runs the packet pump. Confirm the dry-run plan first.

```sh
export THEYOS_T1_DEV_DATAPATH=1
export THEYOS_FORCE_SOFTWARE_KEYS=1
scripts/run-t1-dev-datapath.sh --execute \
  --claw-id <claw-id> --guest-device-pub <64-hex> \
  --device-secret-file /path/to/private/device-secret.hex \
  --config-file /path/to/private/device-session.json
```

`--execute` is refused (non-zero) unless both envs and the exact dev-host ack are
present, and the `prod_guard` passes. For an off-loopback dev relay (e.g. a
Tailscale-transport checkpoint), also pass the public-relay ack; otherwise keep
the loopback endpoint.

## T1–T4 observation checklist (what to capture)

Capture the evidence rows from the readiness runbook's Hardware Evidence Pack.
Use neutral aliases (Device-D, Claw-A, Relay-R, Engine-dev) and
documentation-safe addresses only. Capture **negative** observations too.

| ID | Capture (dev-profile only) |
|---|---|
| **T1 interface up** | `ifconfig <utunN>` (macOS) / `ip addr show <clawvpnN>` (linux) **before / during / after** — proves interface creation, the doc-safe `198.18.0.x` pair, and clean removal on exit. |
| **T2 tunnel plumbing** | From Device-D over the tunnel to Claw-A (`198.18.0.2`): one ICMP echo **and** one TCP echo success, labelled with neutral endpoints only. |
| **T3 route scope** | `netstat -rn` (macOS) / `ip route` (linux) **before / during / after** — prove ONLY the Claw-A `/32` uses the tunnel. Explicit negatives: no default route, no claw-LAN route, no other-claw route, no engine-address route through the tunnel. |
| **T4 fail-closed** | Interrupt Relay-R, then capture: tunnel shutdown, route cleanup, no half-open interface, and dev engine health restored (or the prebuilt rollback executed). |

**Authoritative evidence, not the optimistic startup line.** The device runner
prints a startup line `OK: dev IpTunnel datapath started (... runner_route_installed=true ...)`.
That line reports the *plan* at datapath start — `runner_route_installed=true` is
printed before the asynchronous route install is confirmed. **Do not** use it as
route evidence. The authoritative route/interface evidence is the T1/T3 system
snapshots above; the authoritative pump/teardown evidence is the runtime's final
report (forwarded/dropped counts, stop reason) captured from the run's own
output/logs. Treat the startup booleans only as a "datapath started" marker.

**No value echo.** Public evidence must not contain real hostnames, account or
device names, LAN/tailnet IPs, relay endpoints, secrets, local file paths, or
raw `TunnelFrame` payload bytes. Store raw local details only in ignored local
files or private operator notes; the five refs are private files referenced by
path, never inlined.

## Phase 3 — evidence → #281 record (no host mutation)

1. Assemble the hardware evidence pack markdown (readiness-runbook shape) from
   the T1–T4 captures, then validate it against the exact build artifact SHA:

   ```sh
   scripts/validate-t1-hardware-evidence-pack.py <40-hex-artifact-sha> \
     /path/to/private/hardware-evidence-pack.md
   ```

2. Assemble the SHA-bound #281 preflight record in one shot (Item E). It
   delegates to the existing prepare/validate logic, runs the full
   `--check-private-refs` chain, and fails closed if any of the five refs is
   missing or empty. It fabricates nothing and echoes no ref content, secret,
   private IPv4, or path:

   ```sh
   scripts/assemble-t1-preflight-record.py \
     --artifact-sha <40-hex-artifact-sha> \
     --owner-ref /path/to/private/owner-authorization.txt \
     --rollback-ref /path/to/private/rollback-artifact.txt \
     --hardware-ref /path/to/private/hardware-evidence-pack.md \
     --audit-export-policy-ref /path/to/private/audit-export-policy.txt \
     --device-session-config-ref /path/to/private/device-session.json \
     --out /path/to/private/t1-preflight-record.json
   ```

   The five refs: `owner_authorization_ref`, `rollback_ref`,
   `hardware_evidence_ref`, `audit_export_policy_ref`,
   `device_session_config_ref`. `production_activation` is always `false`.

## Phase 4 — owner authorization signature (never autonomous)

The owner authorization record — owner sentence `I authorize dev-host per-Claw
VPN T1-T4 validation for <artifact>; I do not authorize production activation.`
— is signed with the owner's PersonCert key by the owner. This is a separate
owner decision made **after** the T1–T4 evidence is reviewed. It is not part of
any automated flow.

## Stop conditions

Halt and surface (do not improvise) if any of these hold: a production indicator
appears in env/args; the relay endpoint is non-loopback without the public-relay
ack; the dry-run plan does not match the pins; an interface, route, or pump does
not tear down cleanly on Relay-R interruption; or any of the five refs is
missing when assembling the record. See the readiness runbook's Stop Conditions
for the full list.
