# Follow-up: dev-only IpTunnel client runner for T1-T4 validation

**Severity:** activation-blocker for dev-host T1-T4 validation. This does not
block the draft mount-evidence wiring review, but a real T1-T4 live run cannot
be claimed until the remaining live-runner pieces are resolved and reviewed
under the activation gate checklist.

## Symptom

The server-side T1 mount wiring remains gated by the activation checklist. The
available guest/client CLI still rejects `IpTunnel` before connecting; a
separate dev-only runner boundary now validates member-scoped `IpTunnel` offer
shape offline but deliberately does not connect, open TUN/utun, install routes,
run a packet pump, or touch production.

A PTY or ClawSite smoke proves the existing relay-stream/data-tunnel transport;
it does not prove T1-T4 per-Claw VPN behavior because it does not open a
TUN/utun interface, install a host route, run the packet pump, or exercise
cleanup.

## Reproduction environment

- Dev-host validation only. Production and `/Applications/Soyeht.app` remain
  out of scope.
- Current `friend-cli` package deliberately has no L3 VPN dependency.
- `t1-iptunnel-dev-runner` currently implements only offline
  `validate-offer --offer-file ...` shape validation.
- A relay-stream offer with `resource=IpTunnel` is rejected by the client-side
  resource guard before any relay connection. This is covered for both the
  credential-backed Device dial path and the credential-less Group/Public offer
  dial path, so an `IpTunnel` offer cannot be mistaken for a partial T1 smoke.

## What works vs. what fails

- **Works:** server-side default-off checks, SHA-bound evidence loading helpers,
  audit-sink happy and failure-path tests, and relay-stream PTY/ClawSite client
  smoke tests. The current client also has
  regression coverage proving `IpTunnel` is rejected before TCP connect in both
  supported relay-stream dial paths. The dev runner validates that only
  member-scoped Group `IpTunnel` offers are accepted as future runner input.
- **Fails:** there is not yet a reviewed dev client or runner that can
  authenticate the relay transport, obtain the VPN session parameters, open macOS
  `utun`, install the single claw host route, pump packets, and clean everything
  up.

## Likely causes

1. `friend-cli` intentionally excludes L3 VPN dependencies, so enabling
   `IpTunnel` there is not a one-line resource-guard change.
2. The current dev runner stops at offline offer validation and has no reviewed
   transport, VPN session configuration, interface, route, or packet-pump step.
3. The current data-tunnel open path does not hand the client a reviewed VPN
   session configuration object with the Device-side address/session material
   needed by a packet runner.
4. The low-level TUN/utun, route, packet-pump, and cleanup pieces exist as
   reviewed server-side building blocks, but they are not packaged as a
   dev-client runner.

## What the fix needs

The next safe implementation slices should extend the dev-only runner crate, not
silently repurpose `friend-cli`.

Required properties:

1. Consume a reviewed, member-scoped `IpTunnel` relay-stream offer. **Done for
   offline shape validation only.**
2. Authenticate the existing data tunnel without logging credentials, tokens, or
   local infrastructure values.
3. Obtain or derive a reviewed Device-side VPN session configuration; do not
   infer it from untrusted string fields.
4. Open only a dev-host TUN/utun interface, with explicit stop authority and
   cleanup.
5. Install only a single claw `/32` host route, never a default route, LAN route,
   production route, or wildcard route.
6. Pump packets through the reviewed packet core and reject spoof/control frames.
7. Emit sanitized evidence using neutral aliases and documentation-safe
   addresses only.
8. Add source guards and tests proving `friend-cli` still rejects `IpTunnel`
   unless the reviewed runner is explicitly selected.
9. Keep `/Applications/Soyeht.app` and production untouched; use only disposable
   dev artifacts such as `Soyeht Dev.app`.

## Workaround

There is no valid T1-T4 workaround. Do not substitute PTY, ClawSite, or dry-run
offer validation results for `IpTunnel` evidence. Keep the activation PR in
draft/review state until the dev-only runner can complete the live dev-host
packet path and the owner record, reference-content verification, rollback
artifact, hardware evidence, and review gates are all satisfied.

## Files of interest

- Client reject path: `admin/rust/friend-cli-rs/src/main.rs`
- Client package boundary: `admin/rust/friend-cli-rs/Cargo.toml`
- Dev runner boundary: `admin/rust/t1-iptunnel-dev-runner-rs/src/main.rs`
- Server mount/evidence draft:
  `admin/rust/server-rs/src/claw_share_relay_stream_mount.rs`
- T1 router/audit path: `admin/rust/server-rs/src/claw_vpn_t1_relay_stream_router.rs`
- VPN core/runtime building blocks:
  `admin/rust/household-rs/src/claw_vpn.rs`,
  `admin/rust/server-rs/src/claw_vpn_runtime.rs`,
  `admin/rust/server-rs/src/claw_vpn_interface_route_plan.rs`
- Activation gate checklist:
  `docs/product-a-per-claw-vpn-t1-activation-pr-gate-checklist.md`
