# Follow-up: dev-only IpTunnel client runner for T1-T4 validation

**Severity:** activation-blocker for dev-host T1-T4 validation. This does not
block the draft mount-evidence wiring review, but a real T1-T4 live run cannot
be claimed until the remaining live-runner pieces are resolved and reviewed
under the activation gate checklist.

## Symptom

The server-side T1 mount wiring remains gated by the activation checklist. The
available guest/client CLI still rejects `IpTunnel` before connecting; a
separate dev-only runner boundary validates member-scoped `IpTunnel` offer
shape offline and has an explicit dev-host `open-session` step for the
relay/data-tunnel session-open seam. That session-open step now validates the
server `TunnelAck` metadata shape and reports only redacted/presence status; it
still does not treat the placeholder mesh address as VPN routing config. The
runner still deliberately does not implement the local TUN/utun, route install,
packet pump, or production-app control path. A target open against an activated
dev host remains a gated T1-T4 validation step, not a production activation
path.

A PTY or ClawSite smoke proves the existing relay-stream/data-tunnel transport;
it does not prove T1-T4 per-Claw VPN behavior because it does not open a
TUN/utun interface, install a host route, run the packet pump, or exercise
cleanup.

## Reproduction environment

- Dev-host validation only. Production and `/Applications/Soyeht.app` remain
  out of scope.
- Current `friend-cli` package deliberately has no L3 VPN dependency.
- `t1-iptunnel-dev-runner` implements offline `validate-offer --offer-file ...`
  shape validation plus explicit `open-session` auth/open validation. The
  session-open command requires an exact dev-host/no-production acknowledgement
  and a private device-secret file; it validates the returned session ack and
  prints only booleans plus non-sensitive MTU. It may ask an activated dev host
  to open the reviewed `IpTunnel` target, so it must stay under the dev-host
  activation gate even though the runner itself has no local interface/route/
  packet-pump implementation.
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
  member-scoped Group `IpTunnel` offers are accepted as future runner input and
  can explicitly authenticate/open the `IpTunnel` data-tunnel session while
  validating the ack metadata without printing the raw session id or mesh
  placeholder.
- **Fails:** there is not yet a reviewed dev client or runner that can obtain
  the VPN session parameters, open macOS `utun`, install the single claw host
  route, pump packets, and clean everything up on the client side. The current
  ack metadata is a relay/data-tunnel session-open proof, not the final
  Device-side VPN route/interface configuration.

## Likely causes

1. `friend-cli` intentionally excludes L3 VPN dependencies, so enabling
   `IpTunnel` there is not a one-line resource-guard change.
2. The current dev runner stops at data-tunnel session-open and has only
   redacted ack-metadata validation, not a reviewed VPN session configuration,
   interface, route, or packet-pump step.
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
   offline shape validation and explicit session-open only.**
2. Authenticate the existing data tunnel without logging credentials, tokens, or
   local infrastructure values. **Done for explicit session-open only.**
3. Obtain or derive a reviewed Device-side VPN session configuration; do not
   infer it from untrusted string fields. **Not done. Current runner validates
   only the authenticated session ack metadata and does not route on it.**
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
