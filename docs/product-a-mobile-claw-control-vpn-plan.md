# Product A — mobile Claw control over per-Claw VPN

Status: planning document for the next Product A slice after the dev-host T1
activation/E2E proof. The already validated T1 artifact proves the per-Claw VPN
datapath on a dev host; this document scopes the product work needed for a
Soyeht iPhone client to control Mac and Linux Claws without relying on Tailscale
as the product datapath.

This plan is not an activation record and does not authorize production by
itself. Every public example uses neutral aliases only. Real hostnames, device
names, account names, LAN/tailnet addresses, relay endpoints, any real IP
outside documentation ranges, paths, secrets, and raw run logs must remain in
ignored private files or operator-only stores.

Aliases used here:

- `Device-D`: a Soyeht iPhone dev device.
- `App-M`: the Soyeht macOS app/engine coordinating user-visible state.
- `Claw-M`: a Mac Claw target.
- `Claw-L`: a Linux Claw target or VM.
- `Relay-R`: the community rendezvous relay.
- `Mesh-C`: the mesh/control-plane state used for discovery, authorization,
  offers, and revocation.

## Goal

Ship a Soyeht-owned, per-Claw VPN path where `Device-D` can select and control
`Claw-M` or `Claw-L` through Soyeht, with:

- no Tailscale dependency in the product datapath;
- a blind, untrusted community relay used only for rendezvous/splice;
- mesh/control-plane authorization before any tunnel becomes usable;
- per-Claw route scope, not a default/full-tunnel VPN;
- Mac and Linux Claw support;
- real E2E validation from iPhone dev hardware.

## Target architecture

```text
Device-D (Soyeht iPhone)
  -> Mesh-C discovery/authorization
  -> Relay-R blind rendezvous/splice (Device-D and Claw-* both dial outbound)
  -> Claw-M or Claw-L per-Claw VPN responder (no inbound listener required)
  -> Soyeht control channel for the selected Claw
```

Responsibilities:

- `Device-D`: mobile controller, NetworkExtension packet tunnel client, and
  user-facing connect/disconnect state.
- `App-M`: coordinates Claw inventory, offers, user-visible session state, and
  audit/status surfaces. It must not become a datapath proxy, Linux admin
  workaround, or secret-printing proxy.
- `Claw-M` / `Claw-L`: VPN responder plus Soyeht control target. Each Claw owns
  its tunnel interface, route scope, packet policy, teardown, and audit events.
- `Relay-R`: blind pairing/splice only. It is not trusted for security or
  authorization and must not need plaintext.
- `Mesh-C`: discovery, owner/member/device authorization, offer lifecycle,
  revocation, and stale-session prevention.

## Product invariants

- Tailscale may be used for developer administration only; it is not part of
  the shipped VPN datapath. E2E evidence must prove the product route/tunnel was
  used rather than LAN, tailnet, or another fallback path.
- v1 is one selected Claw per active iPhone tunnel. Authorization may be N:N,
  but each active route scope is per selected Claw.
- The iPhone installs only the selected Claw route, preferably `/32` for the
  Claw tunnel address. It must not install a default route by default.
- The Claw responder is not a LAN router. It accepts only the session peer to
  the selected Claw address and drops everything else fail-closed.
- All offers and records are SHA/session bound where applicable. Stale offers,
  stale records, stale refs, and revoked ACL entries fail closed.
- Public logs, docs, PRs, screenshots, and agent messages must contain only
  aliases and documentation-safe addresses. Real `Relay-R` endpoints must be
  treated as private operator values and shown publicly only as aliases.
- Raw E2E captures must live as mode `0600` files inside private ignored
  directories with mode `0700`.

## Already proven baseline

The dev-host Product A T1 arc has already proven the core per-Claw VPN datapath:

- T1 interface up.
- T2 sustained forwarding.
- T3 route scope constrained to the selected Claw route.
- T4 teardown/rollback clean.
- SHA-bound private gate validates the activation artifact and fails closed on
  mismatched build SHA.
- Pollable pump runs on both device and Claw responder sides.

This plan must not reopen that proof as a substitute for mobile product work.
Instead, it should reuse the validated datapath and extend it to the iPhone,
mesh, relay, Mac coordinator, and Linux/Mac Claw targets.

## Work phases

### Phase 1 — product model and state machine

Define the concrete user/product model:

- Claw identity model for Mac and Linux Claws.
- iPhone device identity and enrollment state.
- Per-Claw authorization state.
- Offer lifecycle: create, publish, consume, expire, revoke.
- Session lifecycle: unavailable, available, connecting, connected, degraded,
  disconnecting, disconnected, failed, revoked.
- User-visible macOS/iOS status fields.

Deliverables:

- Product state-machine document.
- Threat model update for `Device-D -> Relay-R -> Claw-*`.
- Explicit list of states that must fail closed.

### Phase 2 — Mesh-C discovery and authorization

Implement/control:

- Claw registration and availability.
- Device-to-Claw ACL entries.
- Owner/member authorization for iPhone access to each Claw.
- Explicit per-Claw VPN capability, separate from existing PTY/share
  capabilities.
- Offer minting for `IpTunnel` sessions.
- Offer TTL, single-use/replay protection, and revocation.
- Status surface for active sessions and denied attempts.

Exit criteria:

- `Device-D` can request access to `Claw-M` or `Claw-L`.
- Unauthorized or revoked device cannot obtain a usable offer.
- Expired/stale offer cannot connect.
- All denial output is generic and no-value-echo.
- Agents may implement validators, dry-runs, fixtures, and mocked tests
  autonomously, but must not grant real owner/member ACL access, mark a real
  enrollment authorized, or call an owner authorization complete without owner
  input.

### Phase 3 — Relay-R community rendezvous

Prepare the community relay path for product E2E:

- Stable dev endpoint for `Relay-R`.
- Blind splice only; no plaintext, no authorization authority.
- Explicit rendezvous sequence: `Mesh-C` authorizes/mints an offer; `Device-D`
  and the selected `Claw-*` both dial outbound to `Relay-R`; `Relay-R` pairs the
  slot and splices bytes without authenticating the product session, initiating
  any inbound connection, or seeing plaintext.
- Abuse limits: pending slots, source caps, TTL, splice caps, idle timeout.
- Health check and operator status.
- Redacted logs only.

Exit criteria:

- `Device-D` outside the Claw LAN can rendezvous with `Claw-M` and `Claw-L`.
- No inbound listener on `Claw-*` is required for rendezvous.
- Relay failure produces a clear user error and cleans up local tunnel state.
- Relay compromise does not grant access without valid session auth.

### Phase 4 — Claw responder for Mac and Linux

Productize the responder side for both target classes:

- Mac Claw responder using `utun`.
- Linux Claw responder using `tun`.
- Pollable pump for both sides.
- Route apply/cleanup with bounded rollback.
- Interface/route/process cleanup on all exits.
- Drop non-IPv4 and out-of-policy packets without killing valid sessions.
- Audit events for open, denied, revoked, closed, and teardown result.

Exit criteria:

- `Claw-M` responder can run and tear down cleanly.
- `Claw-L` responder can run and tear down cleanly.
- Policy rejects traffic not bound to the selected session pair.
- Teardown leaves no tunnel route, interface, or responder process.

### Phase 5 — Soyeht macOS coordinator

Implement the macOS app/engine product layer:

- List Claws and their VPN availability.
- Mint or fetch per-Claw offers.
- Show iPhone connection state per Claw.
- Start/stop responder where appropriate.
- Treat `Claw-L` as its own responder agent/daemon: it registers availability
  through `Mesh-C` and serves offers itself. `App-M` coordinates user-visible
  state and owner actions; it must not become an implicit SSH/Tailscale control
  path or an ad hoc Linux administration proxy.
- Show audit/status without leaking real identifiers.
- Handle sleep/wake and reconnect-visible state.
- Keep production and dev profiles separate.

Exit criteria:

- macOS can prepare a session for `Device-D -> Claw-M`.
- macOS can prepare a session for `Device-D -> Claw-L`.
- UI/status reflects connect, disconnect, error, and revoked states.
- Starting a responder is gated by profile checks plus an explicit user action
  or an approved background policy. Missing, denied, or stale gates must fail
  before opening TUN/utun, installing routes, spawning responder processes, or
  marking the Claw connectable.

### Phase 6 — iPhone Packet Tunnel client

Implement the iOS side:

- `NetworkExtension` Packet Tunnel provider.
- Mobile datapath adapter from `NEPacketTunnelFlow` to the validated per-Claw
  VPN core. This must be designed explicitly because `NEPacketTunnelFlow` is not
  an fd/pollable interface: decide Rust core through FFI versus Swift-native
  wrapper, define packet atomicity, backpressure, cancellation, teardown, and
  partial-frame behavior, and test the adapter before real mobile E2E.
- Keychain storage for device/session material.
- Claw selection UI.
- Offer verification and relay dial.
- Route configuration for the selected Claw only.
- MTU configuration.
- Connect/disconnect/reconnect handling.
- User-visible status and redacted errors.

Exit criteria:

- `Device-D` connects to a selected Claw through `Relay-R`.
- The mobile datapath adapter preserves packet boundaries, handles backpressure
  without over-counting delivery, cancels cleanly, and cannot corrupt a partial
  stream frame on suspend/reconnect.
- Default route is not captured.
- Only the selected Claw route is installed.
- Disconnect removes the route and packet tunnel.
- Ordering is fail-closed: verify offer, session binding, ACL, revocation
  status, and selected-Claw identity before route install and before reporting
  `connected`. Invalid, stale, revoked, or mismatched input must prevent route
  installation, tear down any partial tunnel state, and report only a redacted
  error.

### Phase 7 — Soyeht control over the VPN

Wire the actual control plane over the tunnel:

- Soyeht command/control channel reaches the selected Claw over an in-tunnel
  endpoint bound to the selected Claw route. The concrete protocol/port/service
  must be documented before E2E and must be scoped by the active session ACL.
- Terminal/control APIs work for `Claw-M`.
- Terminal/control APIs work for `Claw-L`.
- Control failure is distinct from tunnel failure in user-facing state.
- There is no fallback to Tailscale, LAN, or relay data channels when the
  tunnel is down.
- No command payload or secret material enters public logs.

Exit criteria:

- `Device-D` can control a Mac Claw without Tailscale.
- `Device-D` can control a Linux Claw without Tailscale.
- Control survives normal packet loss/retry within documented bounds.
- Tunnel up plus control service down reports a degraded/control-failed state,
  not a tunnel success. Tunnel down plus control request must fail without
  falling back to any non-product datapath.

### Phase 8 — E2E matrix

Run real E2E with private raw capture and public redacted summaries:

- `Device-D -> Claw-M` on the same LAN.
- `Device-D -> Claw-L` on the same LAN.
- `Device-D -> Claw-L` in a remote network.
- `Device-D -> Claw-*` over `Relay-R` from outside the LAN.
- Cellular or otherwise non-shared-network run where Tailscale is not installed,
  not running, or not selected as a route on `Device-D`.
- Relay offline.
- Claw offline.
- Offer expired.
- Revocation during active session.
- Reconnect after network change.
- iOS background/foreground.
- iOS screen lock/unlock.
- Soyeht app kill/reopen while the Packet Tunnel remains active.
- Wi-Fi -> cellular and cellular -> Wi-Fi.
- Claw responder restart while iOS tunnel is active.
- Relay idle timeout while iOS app is suspended.
- Selected `Claw-M` cannot reach `Claw-L`, a LAN peer, or engine/admin
  endpoint through the tunnel.
- Selected `Claw-L` cannot reach `Claw-M`, a LAN peer, or engine/admin endpoint
  through the tunnel.
- Device authorized for one Claw is denied for an unselected/unauthorized Claw.
- Tunnel up with control service down.
- Control authorization revoked while the tunnel is up.
- Teardown after normal disconnect and after forced failure.

Each passing E2E must prove:

- T1: tunnel interface up.
- T2: sustained forwarding with a numeric threshold: at minimum 60 seconds of
  traffic with `>=98%` ICMP delivery or an equivalent `N/N` packet count,
  plus TCP echo or real Soyeht control payload success. Pump counters may
  corroborate delivery, but they do not replace end-to-end delivery evidence.
- T3: selected-Claw route scope only; default route unchanged.
- T4: teardown/rollback clean.
- Soyeht control channel works over the tunnel.
- The route table has exactly the selected Claw route for the tunnel scope; no
  default route, LAN route, tailnet route, unselected Claw route, or engine/admin
  route is installed through the tunnel.
- Attempts to reach unselected Claws, LAN peers, and engine/admin endpoints are
  denied or dropped without session reuse.
- Tailscale is absent, disabled, or demonstrably unused for the product
  datapath: public summaries should show only aliases and product tunnel/relay
  evidence, never tailnet addresses or routes.
- Relay failure and control-service failure produce distinct public summaries.
- Command denial and control auth errors do not log command payloads.
- iOS lifecycle cases leave no stale route, stale interface, stale session, or
  misleading connected state.
- Public summary has no real hostnames, paths, secrets, LAN/tailnet IPs, relay
  endpoints, real non-documentation IPs, or device identifiers.

### Phase 9 — reviews and release gates

Required lenses before product release:

- Code/build correctness.
- Fail-closed gates and ordering.
- Test/evidence fidelity.
- Architecture/datapath/boundary.
- Privacy/no-value-echo.

Blocking findings include:

- Full-tunnel/default-route capture without explicit product decision.
- Relay treated as trusted authorization.
- Stale offer/session/record accepted.
- Secret, path, hostname, LAN/tailnet IP, relay endpoint, real
  non-documentation IP, or device identifier in public output.
- Teardown leaves interface/route/process behind.
- iPhone can reach anything beyond the selected Claw scope.
- Claw responder forwards to LAN or another Claw.

### Phase 10 — rollout

Rollout sequence:

1. Local dev profile.
2. Internal iPhone dev devices.
3. Mac dev app.
4. Remote Linux Claw dev target.
5. TestFlight/internal dogfood.
6. Controlled production rollout.

Production release requires:

- signed/reviewed release record for the effective build SHA;
- green CI and release validation;
- rollback plan;
- private evidence pack;
- owner approval for production activation;
- no open blocking findings.
- production evidence and owner approval must be newly bound to the effective
  production build SHA and production policy. Dev-host T1 records, dev private
  evidence, and `production_activation=false` records cannot authorize
  production.

## Owner and infrastructure unlocks

These are the only expected human/infra unlocks. Everything else should proceed
as implementation/review work without ceremony.

Can proceed automatically:

- Documentation, architecture drafts, local code, and test implementation.
- Unit tests, mocked/no-host integration tests, dry-run scripts, and private
  validators.
- Redacted evidence formatting, local static scans, and PR preparation.
- Review-response edits that do not grant real access, mutate a host, publish
  private evidence, or activate production.

Requires Caio or owner/infra action:

- Provide or confirm the disposable dev relay endpoint for `Relay-R` as a
  private operator value. Public docs and evidence should use only the `Relay-R`
  alias.
- Ensure a dev-accessible Linux Claw target is online when remote E2E starts.
- Ensure Mac Claw and iPhone dev devices are available when mobile E2E starts.
- Approve real `Device-D` / `Claw-*` enrollment and real ACL grants.
- Confirm any owner/member authorization record for real device-to-Claw access.
- Grant temporary owner-present sudo or scoped NOPASSWD only when a run needs
  TUN/utun/route mutation on a dev host.
- Confirm iOS NetworkExtension entitlement status before Phase 6 implementation
  becomes release-bound.
- Approve publication of evidence outside the private store.
- Confirm production rollout only after all dev/TestFlight gates are complete.

Agents must not request passwords in chat and must not print secrets. If an
unlock is needed, ask for the exact minimal owner action, then continue
automatically after it is done.

## Current blocker inventory

No code blocker is known at the time this plan is created. The remaining
blockers are productization and environment gates:

- iOS Packet Tunnel entitlement and implementation.
- Mesh/offer/session product wiring for mobile Claw selection.
- Mac and Linux responder productization.
- Community relay dev/prod readiness.
- Real iPhone-to-Claw E2E across the matrix above.
- Release/rollout decision after reviews.

## Definition of done

Product A mobile Claw VPN is complete when:

- `Device-D` can select and connect to `Claw-M` without Tailscale as datapath.
- `Device-D` can select and connect to `Claw-L` without Tailscale as datapath.
- Soyeht control commands work over the tunnel for both Claw classes.
- Relay-R is blind and untrusted.
- Mesh-C authorizes and revokes sessions correctly.
- Route scope is per selected Claw, not default route.
- T1/T2/T3/T4 pass in the real E2E matrix.
- Public evidence is redacted and private raw capture is stored as `0600` files
  under `0700` private directories.
- All five review lenses are clean.
- Rollback is documented and tested.
