# Product A mobile Claw VPN state machine

Status: Phase 1 execution artifact for
`product-a-mobile-claw-control-vpn-plan.md`. This document defines the product
state model that later code, tests, dry-runs, and E2E evidence must implement.
It does not authorize production, publish private evidence, grant real access,
or mutate any host by itself.

Public examples use only neutral aliases:

- `Device-D`: Soyeht iPhone client.
- `Claw-M`: Mac Claw target.
- `Claw-L`: Linux Claw target.
- `Relay-R`: blind community rendezvous relay.
- `Mesh-C`: mesh/control-plane authorization state.

Real relay endpoints, hostnames, device identifiers, addresses, paths, and raw
captures remain private operator values.

## Actors

- `Device-D` owns the mobile connect/disconnect UI and Packet Tunnel state.
- `Mesh-C` owns discovery, ACLs, offer minting, offer revocation, and session
  visibility.
- `Relay-R` only pairs two outbound rendezvous dials and splices bytes. It does
  not grant access, inspect plaintext, or initiate inbound connections.
- `Claw-M` and `Claw-L` own responder availability, tunnel interface lifecycle,
  route scope, packet policy, and teardown.
- `App-M` presents inventory and owner-visible state, but must not become a
  datapath proxy, Linux administration proxy, or secret-printing proxy.

## Entity States

### Device-D tunnel state

| State | Meaning | Allowed next states |
|---|---|---|
| `unenrolled` | Device has no usable Soyeht identity for this household. | `enrolling`, `unavailable` |
| `enrolling` | User/owner enrollment flow is in progress. | `available`, `unavailable`, `failed` |
| `available` | Device can request Claw access, but no tunnel is active. | `resolving_claw`, `revoked`, `unavailable` |
| `resolving_claw` | Device has selected a Claw and is checking Mesh-C state. | `offer_requested`, `denied`, `failed` |
| `offer_requested` | Device is asking Mesh-C for a selected-Claw offer. | `offer_ready`, `denied`, `failed` |
| `offer_ready` | Device has a verified, fresh offer but has not installed a route. | `dialing_relay`, `expired`, `revoked`, `failed` |
| `dialing_relay` | Device is dialing Relay-R outbound. | `authenticating`, `relay_unavailable`, `failed` |
| `authenticating` | Session auth, ACL, revocation, and selected-Claw binding are checked. | `installing_route`, `denied`, `revoked`, `failed` |
| `installing_route` | Packet Tunnel is being configured for selected Claw route only. | `connected`, `failed` |
| `connected` | Tunnel is up and route scope is active for exactly one selected Claw. | `degraded_control`, `disconnecting`, `revoked`, `failed` |
| `degraded_control` | Tunnel remains up, but Soyeht control service is unavailable. | `connected`, `disconnecting`, `revoked`, `failed` |
| `disconnecting` | User or policy requested teardown. | `disconnected`, `failed_teardown` |
| `disconnected` | Tunnel route/interface removed cleanly. | `available`, `unavailable` |
| `denied` | Mesh-C/ACL/selected-Claw check denied access. | `available`, `unavailable` |
| `expired` | Offer expired before connection completed. | `available`, `offer_requested` |
| `revoked` | Device, ACL, offer, or session was revoked. | `available`, `unavailable` |
| `relay_unavailable` | Relay-R could not be reached or did not pair the slot. | `available`, `offer_requested` |
| `failed` | Generic redacted failure before connected state. | `available`, `unavailable` |
| `failed_teardown` | Teardown failed or left state requiring repair. | `unavailable` |

`connected` is reachable only after offer freshness, session binding, ACL,
revocation status, selected-Claw identity, relay/auth success, and route
installation have all succeeded in that order.

### Claw responder state

| State | Meaning | Allowed next states |
|---|---|---|
| `not_installed` | Responder is not installed or not available. | `installed` |
| `installed` | Responder exists, but is not armed for a session. | `available`, `unavailable` |
| `available` | Claw can serve authorized offers. | `offer_armed`, `unavailable`, `revoked` |
| `offer_armed` | Claw has accepted a fresh selected offer and will dial Relay-R outbound. | `dialing_relay`, `expired`, `revoked` |
| `dialing_relay` | Claw is dialing Relay-R outbound. | `authenticating`, `relay_unavailable`, `failed` |
| `authenticating` | Claw verifies the selected session binding. | `opening_interface`, `denied`, `revoked`, `failed` |
| `opening_interface` | TUN/utun interface and route scope are being prepared. | `serving`, `failed` |
| `serving` | Claw responder is pumping packets for exactly one selected session. | `draining`, `revoked`, `failed` |
| `draining` | Teardown started; no new session traffic should be accepted. | `closed`, `failed_teardown` |
| `closed` | Interface, route, and process state are clean. | `available`, `unavailable` |
| `denied` | Session was denied by policy. | `available`, `unavailable` |
| `expired` | Offer expired before use. | `available` |
| `revoked` | Claw, offer, ACL, or session was revoked. | `draining` |
| `relay_unavailable` | Relay-R could not pair the outbound dial. | `available` |
| `unavailable` | Profile, entitlement, config, or host capability missing. | `available` |
| `failed` | Generic redacted failure before serving. | `available`, `unavailable` |
| `failed_teardown` | Teardown failed or left interface/route/process residue. | `unavailable` |

`serving` must not make the Claw a LAN router. The only accepted packet scope is
the selected Device-D address to the selected Claw tunnel address and the return
path for that same pair.

`opening_interface` is reachable only after a fresh immediately-before-open
check of offer/session binding, ACL, revocation status, selected-Claw identity,
and responder profile. If any input becomes stale, revoked, or mismatched after
relay authentication but before interface/route open, the Claw must transition
to `denied` or `revoked` without opening TUN/utun or installing a route.

### Mesh-C offer/session state

| State | Meaning | Allowed next states |
|---|---|---|
| `no_acl` | Device-D has no authorization for the selected Claw. | `acl_granted` |
| `acl_granted` | Owner/member authorization exists for one Device-D/Claw relation. | `offer_minted`, `acl_revoked` |
| `offer_minted` | A fresh single-use offer exists. | `offer_consumed`, `offer_expired`, `offer_revoked` |
| `offer_consumed` | The offer has been used to establish a session. | `session_active`, `session_failed` |
| `session_active` | Mesh-C sees a live selected-Claw session. | `session_degraded`, `session_closed`, `session_revoked` |
| `session_degraded` | Datapath or control-plane health is degraded but not silently hidden. | `session_active`, `session_closed`, `session_revoked` |
| `session_closed` | Session ended and should not be reusable. | `acl_granted`, `acl_revoked` |
| `offer_expired` | Offer TTL elapsed before use. | `acl_granted` |
| `offer_revoked` | Offer was explicitly revoked before use. | `acl_granted` |
| `acl_revoked` | Owner/member authorization was removed. | `no_acl` |
| `session_revoked` | Live session was revoked and must tear down boundedly. | `acl_revoked`, `session_closed` |
| `session_failed` | Session creation failed without becoming active. | `acl_granted`, `acl_revoked` |

Mesh-C is the only authority for real ACL grants and revocations. Agents may
implement validators, dry-runs, and tests, but must not mark real access granted
without owner input.

## Connection Sequence

1. `Device-D` selects one Claw alias.
2. `Device-D` asks `Mesh-C` for selected-Claw availability and authorization.
3. `Mesh-C` rejects if the device, member, Claw, ACL, capability, or revocation
   state is not valid.
4. `Mesh-C` mints a single-use, TTL-bound `IpTunnel` offer for exactly the
   selected Claw and Device-D identity.
5. `Mesh-C` authorizes the session rendezvous capability only after rechecking
   session binding, ACL, revocation, selected-Claw identity, and Claw
   availability.
6. `Claw-*` and `Device-D` both dial `Relay-R` outbound.
7. `Relay-R` pairs the rendezvous slot and blindly splices bytes.
8. Both endpoints verify offer/session binding, ACL, revocation, and selected
   Claw identity.
9. Immediately before any interface/route open, `Claw-*` rechecks the same
   binding, ACL, revocation, selected-Claw identity, and responder profile.
10. `Device-D` installs only the selected Claw route.
11. `Claw-*` opens only the selected responder interface/route scope.
12. Packet pump starts.
13. Soyeht control channel uses the in-tunnel endpoint for the selected Claw.
14. Disconnect, revoke, failure, relay close, or owner action tears down both
    sides and removes interface/route/process state.

Route installation and `connected` status happen only after step 8 succeeds.

## Fail-closed Rules

- Missing ACL, expired offer, stale offer, stale session, or revoked state denies
  before relay dial where possible.
- A rendezvous capability is not enough by itself: use before `Relay-R` dial
  must revalidate session binding, ACL, revocation, selected-Claw identity, and
  Claw availability.
- Invalid offer/session/ACL/selected-Claw binding denies before route install.
- Any Packet Tunnel setup failure removes partial route/interface state.
- Relay failure never falls back to Tailscale, LAN, or relay data channels.
- Control-service failure is reported as control degradation, not a tunnel
  success.
- Claw responder policy drops non-IPv4 and out-of-scope packets without
  forwarding to LAN, unselected Claws, default route, or engine/admin endpoints.
- Teardown residue puts the entity into `failed_teardown`/`unavailable` until a
  repair path proves state is clean.
- Public status and logs contain only static labels, aliases, and documentation
  safe concepts.

## User-visible Status Mapping

| Internal state | Public status |
|---|---|
| `available` | `available` |
| `resolving_claw`, `offer_requested`, `offer_ready`, `dialing_relay`, `authenticating`, `installing_route` | `connecting` |
| `connected` | `connected` |
| `degraded_control`, `session_degraded` | `connected_degraded_control` |
| `disconnecting`, `draining` | `disconnecting` |
| `disconnected`, `closed`, `session_closed` | `disconnected` |
| `denied`, `no_acl`, `acl_revoked` | `denied` |
| `expired`, `offer_expired` | `expired` |
| `revoked`, `session_revoked`, `offer_revoked` | `revoked` |
| `relay_unavailable` | `relay_unavailable` |
| `failed`, `session_failed` | `failed` |
| `failed_teardown` | `repair_required` |
| `unavailable`, `not_installed` | `unavailable` |

Public status details must be redacted. They can identify which class of check
failed, but not real endpoints, paths, hostnames, device identifiers, secrets,
or non-documentation addresses.

## Test Obligations

State-machine tests should cover at least:

- unauthorized Device-D cannot obtain an offer;
- authorized Device-D can obtain an offer for selected Claw only;
- offer expiry denies before route install;
- revocation before connect denies before route install;
- revocation between relay authentication and Claw interface open denies before
  TUN/utun/route open;
- revocation while connected transitions to teardown and then closed;
- consumed offer replay is denied before relay dial or route install;
- closed session token/record cannot transition back to active session or
  connected state;
- second connection attempt requires a newly minted offer;
- selected Claw mismatch denies before route install;
- Relay-R unavailable does not install route and does not fallback;
- control service down while tunnel up reports degraded control;
- tunnel down plus control request does not fallback;
- teardown after normal disconnect removes route/interface/process state;
- relay close while connected transitions to disconnecting/draining and then
  closed, or to repair-required if cleanup cannot be proven, with no route or
  interface residue;
- owner disconnect tears down both sides and rejects new traffic while draining;
- teardown after forced failure removes route/interface/process state or enters
  repair-required;
- Device-D authorized for Claw-M is denied for Claw-L unless a separate ACL
  exists;
- Device-D authorized for Claw-L is denied for Claw-M unless a separate ACL
  exists;
- Claw-M route scope cannot reach Claw-L, LAN peers, or engine/admin endpoints;
- Claw-L route scope cannot reach Claw-M, LAN peers, or engine/admin endpoints;
- each selected Claw has exactly its own route and no unselected Claw route;
- public error strings contain no real endpoint, hostname, path, secret, or
  non-documentation address.

These tests can be implemented first as pure model tests with mocked Mesh-C,
Relay-R, and Packet Tunnel adapters, then reused as E2E assertions when the
real iOS and Claw responders are available.

## Non-goals

- No production rollout authorization.
- No full-tunnel/default-route VPN.
- No Tailscale datapath fallback.
- No relay-side authorization.
- No Claw LAN routing.
- No public publication of raw evidence.
