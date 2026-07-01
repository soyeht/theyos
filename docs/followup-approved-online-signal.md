# Approved/Online Signal Follow-up

Status: **STOP / decision brief**. No runtime wire message is implemented by
this document.

## Why This Exists

The Local Workspace direction wants the user experience:

1. Mac asks to secure/connect.
2. iPhone approves with the strong owner ceremony.
3. Mac shows approved/online.
4. Connectivity chooses the best available path.

The current presence channel does not carry an explicit approval event. The
current signal is reactive connectivity:

- `PresenceProtocol.swift` defines `presence_ready` and `presence_denied`, but no
  `presence_approved`.
- `PresenceSession` sends `presence_ready` after the presence HMAC verifies.
- `MacPresenceClient` maps `presence_ready` to `.authenticated`.

That proves the iPhone reconnected and authenticated to the Mac's presence
channel. It does not, by itself, prove that the Mac received the result of a
specific Secure/Upgrade with iPhone owner-approval ceremony.

## Non-Goals

- Do not add `presence_approved` opportunistically inside the strong-tier
  minting slice.
- Do not treat `presence_ready` as an explicit approval event in product copy or
  flip-readiness.
- Do not reuse `presence_denied` for owner approval denial unless the wire
  contract explicitly separates auth-denied from approval-denied semantics.
- Do not use Product A / nvpn / relay as authority for approval. Transport can
  carry a post-trust signal later, but it does not define trust.

The current STOP guards fail if product/runtime code adds approved/online wire
tokens before this STOP is resolved:

- Swift product guard: `sourceGuardsSecureUpgradeStrongMintingStop`;
- server runtime guard: `approved_online_signal_source_guard_remains_stop_gated`.

## Decision Options

### Option R: Reactive-Only

Keep the current model. The Mac appears online only after the iPhone reconnects
and completes the presence HMAC handshake.

Properties:

- no new wire message;
- no new replay surface;
- simplest operationally;
- cannot honestly promise immediate "approved" if the iPhone does not reconnect
  or the Mac endpoint is stale/unreachable.

If governance chooses this option, product copy should say the Mac will connect
when the iPhone is reachable again, not that the Mac receives immediate approval.

### Option E: Explicit Approval Signal

Add a versioned, reviewed signal that carries the result of a specific
Secure/Upgrade with iPhone ceremony. Candidate transports:

- iPhone-to-Mac presence message, such as `presence_approved` /
  `approval_denied`, once the iPhone can reach the Mac;
- server-to-Mac event if the backend has a delivery path to the Mac;
- Mac polling a server approval status keyed by the approval request id.

Required properties:

- the signal is bound to the same operation/request/cursor/challenge as the
  Secure/Upgrade ceremony;
- the signal is replay-safe and has expiry or monotonic state;
- denied/cancelled/expired are explicit states, not inferred from network
  absence;
- the Mac distinguishes approval state from network presence state;
- legacy clients ignore unknown messages safely;
- tests cover both sides of the wire and the no-signal/reactive fallback.

This option supports the desired Apple-level handoff, but it is a protocol
change and must be designed with the strong-tier minting ceremony.

## Recommended Framing

Treat the explicit approved/online signal as the UX/protocol half of
Secure/Upgrade with iPhone. It should be decided alongside the strong-tier
minting proof model, not after the fact and not hidden inside the presence
connectivity layer.

Conservative recommendation until governance decides: keep the current
reactive-only runtime, keep the approved/online STOP guards, and avoid UI copy
that promises immediate approval.

## Acceptance Criteria For A Future Implementation

- Decision records whether Option R or Option E is chosen.
- If Option E is chosen, the wire name, payload, versioning, replay rules, and
  failure states are specified before implementation.
- Swift and backend/Mac tests pin the exact payload and state transitions.
- The Swift and server STOP guards are updated in the same PR that implements
  the reviewed signal.
- Flip-readiness continues to require strong-tier minting before
  `reviewed-core-v2`; an approved/online signal alone does not authorize
  fan-out.
