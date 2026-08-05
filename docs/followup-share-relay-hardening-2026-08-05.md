# Follow-up: Share relay and Active Shares hardening (2026-08-05)

**Status:** non-blocking. The Share/relay work is integrated and the planned
validation completed. This document records deliberately deferred improvements
for a separately reviewed branch; it does not authorize runtime, wire, or
Product A changes.

## 1. Make byte telemetry on I/O errors an explicit design decision

The relay status counters count bytes accepted by `AsyncWrite`, including
normal close, byte-cap, idle timeout, and lifetime expiry. This is intentionally
an observation of accepted writes, not proof that a peer consumed the bytes.

An I/O error currently ends the splice without carrying the in-flight byte
snapshot to the status recorder. Decide whether to extend the outcome shape so
the error path reports that same snapshot, or retain the current limitation
with an explicit operator-facing rationale. Either choice needs an end-to-end
test that induces a real I/O error and proves the selected behavior.

## 2. Preflight one-shot Share invites before consuming them

A guest built against an incompatible offer contract can discover that mismatch
only after a one-shot invite has been claimed. Add a non-consuming preflight
that checks local guest capability and offer-contract compatibility before an
owner mints or a guest claims an invite.

The flow must never print an invite URI, credential, token, or slot identifier.
Keep it separate from Product A and make any network dial opt-in and
non-consuming. A negative test must show that an incompatible client fails
before changing the slot state.

## 3. Pin `connectPersistent` to the ClawSite resource on the client

Persistent relay sessions are currently used by ClawSite. Add a narrow,
fail-closed client-side resource check before dialing so a future caller cannot
silently apply the persistent path to another resource.

This is a boundary-hardening change, not an integration of Product A or
IpTunnel: it must reject non-ClawSite resources before opening a network
session, retain existing legacy behavior, and include a direct regression test.

## 4. Turn the 1,000-pair S0 result into an operational capacity policy

The S0 run establishes a demonstrated floor of 1,000 concurrent pairs; it did
not discover a capacity ceiling. If a higher target or service-level objective
is needed, define it first and run a separately authorized capacity experiment
in an isolated environment.

The next run should capture process CPU and resident memory during the known
full-occupancy hold, preserve before/after status snapshots, and stop on the
first admission drop. Do not extrapolate a maximum capacity from the completed
1,000-pair rung.

## 5. Preserve the cache migration boundary if Active Shares gains a new runtime

The Active Shares link cache deliberately treats the stored URI as a protected
value and uses a domain-separated digest only for its Keychain account
metadata. Legacy raw account names are purged on the supported mobile path.

If Active Shares is introduced into a runtime with an additional Keychain
backend or fallback, define and test the equivalent legacy-account sweep there
before enabling the feature. The cache remains a convenience for Copy Link,
never an authority for Share validity.

## Completion criteria

Address each item in its own reviewable change with focused tests and a
mutation or negative control where the property could otherwise become
vacuous. Remove this document and its index row only when all remaining items
have been resolved or moved to dedicated follow-up documents.
