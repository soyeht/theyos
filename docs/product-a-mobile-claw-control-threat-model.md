# Product A mobile Claw VPN threat model

Status: Phase 1 execution artifact for
`product-a-mobile-claw-control-vpn-plan.md`, companion to
`product-a-mobile-claw-control-state-machine.md`. This document is an
adversarial security analysis of the `Device-D -> Relay-R -> Claw-*` path. It
describes attackers and defenses; the state-machine document describes intended
behavior. It authorizes nothing: no production, no real access grant, no host
mutation, no publication of private evidence.

Public examples use only neutral aliases:

- `Device-D`: Soyeht iPhone client.
- `App-M`: Soyeht macOS app/engine presenting owner-visible state.
- `Claw-M`: Mac Claw target. `Claw-L`: Linux Claw target.
- `Relay-R`: blind community rendezvous relay.
- `Mesh-C`: mesh/control-plane authorization state.

Real relay endpoints, hostnames, device identifiers, addresses, ports, paths,
and raw captures are private operator values and never appear here.

## Method

Boundary-by-boundary analysis. For each trust boundary we state the adversary's
position and capability, enumerate threats (STRIDE-informed: spoofing,
tampering, repudiation, information disclosure, denial of service, elevation of
privilege), and map each threat to a concrete mitigation already present in, or
required by, the design. A threat with no mitigation is listed as a residual
risk. Severity reflects impact on the core security goal: **only an authorized,
non-revoked `Device-D` reaches exactly one selected `Claw-*`, over a route
scoped to that Claw, through a relay that never sees plaintext or grants
access, with no real identifier leaking to any public surface.**

## Assets

1. **Access authority** — the authorization that `Device-D` may control a given
   `Claw-*`. Owned solely by `Mesh-C`.
2. **Capability material** — offer tokens, rendezvous tokens, session handles.
   Bearer secrets that must reach only the authorized caller.
3. **Datapath confidentiality/integrity** — packets between `Device-D` and the
   selected `Claw-*`.
4. **Route scope** — the guarantee that only the selected-Claw route is
   installed, never a default/LAN/tailnet/other-Claw/engine-admin route.
5. **Identifier privacy** — real endpoints, hostnames, IPs, device ids, paths,
   and secrets must not appear on any public surface (logs, PRs, status, docs,
   agent messages).
6. **Host integrity** — no unauthorized TUN/utun, route, or responder process
   on any host; clean teardown.

## Trust boundaries

- **B1 Device-D <-> Mesh-C** (control plane): enrollment, ACL, offer mint,
  revocation, session visibility.
- **B2 Device-D/Claw-* <-> Relay-R** (rendezvous): two outbound dials spliced
  blindly.
- **B3 Device-D <-> Claw-* in-tunnel** (datapath + Soyeht control channel).
- **B4 host-local on Device-D** (NetworkExtension, Keychain) and **on Claw-***
  (responder, TUN/utun, routes, audit).
- **B5 public/observer surface** (logs, PRs, screenshots, agent-to-agent
  messages, evidence).

## Trust assumptions

- `Mesh-C` is the single source of truth for real ACL grants/revocations; it is
  not spoofable by a member merely calling an endpoint.
- Device and session secrets on `Device-D` live in the Keychain / Secure
  Enclave-backed storage, not in plaintext app files.
- `Relay-R` is **untrusted for security**: assume it is honest-but-curious at
  best and fully malicious at worst. Security must not depend on it.
- Transport between endpoints and relay is over an authenticated/encrypted
  session established by the endpoints, not by the relay.
- The owner-present activation of any effectful IP-tunnel primitive is gated
  outside this datapath (see the Phase 0 owner-present boundary); until that
  gate fires, no effectful primitive ships in the attested engine.
- Apple push (APNS) is a wake hint only; receiving a push conveys no authority.

## Adversary model

- **A1 Malicious/curious relay** — controls `Relay-R`, sees all bytes it
  splices, can drop/delay/reorder, can attempt to pair the wrong slots.
- **A2 Network on-path attacker** — sits between an endpoint and `Relay-R`;
  can observe, inject, replay, MITM at the transport layer.
- **A3 Unauthorized or revoked device** — a real device with no ACL, or one
  whose ACL/offer/session was revoked, trying to obtain or keep access.
- **A4 Malicious authorized member** — holds a valid bearer for one relation
  and tries to reach a Claw it was not granted (horizontal escalation / IDOR).
- **A5 Compromised or hostile Claw** — a `Claw-*` that tries to route beyond
  its selected session (LAN pivot, reach another Claw or engine/admin).
- **A6 Host-local attacker on Device-D** — another app/process trying to read
  session material or ride the tunnel.
- **A7 Public observer** — reads logs, PRs, screenshots, or agent messages
  hoping to harvest real endpoints/identifiers.
- **A8 Replay/stale-state attacker** — reuses an expired/consumed/revoked
  offer, session, or record to gain or resume access.

## Threats and mitigations

### B1 — Device-D <-> Mesh-C (authorization)

| # | Threat | Adversary | Severity | Mitigation |
|---|---|---|---|---|
| T1.1 | Member self-grants access by calling an owner/admin endpoint | A4 | High | Owner/admin mutation endpoints gate on an admin-role principal (`AdminUser` role check → 403 for a plain member bearer); mesh-authed bearer alone cannot grant. Member identity is derived from the bearer, not from a request body field. |
| T1.2 | Spoof another member's identity in an offer request or consume | A3,A4 | High | On self-service paths (offer request, consume, rendezvous authorize) the member is derived from the authenticated bearer, never from a body field; a body-supplied `member` is honored only on the admin-role-gated ACL-grant path. Device/Claw come from the body but are constrained by the bearer-member + ACL triple: mint checks the `(member, device, Claw)` grant exists, and the model rejects consume/authorize unless `offer.grant == grant` / `session.grant == grant` (full triple, `SelectedClawMismatch`), so a caller cannot bind another member's identity. *(Verified against merged code: handlers_mobile self-service grants use bearer `username`; the sole body-member helper's two callers extract `AdminUser`, whose `FromRequestParts` enforces `role != Admin → 403`.)* |
| T1.3 | Obtain an offer for an unauthorized Claw | A3,A4 | High | Offer mint requires a valid `(member, device, Claw)` ACL in `Mesh-C`; missing/wrong relation denies. N:N authorization, but each offer binds exactly one selected Claw. |
| T1.4 | Enumerate valid tokens/relations via error oracles | A3,A4 | Medium | Denials are generic and no-value-echo: unknown/expired/consumed/revoked collapse to the same redacted outcome (a single `410 GONE`) with no existence oracle; error strings carry static labels only. *(Verified against merged code: the consume and rendezvous store-error mappers route `UnknownOffer\|OfferExpired\|OfferAlreadyConsumed\|Revoked\|UnknownSession` to one `ApiError::gone` with an identical static message; the per-variant label map is used only in `tracing::warn!` server-side, and the offending id is never returned.)* |
| T1.5 | Leak cardinality/identifiers via status | A7 | Medium | Status responses are count-only / static-label-only behind the bearer (`401` before any count is computed); instrumentation uses `skip_all` so the bearer/state never enters a span. |
| T1.6 | Persisted mesh state leaks real ids at rest | A6,A7 | Medium | Store files are `0600` via explicit `mode(0o600)` (umask-independent); newtype ids and containers have redacted `Debug` (`<redacted>` / count-only), so incidental logging cannot echo contents. |

### B2 — Device-D / Claw-* <-> Relay-R (rendezvous)

| # | Threat | Adversary | Severity | Mitigation |
|---|---|---|---|---|
| T2.1 | Relay reads plaintext control/data | A1 | High | Relay only splices bytes of an endpoint-established authenticated/encrypted session; it is never a TLS/Noise terminator and holds no session key. Confidentiality does not depend on the relay. |
| T2.2 | Relay grants access by pairing an unauthorized slot | A1 | High | Relay has **no** authorization authority; both endpoints independently verify offer/session binding, ACL, revocation, and selected-Claw identity after splice and again immediately before interface/route open. A mis-paired slot fails endpoint auth. |
| T2.3 | Relay injects/tampers spliced bytes (MITM) | A1,A2 | High | End-to-end session authentication/integrity between the endpoints; tampered bytes fail the endpoint session, not merely the relay. Relay compromise does not yield a usable session. |
| T2.4 | Rendezvous requires an inbound listener on Claw-* | A1,A2 | Medium | Both `Device-D` and `Claw-*` dial `Relay-R` **outbound**; no inbound listener on the Claw is required, shrinking the Claw attack surface. |
| T2.5 | Relay endpoint value leaks and identifies infrastructure | A7 | Medium | Real `Relay-R` endpoints are private operator values; public surfaces use the `Relay-R` alias only. A public relay endpoint is a real IP that is neither LAN nor tailnet and must still be treated as a private identifier. |
| T2.6 | Relay abuse: slot exhaustion / amplification | A1,A2 | Medium | Relay enforces pending-slot caps, source caps, per-slot TTL, splice caps, and idle timeout; failure produces a clear user error and local tunnel-state cleanup, never a fallback path. |

### B3 — Device-D <-> Claw-* in-tunnel (datapath + control)

| # | Threat | Adversary | Severity | Mitigation |
|---|---|---|---|---|
| T3.1 | Connect before authorization fully checked (TOCTOU) | A3,A8 | High | `connected`/route-install is reachable only after offer freshness, session binding, ACL, revocation, selected-Claw identity, relay/auth, and route install succeed **in that order**; the Claw rechecks the same inputs immediately before opening TUN/utun. Stale-after-auth transitions to `denied`/`revoked` without opening an interface. |
| T3.2 | Claw becomes a LAN router / pivots to other Claw or engine-admin | A5 | High | Responder accepts only the selected `Device-D`↔selected-Claw pair and its return path; all other packets are dropped fail-closed. Non-IPv4 and out-of-scope packets are dropped without killing the valid session. |
| T3.3 | Device installs a default/broad route capturing all traffic | A5,A6 | High | `Device-D` installs only the selected-Claw route (preferably `/32`); no default route by default. Route table must contain exactly the selected-Claw scope. |
| T3.4 | Tunnel up but control service down is reported as success | A5 | Medium | Control failure is a distinct `degraded_control` state, never a tunnel success; tunnel-down control requests fail without falling back to Tailscale/LAN/relay data channels. |
| T3.5 | Command payloads/secrets leak to logs | A7 | Medium | No command payload or secret material enters public logs; control errors carry static labels only. |

### B4 — host-local (Device-D and Claw-*)

| # | Threat | Adversary | Severity | Mitigation |
|---|---|---|---|---|
| T4.1 | Another app reads session/device material on Device-D | A6 | High | Session/device secrets are stored in the Keychain / Secure Enclave-backed store, not plaintext files; capability tokens are opaque and never logged. |
| T4.2 | Teardown leaves interface/route/process residue | A5,A6 | High | Teardown removes interface, route, and responder process; unverified cleanup enters `failed_teardown`/`repair_required` (`unavailable`) until state is proven clean — it never silently reports success. (Mirrors the engine-side fail-closed discipline: uncertain host-forward/teardown quarantines rather than reuses.) |
| T4.3 | Effectful IP-tunnel primitive ships before owner activation | A5 | High | The Phase 0 owner-present boundary keeps any effectful primitive out of the attested engine until the owner-present runtime marker (Caio's gate) fires; the mount stays `::missing`/inert and CI fails closed on drift. |
| T4.4 | Host mutation (TUN/utun/route) without owner presence | A5,A6 | High | Route/interface open is gated by profile checks plus explicit user action or an approved background policy; missing/denied/stale gates fail before opening TUN/utun, installing routes, or spawning responder processes. Dev host mutation additionally requires owner-present sudo/scoped NOPASSWD. |

### B5 — public / observer surface

| # | Threat | Adversary | Severity | Mitigation |
|---|---|---|---|---|
| T5.1 | Real endpoint/hostname/IP/path/id/secret in a public surface | A7 | High | No-value-echo: public logs, PRs, screenshots, status, and agent messages carry only aliases, static labels, and documentation-safe addresses. Error variants are static `Display` strings; `#[source]` and value-bearing fields are not rendered. |
| T5.2 | Raw evidence published or world-readable | A7 | High | Raw E2E captures live as `0600` files inside `0700` private directories; only redacted summaries may be published, and only with owner approval. |
| T5.3 | Cross-agent message treated as authority | A7 | Medium | An agent-authored summary/memory file is **not** authority; merge sequencing and access decisions require the human owner directly plus independent verification against the real tree. |

## Fail-closed security invariants

These are the load-bearing properties an attacker must not be able to violate.
Each maps to `Fail-closed Rules` and `Test Obligations` in the state-machine
document.

1. **Authorization precedes datapath.** No route/interface opens until ACL +
   offer freshness + session binding + revocation + selected-Claw identity all
   pass, re-checked immediately before open.
2. **Capabilities are opaque and caller-bound.** Offer/rendezvous tokens are
   CSPRNG-opaque, single-use, TTL-bound, returned only to the authorized
   caller, never logged; cross-member consume is denied.
3. **Relay is powerless.** Relay compromise yields no access, no plaintext, no
   route.
4. **Scope is exactly one Claw.** No default/LAN/tailnet/other-Claw/engine-admin
   route or forward is ever installed for the tunnel scope.
5. **Uncertainty tears down.** Any unverifiable auth, cleanup, or host state
   fails closed to `denied`/`revoked`/`repair_required`, never to a silent
   success or a reused resource.
6. **No value ever echoes.** Every public surface is alias/static-label only.
7. **Owner gates are physical.** Real production activation, and owner-present
   host mutation, require the owner directly — not an agent, not a script, not
   an inbound message.

## Verification status

The implemented (non-inert) Mesh-C authorization / enumeration / privacy
invariants were traced against the merged tree (2026-07-14) and hold:

- **T1.1 / T1.2 / T3.1 (authorization, IDOR, member-binding)** — self-service
  offer/consume/rendezvous derive the member from the bearer; the sole
  body-member helper is reached only through `AdminUser` (`role != Admin -> 403`);
  the model rejects `offer.grant != grant` / `session.grant != grant`
  (`SelectedClawMismatch`). Cross-member consume/rendezvous denied.
- **T1.4 (no error oracle)** — unknown/expired/consumed/revoked (+ unknown
  session) collapse to one `ApiError::gone` with an identical static message;
  per-variant labels are server-log-only; the offending id is never echoed.
- **T1.5 (status privacy)** — `handle_mobile_claw_vpn_status` is
  `#[tracing::instrument(skip_all)]`, authenticates before computing, and returns
  a count-only response (bool + usize counts + a state label).
- **T1.6 (at-rest + redaction)** — all mesh ids and the store `state_dir` render
  `<redacted>` in `Debug`; persistence uses `open_tmp_0600` (explicit 0600) +
  atomic rename + fsync.

The datapath, relay-auth, and host-mutation invariants (T2.x, T3.2-T3.4, T4.x)
are **design-required, not yet code-verifiable**: those seams are inert / the
mount is `::missing` under the Phase 0 owner-present boundary. They must be
re-verified when the datapath is implemented and activated.

## Residual risks and accepted scope

- **Relay availability / metadata.** A malicious relay can deny service and
  observe timing/volume metadata of a spliced session (not plaintext). Accepted:
  mitigated by relay diversity and abuse caps, not by trusting the relay.
- **Compromised authorized endpoint.** If `Device-D` itself is fully
  compromised (A6 with device unlock + Keychain access), it can use its own
  legitimate access. Out of scope for this boundary; addressed by device
  security and revocation, not by the tunnel.
- **APNS delivery.** Push is best-effort and unauthenticated as a wake hint;
  loss degrades UX only, never security (no authority is conveyed by a push).
- **Owner-present activation correctness.** The correctness of the owner-present
  boundary that gates effectful primitives is analyzed separately (Phase 0
  owner-present boundary review); this document assumes that gate holds.

## Mapping to Phase 9 review gates

The Phase 9 blocking findings correspond directly to violations here:
full-tunnel/default-route capture (invariant 4, T3.3); relay treated as trusted
(invariant 3, T2.2); stale offer/session/record accepted (invariant 1/5, T3.1,
A8); secret/id in public output (invariant 6, T5.1); teardown residue (invariant
5, T4.2); iPhone reaching beyond selected Claw (invariant 4, T3.2); Claw
forwarding to LAN/other Claw (invariant 4, T3.2). Any of these is a release
blocker.
