# Household Listener Bind Posture

The household listener deliberately binds only concrete local addresses and then
narrows them by bootstrap state:

- loopback (`127.0.0.1`, `::1`);
- LAN-class private addresses, excluding link-local addresses;
- Tailnet addresses in the Tailscale IPv4/IPv6 ranges.
- a verified Mesh-interface address, but only after the narrow Product A
  allocation has been validated and the local inventory supplies an explicit
  `VerifiedMesh` ownership fact.

It never binds wildcard addresses such as `0.0.0.0` or `::`.

`THEYOS_MESH_SUBNET` is only a validated input, not an authority to bind an
arbitrary private address. The only accepted value is the canonical Product A
allocation `10.44.0.0/16`; absent, empty, malformed, broad, reserved,
noncanonical, or locally overlapping values fail closed. A valid value without
a verified Mesh-interface ownership fact also makes zero Mesh binds. A local
address inside the configured allocation without that fact is quarantined
rather than falling through to LAN, so onboarding cannot bind or Bonjour-
advertise a real-but-unverified tunnel address. The shipping system inventory
deliberately supplies no such fact until a separate, reviewed runtime provider
can attest the real nvpn interface.

Exposure policy:

- `uninitialized` / `ready_for_naming`: loopback + LAN + Tailnet. LAN is only
  for onboarding and pre-household discovery.
- `named_awaiting_pair` / `ready` / `recovering`: loopback + Tailnet + verified
  Mesh. Ready household control-plane traffic is not exposed over LAN HTTP.

Transport posture:

- Current household traffic is HTTP plaintext on concrete TCP listeners. There
  is no TLS/rustls layer in the household listener today.
- The Ready invariant is loopback + Tailnet + verified Mesh. Tailnet and a
  verified Mesh interface are each a post-trust operator-network boundary;
  hosts outside those boundaries, including LAN peers, must not reach the Ready
  control plane.
- Wildcard binds remain prohibited. A future TLS migration must be an explicit
  transport change with new trust-bootstrap, URL, and WebSocket coverage.

Interface names are not a security signal. A host named `tailscale*` is not
treated as Tailnet unless the address itself is in the Tailnet range. This keeps
runtime transport policy tied to addresses, not adapter labels.

Security posture:

- Claw Store household routes are PoP-gated by operation.
- Terminal attach uses a short-lived single-use token and rejects non-loopback /
  non-Tailnet / non-verified-Mesh peers before token consumption. A verified
  Mesh peer is additionally admitted only while the live bootstrap state is
  literal `ready`; otherwise the route returns `403` before PoP, minting, or
  token consumption.
- Bonjour advertises only addresses that actually bound and are allowed by the
  same exposure policy; it must not advertise Mesh addresses through LAN mDNS.

Route and boundary summary:

| Route family | Boundary |
| --- | --- |
| `GET /bootstrap/status`, `GET /health`, `GET /healthz` | No auth by contract; status/liveness only, reachable according to bind posture. |
| `/bootstrap/*` onboarding routes | No admin session; ceremony-specific state, token, invitation, or local gates. |
| `POST /bootstrap/pair-machine/local/stage` | Loopback-only and only accepted while uninitialized or ready for naming. |
| `/pair-machine/local/*` | Pre-household candidate routes; gated by the candidate ceremony state. |
| `GET /pair-machine/anchor-handoff` | Tailnet-source gate plus active pair-machine window state. |
| `/api/v1/household/claws*`, instances, workspaces | Soyeht-PoP plus the declared `Operation::Claws*` caveat. |
| `POST /api/v1/household/guest-image/prepare` | Soyeht-PoP using `Operation::ClawsCreate`. |
| Terminal attach-token and PTY | Attach-token mint is peer-gated and Soyeht-PoP `ClawsUse`; PTY accepts only loopback/Tailnet/verified-Mesh peers and a single-use header token. Mesh terminal attach requires literal `ready` and otherwise returns `403` before PoP, minting, or token consumption. |

This document records the current posture. Any future widening or narrowing of
bind targets, including providing the reviewed Mesh ownership fact, must be an
explicit transport-policy change with tests, not an accidental side effect of
interface naming, CIDR membership, or discovery behavior.

The admin HTTP listener is separate from the household listener. Its release
defaults are loopback-only (`127.0.0.1:8090` in `server-rs`, `127.0.0.1:8892`
in the Linux installer/launcher path). Operators may still set `ADDR`
explicitly when they need a wider bind, but broad exposure is no longer the
default.
