# Household Listener Bind Posture

The household listener deliberately binds only concrete local addresses and then
narrows them by bootstrap state:

- loopback (`127.0.0.1`, `::1`);
- LAN-class private addresses, excluding link-local addresses;
- Tailnet addresses in the Tailscale IPv4/IPv6 ranges.

It never binds wildcard addresses such as `0.0.0.0` or `::`.

Exposure policy:

- `uninitialized` / `ready_for_naming`: loopback + LAN + Tailnet. LAN is only
  for onboarding and pre-household discovery.
- `named_awaiting_pair` / `ready` / `recovering`: loopback + Tailnet only. Ready
  household control-plane traffic is not exposed over LAN HTTP.

Transport posture:

- Current household traffic is HTTP plaintext on concrete TCP listeners. There
  is no TLS/rustls layer in the household listener today.
- The Ready invariant is loopback + Tailnet only. Tailnet is treated as an
  operator-network boundary; hosts outside loopback/Tailnet must not reach the
  Ready control plane.
- Wildcard binds remain prohibited. A future TLS migration must be an explicit
  transport change with new trust-bootstrap, URL, and WebSocket coverage.

Interface names are not a security signal. A host named `tailscale*` is not
treated as Tailnet unless the address itself is in the Tailnet range. This keeps
runtime transport policy tied to addresses, not adapter labels.

Security posture:

- Claw Store household routes are PoP-gated by operation.
- Terminal attach uses a short-lived single-use token and rejects non-loopback /
  non-Tailnet peers before token consumption.
- Bonjour advertises only addresses that actually bound and are allowed by the
  same exposure policy.

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
| Terminal attach-token and PTY | Attach-token mint is peer-gated and Soyeht-PoP `ClawsUse`; PTY accepts only loopback/Tailnet peers and a single-use header token. |

This document records the current posture. Any future widening or narrowing of
bind targets must be an explicit transport-policy change with tests, not an
accidental side effect of interface naming or discovery behavior.

The admin HTTP listener is separate from the household listener. Its release
defaults are loopback-only (`127.0.0.1:8090` in `server-rs`, `127.0.0.1:8892`
in the Linux installer/launcher path). Operators may still set `ADDR`
explicitly when they need a wider bind, but broad exposure is no longer the
default.
