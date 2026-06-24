# Household Listener Bind Posture

The household listener deliberately binds only concrete local addresses and then
narrows them by bootstrap state:

- loopback (`127.0.0.1`, `::1`);
- LAN-class private addresses, excluding link-local addresses;
- Tailnet addresses in the Tailscale IPv4/IPv6 ranges.

It never binds wildcard addresses such as `0.0.0.0` or `::`.

Exposure policy:

- `uninitialized` / `ready_for_naming`: loopback + LAN + Tailnet. This preserves
  first-launch setup and pre-household discovery on the local network.
- `named_awaiting_pair` / `ready` / `recovering`: loopback + Tailnet only. Ready
  household control-plane traffic is not exposed over LAN HTTP.

Interface names are not a security signal. A host named `tailscale*` is not
treated as Tailnet unless the address itself is in the Tailnet range. This keeps
runtime transport policy tied to addresses, not adapter labels.

Security posture:

- Claw Store household routes are PoP-gated by operation.
- Terminal attach uses a short-lived single-use token and rejects non-loopback /
  non-Tailnet peers before token consumption.
- Bonjour advertises only addresses that actually bound and are allowed by the
  same exposure policy.

This document records the current posture. Any future widening or narrowing of
bind targets must be an explicit transport-policy change with tests, not an
accidental side effect of interface naming or discovery behavior.

The admin HTTP listener is separate from the household listener. Its release
defaults are loopback-only (`127.0.0.1:8090` in `server-rs`, `127.0.0.1:8892`
in the Linux installer/launcher path). Operators may still set `ADDR`
explicitly when they need a wider bind, but broad exposure is no longer the
default.
