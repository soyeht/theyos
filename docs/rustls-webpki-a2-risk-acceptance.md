# Rustls WebPKI And A2 Risk Acceptance

## Scope

The Rust workspace resolves two `rustls-webpki` versions:

| Version | Consumer | Disposition |
| --- | --- | --- |
| `0.103.13` | Rustls 0.23 consumers, including the general-purpose HTTP and relay paths | Updated directly to the latest compatible `0.103.x` release. |
| `0.102.8` | `a2` 0.10.0 in the APNs client path | Accepted temporarily under the narrow conditions below. |

The direct update to `0.103.13` addresses `RUSTSEC-2026-0098`,
`RUSTSEC-2026-0099`, and `RUSTSEC-2026-0104` for the reachable Rustls 0.23
dependency graph. `RUSTSEC-2026-0049` is already addressed for that graph by
the pre-update `0.103.10` version.

## Why The Older Copy Remains

`a2` 0.10.0 is the only dependency holding `rustls-webpki` 0.102.8. It uses
Rustls 0.22.4, and no released `a2` version upgrades that Rustls line to 0.23.
The upstream default branch is also still on Rustls 0.22.4. Updating the older
WebPKI package directly would violate `a2`'s Rustls 0.22 dependency contract.

## Accepted APNs Threat Model

The remaining 0.102.8 use is an outbound TLS client for the fixed Apple APNs
endpoint. It uses the default client configuration and does not enable CRL
checking or install a custom certificate verifier.

Under that configuration, the CRL-dependent behavior in
`RUSTSEC-2026-0049` and `RUSTSEC-2026-0104` is not reachable. Exploitation of
`RUSTSEC-2026-0098` or `RUSTSEC-2026-0099` would additionally require an
active man-in-the-middle position on the APNs connection and a trusted,
name-constrained certificate authority. This is a temporary, bounded risk
acceptance for the APNs path only; it is not a waiver for other Rustls clients.

## Mandatory Review Triggers

Revisit this acceptance immediately if either condition occurs:

1. The APNs client enables CRL checking or any custom certificate verifier.
2. `a2` publishes a release based on Rustls 0.23 or later.

On the second trigger, upgrade `a2`, remove the 0.102.8 WebPKI instance, and
delete this acceptance note. A fork of `a2` remains a separate maintenance
decision and is not authorized by this document.
