# Contract: Bonjour `_soyeht-household._tcp` for pair-machine windows

Per protocol §13. This contract refines Phase 2's publisher to handle the Phase 3 ceremony state.

## Service

- Service type: `_soyeht-household._tcp.local.`
- Port: theyOS HTTPS port (default 8443).
- Members publish on every household-routable interface (Tailscale + LAN).

## TXT records — base set (always)

| Key | Value | Source |
|---|---|---|
| `proto` | `1` | constant |
| `hh_id` | `hh_<base32>` | local household id |
| `hh_name` | UTF-8 household name | `HouseholdRecord.name` |
| `m_id` | `m_<base32>` | local machine id |

## TXT records — pairing-state layered

When a pair-device or pair-machine window is open, the publisher adds these keys.

| Key | Value | Phase 2 (pair-device) | Phase 3 (pair-machine, founder side) | Phase 3 (pair-machine, candidate side) |
|---|---|---|---|---|
| `pairing` | `device` / `machine` | `device` | `machine` | `machine` |
| `pair_role` | `founder` / `joiner` | absent | `founder` | `joiner` |
| `pair_nonce` | base32-lowercase no-pad of first 8 bytes of the window nonce | present | present | present |
| `m_pub_b32` | base32-lowercase no-pad of `BLAKE3-128(m_pub)[0..12]` (20 chars) | absent | absent | present (candidate's own m_pub hint) |

The publisher subscribes to `PairDeviceWindow` and `PairMachineWindow` state via in-process channels and re-registers the TXT only (not the service type) on every state change. Exactly one of `pairing=device` / `pairing=machine` is present at a time; it is absent when both windows are idle.

## Browser behaviour (M1, founding machine, Phase 3)

When M1 is in single-machine mode and `PairMachineWindow.state == idle`, M1 browses for `_soyeht-household._tcp` records carrying:

- `hh_id` equal to its own (so it ignores other households on the same LAN);
- `pair_role=joiner` and a `pair_nonce` it has not yet seen;
- `m_pub_b32` consistent with the eventual `JoinRequest` it fetches.

On finding a candidate, M1 issues `GET http://<resolved-addr>:<port>/pair-machine/local/seed?nonce=<short>` against the candidate's pre-household listener (see R5 and `contracts/join-request.md`) to obtain the signed `JoinRequest`. M1 does not surface any UI before that fetch succeeds. HTTP (not HTTPS): the candidate has no household-issued cert yet; the underlay (Tailscale WireGuard or LAN) plus the candidate's `response_sig` over the `JoinRequest` body provide authenticity, and there is no confidential payload until `local/finalize` (which ships an AEAD-encrypted shard).

## Browser behaviour (Soyeht iPhone, Phase 3, owner)

The iPhone does not need to browse Bonjour for Phase 3 — its job is to consume `OwnerEvent`s via long-poll. Bonjour is between the two theyOS machines.

## Anti-spoofing

A LAN attacker can publish any TXT it wants. M1 mitigates by:

1. Only fetching `JoinRequest` from the published `addr` for short-nonce-matching announcements.
2. Verifying `challenge_sig` on the fetched `JoinRequest` under the included `m_pub` before any state change.
3. Surfacing the fingerprint from the verified `JoinRequest` to the owner iPhone, not from the TXT.

Bonjour is therefore a discovery hint, not a trust input.
