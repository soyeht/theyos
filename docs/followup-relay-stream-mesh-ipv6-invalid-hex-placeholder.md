# Follow-up: `mesh_ipv6` placeholder is not valid hex (`fd00:c1aw::…` twins)

**Severity:** LOW / latent. Not a T1 blocker — the server-rs relay_stream twin
that the T1 `IpTunnel` datapath depends on was fixed on
`t1-phase0-dev-datapath`. The remaining twins are on the PTY/ClawSite
`GuestCredential` path and a `friend-cli` test fixture, which never parse the
value today, so nothing is broken in production right now. This is a
correctness cleanup to prevent the same bug biting any future strict-parsing
consumer.

## Symptom

The `mesh_ipv6` session-correlation placeholder is formatted as
`fd00:c1aw::…`. The hextet `c1aw` is a human-recognizable "claw" label, but `w`
is not a hex digit, so the string is **not a syntactically valid IPv6 address**:

```
"fd00:c1aw::2222:2222".parse::<std::net::Ipv6Addr>()  // Err(invalid IPv6 address syntax)
```

## Reproduction env

Any build; pure string/parse behavior, no host or network needed.

## What works vs. what fails

- **Works today:** the PTY/ClawSite guest and `friend-cli` treat `mesh_ipv6`
  as an opaque correlation string and never call `.parse::<Ipv6Addr>()`, so the
  invalid value is inert.
- **Fails:** any consumer that validates the ack's `mesh_ipv6` as a real IPv6.
  The new T1 `IpTunnel` guest (`t1-iptunnel-dev-runner`'s `validate_session_ack`)
  does exactly this and rejects the session with `IpTunnel session ack mesh
  address invalid` / `invalid IPv6 address syntax`. That is the correct,
  fail-closed behavior — the producer is the bug.

## Fix (do this on a shared/main-track branch, not the isolated T1 branch)

Change `c1aw` → a valid hex hextet (the T1 branch used `c1a0`, which still reads
"claw"-ish) at the remaining sites, update the exact-string assertions, and add
a parse-regression guard so a future invalid-hex placeholder fails a test
instead of a live datapath:

- `admin/rust/household-rs/src/claw_share_data_tunnel.rs:423`
  — `GuestCredential::mesh_ipv6()` format string (`fd00:c1aw::{:02x}{:02x}:{:02x}{:02x}`).
- `admin/rust/household-rs/src/claw_share_data_tunnel.rs:1187`
  — `assert_eq!(cred.mesh_ipv6(), "fd00:c1aw::2222:2222")` fixture assertion.
- `admin/rust/friend-cli-rs/src/main.rs:2305`
  — `"fd00:c1aw::1"` test literal.

## Why this was deferred here

`t1-phase0-dev-datapath` is an isolated Product A / per-Claw VPN experimental
branch (nothing merged, nothing imported elsewhere). `household-rs` is
foundational shared code and `friend-cli` is the general guest client; changing
them belongs on a shared-track change with its own review, not on the isolated
T1 branch. The T1 crown (two-ended no-net datapath) only needs the server-rs
`RelayStreamOfferSession` twin, which was fixed here:

- `admin/rust/server-rs/src/claw_share_relay_stream_session.rs`
  — `RelayStreamOfferSession::from_offer` now emits `fd00:c1a0::…` and its
    module test parses the placeholder as a real `Ipv6Addr` (regression guard).

## Files of interest

- `admin/rust/household-rs/src/claw_share_data_tunnel.rs` (Device/PTY path twin)
- `admin/rust/friend-cli-rs/src/main.rs` (test fixture twin)
- `admin/rust/server-rs/src/claw_share_relay_stream_session.rs` (fixed T1 twin, reference)
- `admin/rust/t1-iptunnel-dev-runner-rs/src/main.rs` (`validate_session_ack`, the strict consumer)
