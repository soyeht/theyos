# Post-merge recovery — theyos engine — contingent role

Branch: `fix/post-merge-recovery` (off `origin/main` @ `4abb72a`).
Date: 2026-05-21.

## Status

This worktree is **contingent**. The two bugs being addressed in the
2026-05-21 post-merge recovery pass live in the soyeht-ios repo:

1. **Bug 1** — iPhone Soyeht.app gets `URLError.-1022` on iPhone→Mac
   Caso B. Root cause is being narrowed via instrumentation. Strong
   hypothesis (≈85%, backed by Apple's `NSAllowsArbitraryLoads`
   reference) is the iOS Info.plist combo of
   `NSAllowsArbitraryLoads=true` + `NSAllowsLocalNetworking=true`
   silently disabling arbitrary loads.
2. **Bug 2** — Mac.app "Continue with this Mac" kills
   SetupInvitationListener prematurely. Pure Mac.app SwiftUI state-
   machine fix.

theyos engine code was inspected and found correct on this
branch's HEAD (`4abb72a`):

- `admin/rust/server-rs/src/tailnet_address.rs::build_mac_engine_url`
  formats `mac_engine_url` as `http://{ipv4}:{port}` (well-formed
  `http://100.103.149.48:8091` on Caio's Mac Studio).
- `admin/rust/server-rs/src/handlers_bootstrap.rs::post_claim_setup_invitation`
  emits the field into `ClaimSetupInvitationAck.mac_engine_url` with
  `#[serde(skip_serializing_if = "Option::is_none")]`.

## When this worktree gets activated

Only if the soyeht-ios Step 1.2 log capture reveals one of:

- The raw `mac_engine_url` JSON value from the engine is mis-shaped
  (zone id, percent-encoded host, IDN, unexpected scheme).
- The CBOR/JSON envelope on the wire mangles the URL between Rust
  `serde_json` encoding and Swift `JSONDecoder` parsing.

In either case the fix is in `tailnet_address.rs::build_mac_engine_url`
or the serializer of `ClaimSetupInvitationAck`, and a separate theyos PR
will be opened.

## When this worktree gets removed

If soyeht-ios logs show the URL on the wire is exactly
`http://100.103.149.48:8091` (well-formed), this worktree is removed
pre-commit:

```bash
cd /Users/macstudio/Documents/theyos
git worktree remove /Users/macstudio/Documents/theyos-recovery-fix --force
git branch -d fix/post-merge-recovery
```

…with Caio's explicit approval at the moment of removal (per system Bash
safety + memory `feedback_apple_quality_standard`).

## Build sanity (if activated)

```bash
cd /Users/macstudio/Documents/theyos-recovery-fix/admin/rust
cargo clippy -p server-rs --all-targets -- -D warnings
cargo test -p server-rs
```

## PR

If activated: separate theyos PR titled `fix(setup-invitation):
<observed issue from soyeht-ios instrumentation>`. Auto-merge disabled.
English-only.
