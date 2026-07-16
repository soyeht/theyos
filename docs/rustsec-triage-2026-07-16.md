# RustSec Triage — 2026-07-16

## Purpose and boundary

This is a decision record for the RustSec findings observed against the Rust
workspace on 2026-07-16. It makes the routine, compatible lockfile updates
reviewable and records the unresolved items without silently weakening the
advisory policy.

This branch does **not** add or modify `deny.toml`, and in particular does
**not** add an ignore for `RUSTSEC-2023-0071`. An acceptance for that finding
is a decision for Caio, not an implementation-side default.

## Reproduction

The baseline used `cargo-deny 0.20.2`, the committed workspace lockfile, and
the review-candidate advisory policy from PR #357 solely as a read-only input
for its pre-existing APNs/WebPKI exceptions. This branch does not adopt that
policy file or change its exceptions.

```text
cargo deny --manifest-path admin/rust/Cargo.toml \
  --config <PR-357>/admin/rust/deny.toml \
  --workspace --all-features --locked check advisories
```

The baseline reported the five findings below. It also rejected the yanked
`spin` 0.9.8 lockfile entry; that is a package-status finding, not a RustSec
advisory. `spin` 0.10.0 is updated alongside it as a compatible routine
maintenance bump.

## Disposition

| Finding | Resolved package | Dependency / exposure summary | Disposition |
| --- | --- | --- | --- |
| `RUSTSEC-2026-0190` | `anyhow` 1.0.102 | General workspace error handling; advisory fixes mutable downcast after context. | Routine lockfile bump to 1.0.103. |
| `RUSTSEC-2026-0204` | `crossbeam-epoch` 0.9.18 | Reached by `criterion` / `rayon` development dependency paths. | Routine lockfile bump to 0.9.20. |
| `RUSTSEC-2024-0384` | `instant` 0.1.13 | `nostr` 0.43.1 through `nostr-relay-rs`; resolved only for `wasm32`, not the macOS/Linux engine target trees. | No compatible lock-only repair. Keep unaccepted; plan the reviewed `nostr` upgrade or replacement. |
| `RUSTSEC-2023-0071` | `rsa` 0.10.0-rc.16 | Transitive through `russh` in the local VM SSH client path. | **Decision required from Caio; no ignore is committed.** |
| `RUSTSEC-2025-0134` | `rustls-pemfile` 2.2.0 | Transitive through `a2` in the APNs HTTP/2 client path. | No compatible lock-only repair. Keep unaccepted; upgrade or replace `a2` under review. |

## Routine changes in this branch

The lockfile-only update makes these compatible selections:

| Package | Before | After | Reason |
| --- | --- | --- | --- |
| `anyhow` | 1.0.102 | 1.0.103 | Resolves `RUSTSEC-2026-0190`. |
| `crossbeam-epoch` | 0.9.18 | 0.9.20 | Resolves `RUSTSEC-2026-0204`. |
| `spin` | 0.9.8 | 0.9.9 | Removes the yanked 0.9 lockfile entry. |
| `spin` | 0.10.0 | 0.10.1 | Compatible companion maintenance bump. |

No first-party source, API, feature, or routing changed; these are lockfile
selections only. After the update, advisory checking reports only the three
intentionally unresolved items: `instant`, `rsa`, and `rustls-pemfile`.

## RSA / Marvin timing finding — DECISION REQUIRED FROM CAIO

`RUSTSEC-2023-0071` reports the Marvin timing side channel in
`rsa` 0.10.0-rc.16. The resolved path is
`rsa` → `internal-russh-forked-ssh-key` → `russh` 0.60.3. The repository uses
that line in the VM/image-builder SSH **client**, including production
`server-rs` through `vmrunner-rs`; it is not merely an e2e-only dependency.

Static review establishes a narrow current exposure, not absence of risk:

- `admin/rust/vmrunner-rs/src/ssh_client.rs` constructs a `russh::client` and
  connects only to `127.0.0.1:<ssh_port>` for Firecracker guest VMs.
- The e2e SSH helper has the same loopback-client shape in
  `admin/rust/e2e-rs/src/ssh.rs`.
- The VM host-forward model binds SSH to loopback (for example
  `admin/rust/vmrunner-rs/src/network.rs`), and this review found no
  `russh::server` use in the repository.

That scope reduces the remote-network exposure, but does not make the finding
safe by assertion. A local same-host process, a captured/reused loopback port,
or a malicious guest-side SSH endpoint may still be positioned to observe
timing. The client intentionally accepts any host key in this local-VM model,
so preserving the loopback/VM boundary is itself a security invariant.

There is no compatible patched `rsa` release to select lockfile-only. Caio
must choose one of the following explicitly before any policy exception is
added:

1. Temporarily accept the bounded local-VM client risk with an owner, review
   date, expiry, and regression coverage for the loopback-only invariant.
2. Fund a reviewed migration or feature change that removes the RSA/russh
   path.
3. Leave the advisory unaccepted and block a strict RustSec gate until an
   upstream-compatible remediation exists.

This document is not an acceptance and grants no authority to add an ignore.

## Unmaintained dependency follow-ups

`instant` is brought in by `nostr` 0.43.1 for `wasm32`; `cargo tree` finds no
instance for the macOS or Linux engine targets. It remains an advisory-policy
finding, so its eventual resolution should be a reviewed Nostr dependency
upgrade rather than an unscoped ignore.

`rustls-pemfile` is brought in only by `a2` 0.10.0. The workspace describes
`a2` as the Phase 3 APNs HTTP/2 transport and the dispatcher honors the
`THEYOS_PUSH_DISABLED=1` runtime kill switch. That is operational scope, not a
RustSec acceptance: the tracked remediation is a reviewed `a2` upgrade or
replacement.

## Merge runbook — #358 before RustSec

Both pending branches change `admin/rust`, so their independent boundary
entries cannot both describe the final main tree: #358 (`89ad9628`) pins
`ea98e49f…`; this RustSec branch (`d6518a6c`) pins `3f627f31…`. Merge #358
first because it is the engine foundation. Do not merge this branch against
the pre-#358 base.

After #358 lands, update the RustSec branch in this order:

```text
git fetch origin
git rebase origin/main

pin="$(git rev-parse HEAD:admin/rust)"
boundary="admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv"
awk -F '\t' -v OFS='\t' -v pin="$pin" '$4 == "admin/rust" { $3 = pin; found = 1 } { print } END { exit !found }' "$boundary" > "${boundary}.tmp"
mv "${boundary}.tmp" "$boundary"

git add "$boundary"
git commit -m "chore(phase0): reseal artifact boundary"
```

The exact recomputation is `git rev-parse HEAD:admin/rust`; run it only after
the rebase has completed. Verify the TSV before offering the rebased branch:

```text
test "$(git rev-parse HEAD:admin/rust)" = "$(awk -F '\t' '$4 == "admin/rust" { print $3 }' "$boundary")"
```

Only then run the required checks and merge the RustSec change. This current
documentation-only follow-up does not alter `admin/rust`; its existing
`3f627f31…` boundary pin remains valid for the current branch head.

## Validation expected for the branch

The validation record must show all of the following before this branch is
offered for human review:

1. `cargo-deny` no longer reports the routine `anyhow` and `crossbeam-epoch`
   advisories or the yanked `spin` 0.9.8 entry.
2. It reports exactly the three unresolved items named above, with no new
   policy ignore.
3. The appropriate locked local Rust test suite passes.
4. Because `admin/rust` changes, the owner-present Phase 0 artifact boundary
   is re-sealed to the resulting `admin/rust` tree in the same review branch.
