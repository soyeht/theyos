# Follow-up: macOS Secure Enclave Keychain ACL breaks on every release

**Status:** in progress — addressed by branch
`feat/release-macos-codesign`. Plan at
`~/.claude/plans/giggly-knitting-meadow.md`. The branch ships Developer
ID code-signing (with explicit `--identifier` + hardened runtime +
notarization) so the Keychain ACL anchors to the cert chain, stable
across rebuilds. After that branch lands and a release is cut from it,
this followup is closed.
**Discovered:** 2026-05-08 during PR #42 B-5 hardware walkthrough
(server-side smoke on Mac macOS 26).
**Severity:** blocking for normal `brew upgrade theyos` flow on hosts
that use Secure Enclave-backed keys (production default on
SE-equipped hardware).
**Owner:** backend (`@agente-backend`).

## Dual-nature update (2026-05-08, post-discovery)

External plan review surfaced that this followup conflates **two
distinct sub-bugs** that share the symptom:

1. **cdhash drift on SE-default installs.** Each ad-hoc-rebuild of the
   daemon binary produces a new `cdhash`; the Keychain ACL on the SE
   item created by the previous binary's cdhash refuses the new one.
   Fixed by `feat/release-macos-codesign` (Developer ID stable
   identifier + cert chain → ACL no longer cdhash-bound).

2. **Policy mismatch on file-default installs.** When the original
   `theyos install` ran with `THEYOS_FORCE_SOFTWARE_KEYS=1`, file-based
   keys were created under `~/.theyos/household-state/household/secrets/*.bin`
   with no SE item ever existing. Subsequent daemon starts with the env
   var **unset** look at the SE path (per the cfg-gated
   `bootstrap.rs::read_existing_machine_key` macOS branch),
   `errSecItemNotFound`, panic. Fixed today by keeping the env var set
   in the launchd plist (consistent with `specs/003-machine-join/spec.md:80`
   which mandates the flag for Phase 3 anyway). A future code change
   could add a `errSecItemNotFound → file fallback` safety net (Phase 8
   in the plan) to remove the env-var dependency.

## Phase 3 machine-join SE carve-out (NOT resolved by Developer ID)

`specs/003-machine-join/spec.md:80` (FR-002) requires the raw `M_priv`
scalar for ECDH-based shard decryption. Apple's Secure Enclave by
design will not release the raw scalar — it only exposes signing/ECDH
on the opaque SE handle. So Phase 3 machines **must** run with
`THEYOS_FORCE_SOFTWARE_KEYS=1` on macOS regardless of code-signing.
Developer ID resolves the cdhash-drift sub-bug, NOT this constraint.
Future work: introduce a threshold-signature primitive that operates
on the SE handle without exporting bytes, then revisit FR-002.

## Symptom

After `make.sh package` builds v0.1.6 and the new binaries replace
v0.1.5 in `/opt/homebrew/opt/theyos/libexec/`, the daemon panics on
startup:

```
thread 'main' panicked at server-rs/src/household_bootstrap.rs:131:17:
household identity load failed: keystore failure during
keystore.read.machine: keystore I/O error: Error { code: -25300,
message: "The specified item could not be found in the keychain." }:
Check that theyos can read its Secure Enclave key from the Keychain.
```

`errSecItemNotFound = -25300`. The item *exists* in the user's
Keychain (created at first `theyos install` under v0.1.5), but the
new v0.1.6 binary cannot read it.

## Reproduction environment

| Item | Value |
|---|---|
| OS | macOS 26 (Mac, `Darwin 25.4.0`) |
| theyos prior | 0.1.5 (installed via `brew install`, daemon running) |
| theyos new | 0.1.6 (built via `make.sh package`, replaces libexec/ binaries) |
| Codesign mode | ad-hoc (`flags=0x20002(adhoc,linker-signed)`) |
| Identifier match | re-signed manually to v0.1.5's identifier; **still failed** |
| `THEYOS_FORCE_SOFTWARE_KEYS=1` | bypasses the issue (uses file-based keys instead) |

## Root cause analysis

macOS Keychain access for Secure Enclave-backed items is gated by the
calling process's **DesignatedRequirement** (DR), which for ad-hoc
binaries is usually `cdhash H"<sha256-of-mach-o>"`. The `cdhash` is
content-addressed, so any rebuild produces a different cdhash even
when the identifier is held stable via `codesign --identifier`.

Concretely: v0.1.5's `server` binary was ad-hoc-signed with a specific
cdhash; the SE key's ACL was bound to that DR. v0.1.6's `server` has
a new cdhash (new compile = new content). The Keychain returns
`errSecItemNotFound` rather than a permission-denied error to avoid
leaking the item's existence to non-privileged callers — that's why
the symptom looks like the item is missing.

`codesign --force --identifier server-09e6d641275b0465` keeps the
identifier stable but does NOT roll the cdhash back, so the DR
mismatch persists.

## Why this matters for the v0.1.6 release

Any user who installed v0.1.5 via `brew install theyos` and runs
`brew upgrade theyos` to land v0.1.6 will hit the same panic on the
first daemon start after the upgrade. Their household identity is
stored in the SE; the new binary cannot read it; the daemon refuses
to come up.

This is a **release-blocking** issue. v0.1.6 cannot ship until either
(a) the rebuild produces a binary that the existing SE ACL accepts,
or (b) we provide a documented upgrade path that handles the ACL
re-grant.

## Proposed fix paths (pick one before tagging v0.1.6)

1. **Stable Apple Developer code-signing.** Sign release builds with
   a Developer ID certificate so the DesignatedRequirement is
   `anchor apple generic and certificate leaf [stable cert]`,
   independent of cdhash. Standard practice for Mac apps that touch
   SE. Requires us to register a Developer ID and ship the formula
   with notarization. Highest effort, most correct.
2. **Re-grant the ACL on upgrade.** Detect `errSecItemNotFound` at
   startup, prompt the user (or the next `theyos install
   --reissue-keychain-acl` flow) to re-grant access. The SE key
   itself can stay; only the ACL needs to be updated. Requires SE
   item re-creation with a new ACL (may break-and-recreate the SE
   keypair, losing identity continuity).
3. **Move household keys off SE for release builds.** Set
   `THEYOS_FORCE_SOFTWARE_KEYS=1` by default in the brew formula's
   plist. File-based keys avoid the entire SE-cdhash issue. Trade-off:
   loss of SE-backed unphishable signatures.
4. **Per-release Keychain namespace.** Tag SE items with the version
   number in the label (e.g., `com.soyeht.theyos.0.1.5.machine.<m_id>`).
   On upgrade, migrate items to the new label. Data continuity but
   a one-time prompt on every upgrade.

Recommendation: **(1) stable Developer ID signing**. Aligns with
"Apple-grade" path memory rule. Other paths are workarounds.

## Workaround (current B-5 only)

For the in-flight B-5 walkthrough on Mac, edited the launchd
plist to set `THEYOS_FORCE_SOFTWARE_KEYS=1`:

```sh
/usr/libexec/PlistBuddy \
  -c "Add :EnvironmentVariables:THEYOS_FORCE_SOFTWARE_KEYS string 1" \
  /opt/homebrew/opt/theyos/homebrew.mxcl.theyos.plist
launchctl bootout user/$(id -u)/homebrew.mxcl.theyos
launchctl bootstrap user/$(id -u) /opt/homebrew/opt/theyos/homebrew.mxcl.theyos.plist
```

This makes the daemon read the file-based keys present at
`~/.theyos/household-state/household/secrets/*.bin` instead of
attempting SE access. Confirmed working: daemon up, Bonjour
publishing, T046 fix validated end-to-end.

After v0.1.6 ships with one of the proposed fixes, **revert the plist
edit** and verify the daemon starts cleanly without
`THEYOS_FORCE_SOFTWARE_KEYS`.

## Files of interest

- `admin/rust/household-rs/src/keystore.rs` — keychain item label scheme.
- `admin/rust/household-rs/src/keys_se.rs` — SE-backed keypair impl.
- `admin/rust/server-rs/src/household_bootstrap.rs:131` — the panic
  site.
- `scripts/make.sh` — codesigning flow (only signs `vmrunner_macos_ipc`
  with VZ entitlement; the rest are ad-hoc-signed by the linker).
- `homebrew/Formula/theyos.rb` — formula's launchd block (where the
  env var or stable signing would land).

## When to delete this doc

When `brew upgrade theyos` from any prior version to v0.1.7+ starts
the daemon cleanly without the panic AND without
`THEYOS_FORCE_SOFTWARE_KEYS=1` set, on at least one Mac that originally
installed via SE-default install path.
