# kc-acl-spike (P0.3-C Tier 2 evidence tooling)

THROWAWAY local tooling to gather evidence for ONE blocked question on P0.3-C
Tier 2: does a macOS login-keychain generic-password item stay readable, without
a prompt and headless, by a re-signed build of the same app (same Team +
identifier)?

This is NOT shipped and NOT a CI test. It requires the Developer ID signing
identity (absent in CI). An ad-hoc-signed pair would have no stable Designated
Requirement (DR) and would always fail the cross-build read, so it cannot model a
release re-sign. Hence the representative run is local + operator-gated.

## Why this gates Stage B

Stage B of Tier 2 = move the software identity scalar into the Keychain and
DELETE the plaintext file. That is only safe if a future release (a re-signed
binary) can still read the item. The login-keychain ACL gates reads by the
caller's DR (roughly `identifier "X" and anchor apple generic and certificate
leaf[subject.OU] = TEAM`). If the DR is build-independent, a re-signed release
reads without a prompt -> works headless. If not, the re-signed engine gets
errSecInteractionNotAllowed (-25308) headless, cannot load identity, and refuses
to start. Because HH_priv / M_priv are random and non-re-derivable, a broken read
after the file is deleted is a PERMANENT lockout. So Stage B stays blocked until
this is known.

## Usage

- `./run-spike.sh --plan` (default): prints the representative plan; executes
  nothing. Safe.
- `./run-spike.sh --self-test`: builds and runs the UNSIGNED helper through a
  write/read/delete round-trip against the neutral service, then verifies the
  item is gone. Proves the tooling works WITHOUT the Developer ID. No DR test.
- `./run-spike.sh --run-representative`: the full A/B/C Developer ID test.
  OPERATOR-ONLY; refuses unless `KC_SPIKE_ALLOW_DEVID_SIGN=1`, because signing
  with the real identity can prompt for signing-key access.

The helper uses a neutral service `com.soyeht.theyos.acl-spike`, account `probe`,
and a synthetic non-secret value. It never touches the shipping app, the engine,
the LaunchAgent, the login-keychain lock state, or the real household keystore.
The item is deleted at the end.

## Pass criterion (DR-durability evidence)

- B (rebuilt, re-signed with the SAME Team + identifier as A) `read` returns
  `READ ok matches_probe=true` with NO prompt, in a non-interactive context.
- C (ad-hoc / different identifier) `read` is denied (osstatus -25308 / -25244)
  or prompts.

Together these show the ACL survives a re-sign and the gate is real.

## What this does NOT settle (still required before Stage B ships)

1. The REAL engine's signing identifier must be stable across releases (this
   spike uses a fixed identifier; confirm the engine target's identifier).
2. A verify-before-delete migration (designed in the Tier 2 STOP-POINT).
3. A recovery decision for the non-re-derivable keys if access is ever lost.
4. Out of scope here: keychain lock/unlock accessibility class (optional, use a
   throwaway keychain; never lock the login keychain), the
   `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` backup-restore residual
   (separate FFI follow-up), and real-fleet variance (MDM, separate keychain
   passwords, future macOS DR-semantics changes).
