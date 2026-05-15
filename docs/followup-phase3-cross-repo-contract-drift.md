# Follow-up: Phase 3 cross-repo contract drift (T099)

T099 asks for byte-for-byte parity between
`specs/003-machine-join/contracts/` on theyos and the matching directory
on `iSoyehtTerm`. The audit ran on 2026-05-08 against
`/Users/macstudio/Documents/SwiftProjects/iSoyehtTerm/specs/003-machine-join/contracts/`.
Result: **the contracts are NOT byte-equivalent**, but they describe
semantically the same wire formats. Two true blockers below; everything
else is documentation drift that should be reconciled before Phase 3
lands on `main`.

## Symptom

`diff theyos/.../contracts/pair-machine-url.md iSoyehtTerm/.../contracts/pair-machine-url.md`
produces non-trivial output. The same is true for every contract that
exists on both sides. Most of the divergence is stylistic (ABNF grammar
on the iSoyehtTerm side vs. less formal examples on theyos), but at
least one substantive difference is a real protocol gap.

## What works vs. fails

**Works** (T094 verified 2026-05-08):

- `specs/003-machine-join/tests/fingerprint_vectors.json` is byte-for-
  byte identical between the two repos. iSoyehtTerm's
  `OperatorFingerprintTests.crossRepoFingerprintBindingMatchesTheyos`
  test target passes against the same 16 entries. BIP-39 derivation is
  cross-repo deterministic.

**Fails** (cross-repo blockers):

1. **iSoyehtTerm `pair-machine-url.md` is missing `anchor_secret`.**
   theyos's post-B7 (PR #28) version of the contract requires the QR
   to include `&anchor_secret=<base64url no-pad of 32 random bytes>`
   AND the iPhone to deliver it via `POST /pair-machine/local/anchor`
   before M2 will accept the finalize POST. iSoyehtTerm's contract
   does not mention `anchor_secret` at all (`grep -c anchor_secret`
   returns `0` against the iSoyehtTerm file vs. `4` on theyos).
   Without this, an iSoyehtTerm-shaped client cannot complete a
   modern Phase 3 ceremony — the candidate will reject `local/finalize`
   with `trust_anchor_missing`.

2. **Contract file naming has diverged.** T099 enumerates four
   contract names theyos and iSoyehtTerm should agree on:
   `pair-machine-url`, `owner-events-client`, `fingerprint-derivation`,
   `apns-opacity`.

   Only `pair-machine-url` exists on both sides. The others have
   different names:

   | T099 contract name        | theyos file                        | iSoyehtTerm file                       |
   |---------------------------|------------------------------------|----------------------------------------|
   | `pair-machine-url`        | `pair-machine-url.md`              | `pair-machine-url.md`                  |
   | `owner-events-client`     | `owner-events.md`                  | `owner-events-long-poll.md`            |
   | `fingerprint-derivation`  | `fingerprint-derivation.md`        | (missing — derived from spec body?)    |
   | `apns-opacity`            | (semantics in `owner-events.md`)   | `apns-registration.md`                 |

   The iSoyehtTerm side also carries `household-gossip-consumer.md`,
   `household-snapshot.md`, and `operator-authorization.md`, none of
   which have a theyos analog under `contracts/` (some of the
   semantics live in `docs/household-protocol.md` instead).

## Diagnostic recipe

```bash
# Confirm the fingerprint vectors round-trip (PASS):
diff specs/003-machine-join/tests/fingerprint_vectors.json \
     /Users/macstudio/Documents/SwiftProjects/iSoyehtTerm/Packages/SoyehtCore/Tests/SoyehtCoreTests/HouseholdFixtures/MachineJoin/fingerprint_vectors.json
# (no output expected)

cd /Users/macstudio/Documents/SwiftProjects/iSoyehtTerm/Packages/SoyehtCore
swift test --filter OperatorFingerprintTests
# expect 8/8 pass, including crossRepoFingerprintBindingMatchesTheyos

# Confirm the anchor_secret gap on iSoyehtTerm (FAIL):
grep -c anchor_secret /Users/macstudio/Documents/SwiftProjects/iSoyehtTerm/specs/003-machine-join/contracts/pair-machine-url.md
# expect 0 (broken)

grep -c anchor_secret specs/003-machine-join/contracts/pair-machine-url.md
# expect ≥ 4

# List the contract-name set on each side:
ls specs/003-machine-join/contracts/
ls /Users/macstudio/Documents/SwiftProjects/iSoyehtTerm/specs/003-machine-join/contracts/
```

## Workarounds

- For Phase 3 launch on `main`: the theyos-side implementation is
  authoritative and tested against the failure-injection harness
  (T067-T072 + T080 + T096). An iSoyehtTerm client that does not
  implement `anchor_secret` will fail closed at `local/finalize`
  with `trust_anchor_missing` — not a security regression.

- For an iPhone partner shipping ahead of the contract reconciliation:
  pin the operating constraint that the iPhone client MUST mint the
  32-byte `anchor_secret`, embed it in the QR, and POST it to M2's
  `/pair-machine/local/anchor` before submitting `OwnerApproval`. The
  theyos-side contract at `contracts/local-anchor.md` is the
  authoritative spec for that flow.

## Likely causes

The contracts diverged when iSoyehtTerm was authored from an earlier
revision of the theyos contracts (before B7 / PR #28 introduced
`anchor_secret`). The iSoyehtTerm-side ABNF grammar was hand-written
rather than copied verbatim, so the documents have always been
parallel rather than derived.

## Files of interest

- `specs/003-machine-join/contracts/pair-machine-url.md` (theyos)
- `specs/003-machine-join/contracts/local-anchor.md` (theyos, B7)
- `/Users/macstudio/Documents/SwiftProjects/iSoyehtTerm/specs/003-machine-join/contracts/pair-machine-url.md`
- `/Users/macstudio/Documents/SwiftProjects/iSoyehtTerm/Packages/SoyehtCore/Tests/SoyehtCoreTests/OperatorFingerprintTests.swift`
- `specs/003-machine-join/tasks.md` (T094, T099)

## Status

- T094: PASSING (fingerprint vectors byte-equivalent + Swift target green)
- T099 byte-for-byte: FAILING — see blockers above. Track until
  iSoyehtTerm publishes a contract sync that:
    1. Adds `anchor_secret` and `local-anchor.md` semantics.
    2. Renames or aliases its contract files to match theyos (or
       theyos accepts iSoyehtTerm's naming).
