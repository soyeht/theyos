# Claw Store cross-repo contract

How the Claw Store wire contract is kept in sync between **theyos** (the Rust
backend / engine) and **soyeht-ios** (the Swift iOS + macOS apps). This is the
runbook for the CI drift guards in this directory's neighbourhood.

## Source of truth

The contract is authored **here, in theyos**:

- `admin/contracts/claw-store/v1/contract.json` — the Claw Store wire contract.
- `admin/contracts/store/`, `admin/contracts/terminal/`, … — sibling contracts.

The Rust handlers/types are checked against these fixtures by the contract test
suite under `admin/rust/server-rs/tests/` (e.g. `claw_store_wire_contract.rs`,
`claw_store_route_contract.rs`, `household_contract_cross_check.rs`).

## Vendored Swift copy

soyeht-ios vendors a byte-for-byte copy of the theyos contract as a Swift test
fixture and decodes it to prove the Swift models match:

- `soyeht-ios: Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/claw-store/v1/contract.json`
- exercised by `soyeht-ios: Packages/SoyehtCore/Tests/SoyehtCoreTests/ClawStoreContractFixtureTests.swift`

## The pin

soyeht-ios records the exact theyos commit the vendored fixtures were synced
from:

- `soyeht-ios: scripts/cross-repo-contract.sha`

The pin is audit metadata recording the synced point; the enforced invariant is
**vendored fixture == theyos contract at the pinned commit**. A contract file
that does not yet exist at the pinned commit is reported as a *skip* (not a
failure), so each contract activates as it lands and the pin is bumped.

## Sync / check commands (run in the soyeht-ios checkout)

Refresh the vendored fixtures from a local theyos checkout:

```sh
THEYOS_DIR=/path/to/theyos scripts/sync-cross-repo-fixtures.sh
# or only one group:
SOYEHT_SYNC_ONLY=claw-store THEYOS_DIR=/path/to/theyos scripts/sync-cross-repo-fixtures.sh
```

Verify the vendored fixtures match theyos at the pinned commit (this is what CI
runs):

```sh
scripts/check-cross-repo-fixtures.sh
```

## CI guards (symmetric, one per repo)

- **soyeht-ios:** `.github/workflows/contract-fixture-sync.yml` byte-diffs every
  vendored fixture against theyos at the pinned commit, on PRs that touch the
  fixtures, the sync/check scripts, or the pin.
- **theyos:** `.github/workflows/contracts-cross-repo-sync.yml` scans the
  soyeht-ios markdown contract mirrors and diffs them against `theyos@HEAD`, on
  theyos PRs.

## Who bumps the pin, and when

Whoever lands a contract change in theyos (`admin/contracts/…`) is responsible
for the soyeht-ios side in the same change set:

1. Bump `soyeht-ios: scripts/cross-repo-contract.sha` to the new theyos commit.
2. Re-run `scripts/sync-cross-repo-fixtures.sh` to refresh the vendored fixtures.
3. Land the refreshed fixtures (and any Swift model updates) in the companion
   soyeht-ios PR.

Until both sides land, the iOS byte-diff guard fails (or skips, for a contract
not yet present at the pin), surfacing the drift instead of letting it ship
silently.

## Repo naming — do not confuse with the old repo

The live iOS repository is **`soyeht/soyeht-ios`**. The old name
**`soyeht/iSoyehtTerm`** is a *separate, stale* repository and must not be the
target of any CI checkout, script, or doc. The theyos
`contracts-cross-repo-sync.yml` workflow checkout is pinned to
`soyeht/soyeht-ios` for exactly this reason.
