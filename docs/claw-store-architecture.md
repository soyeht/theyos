# Claw Store Architecture Map

This map is for agents making Claw Store changes across `theyos` and the Swift
client repo. It is not a replacement for the executable contract, tests, or
source code. When this document conflicts with the files below, treat the
source-of-truth files and guards as authoritative and update this map in the
same change.

Paths are written relative to their repo roots:

- `theyos/...` means this repo.
- `Swift/...` means the iOS/macOS client repo.

## Read This First

- Routes are owned in Rust, not in Swift.
- Swift contract files are vendored projections and must byte-match the Rust
  source contract.
- Household routes use proof-of-possession operations, not a generic mobile
  Bearer session.
- Terminal attach tokens authenticate only through the attach-token header, not
  URL query parameters.
- App UI must not invent endpoint resolvers or fall back to lossy household
  targets.
- Current Ready posture is HTTP plaintext on concrete loopback/Tailnet
  listeners. TLS is a future transport slice, not an implicit assumption.

## Source-Of-Truth Map

| Area | Current owner | Guard or consumer |
| --- | --- | --- |
| Route IDs, methods, paths, mounts, handlers | `theyos/admin/rust/server-rs/src/claw_store_routes.rs` | `theyos/admin/rust/server-rs/tests/claw_store_route_contract.rs` |
| Executable contract JSON | `theyos/admin/contracts/claw-store/v1/contract.json` | `claw_store_route_contract.rs`, `claw_store_wire_contract.rs`, Swift fixture sync |
| Household docs projection | `theyos/docs/contracts/claw-store-household-v1.json` | `theyos/admin/rust/server-rs/tests/household_contract_cross_check.rs` |
| Swift vendored contract fixture | `Swift/Packages/SoyehtCore/Tests/SoyehtCoreTests/Fixtures/claw-store/v1/contract.json` | `Swift/Packages/SoyehtCore/Tests/SoyehtCoreTests/ClawStoreContractFixtureTests.swift` |
| Swift endpoint paths by server kind | `Swift/Packages/SoyehtCore/Sources/SoyehtCore/API/ServerKind+Endpoint.swift` | `ClawStoreContractFixtureTests.swift`, `SoyehtAPIClientKindTests` |
| Swift Claw API bindings | `Swift/Packages/SoyehtCore/Sources/SoyehtCore/API/SoyehtAPIClient+Claws.swift` | `HouseholdAPIClientTests`, `ClawStoreContractFixtureTests.swift` |
| Admin and mobile HTTP mounts | `theyos/admin/rust/server-rs/src/main.rs` | Route contract tests and wire tests |
| Household Claw PoP wrappers | `theyos/admin/rust/server-rs/src/handlers_household_claws.rs` | `household_pop_gate_completeness.rs`, `claw_store_wire_contract.rs` |
| Guest-image prepare/status boundary | `theyos/admin/rust/server-rs/src/handlers_household_guest_image.rs`, `theyos/admin/rust/server-rs/src/guest_image_state.rs` | `household_exposure_policy_guard.rs`, Swift readiness tests |
| Install/uninstall action policy | `theyos/admin/rust/server-rs/src/claw_store_service.rs` | Wire tests and handler tests |
| Availability projection | `theyos/admin/rust/server-rs/src/availability.rs` | Claw list/availability route tests and Swift decoding tests |
| Instance create/list lifecycle and leases | `theyos/admin/rust/server-rs/src/handlers_instances.rs`, `theyos/admin/rust/store-rs/src/instance_db.rs` | Instance and lease tests |
| Swift inventory/polling | `Swift/Packages/SoyehtCore/Sources/SoyehtCore/ClawStore/ClawInventoryService.swift` | `ClawInventoryServiceTests`, view-model adoption tests |
| Swift Claw Store view model target identity | `Swift/Packages/SoyehtCore/Sources/SoyehtCore/ClawStore/ClawStoreViewModel.swift` | `ClawStoreViewModelTargetTests`, source guards |
| iOS install target resolver | `Swift/TerminalApp/Soyeht/ClawStore/ClawInstallTargetResolver.swift` | `Swift/TerminalApp/SoyehtTests/ClawRouteUsageTests.swift` |
| iOS/macOS legacy boundary guards | `Swift/TerminalApp/SoyehtTests/LegacyBoundaryUsageTests.swift` | App source scans |
| Ready bind posture | `theyos/docs/household-bind-posture.md` | `theyos/admin/rust/server-rs/tests/household_exposure_policy_guard.rs` |
| macOS runner artifact posture | `theyos/docs/macos-setup.md` | Runner resolver and wrapper tests |

## Contract Change Flow

1. Add or change the route in
   `theyos/admin/rust/server-rs/src/claw_store_routes.rs`.
2. Keep `theyos/admin/contracts/claw-store/v1/contract.json` in agreement with
   the Rust registry. The route contract test is the executable guard.
3. If the route is household-facing, keep
   `theyos/docs/contracts/claw-store-household-v1.json` as a projection of the
   executable contract. The household cross-check compares IDs, methods, paths,
   operations, auth, and peer guard.
4. Do not edit Swift vendored fixtures by hand. Sync from `theyos`, then run the
   Swift fixture check.
5. Update Swift bindings only after the Rust contract is stable and the
   vendored fixture byte-matches the Rust source.

Current expected counts on this branch:

```sh
jq '.routes | length' admin/contracts/claw-store/v1/contract.json
# 41
jq '.routes | length' docs/contracts/claw-store-household-v1.json
# 17
```

## Auth Boundaries

| Surface | Auth boundary | Notes |
| --- | --- | --- |
| Admin host | `admin_session` / `AdminUser` | Admin handlers may share post-auth business logic with mobile handlers, but must not call mobile handlers that extract Bearer auth. |
| Mobile app | mobile Bearer session | Mobile endpoints stay under the mobile surface and apply mobile role checks. |
| Household Claw routes | household PoP with a declared operation | PoP wrappers authorize the specific operation before calling shared business logic. |
| Terminal attach/PTY | short-lived attach token header plus peer policy | Query-string tokens are intentionally ignored and must not consume the token. |
| Bootstrap/status and health posture | documented per route in `docs/household-bind-posture.md` | Some status routes are intentionally no-auth, so transport/bind posture is part of the boundary. |

Do not collapse these boundaries into one generic auth helper unless the route
contract, wire tests, and posture docs move together.

## Install, Create, And Inventory Flow

The backend action policy lives in `claw_store_service.rs`. Surface-specific
handlers are auth adapters; they should delegate to shared post-auth logic for
manifest lookup, installability, status, job creation, and install/uninstall
mutation.

Create/list lifecycle runs through `handlers_instances.rs` and the typed lease
APIs in `store-rs/src/instance_db.rs`. Capacity checks, active runtime/storage
leases, and macOS slot counts belong there, not in Swift UI code.

Swift inventory should flow through `ClawInventoryService`. It owns catalog and
instance fetches, online filtering, and polling. New app screens should not add
parallel fetch/filter/poll loops.

## Guest-Image Readiness

Rust exposes guest-image state through `guest_image_state.rs`,
`handlers_household_guest_image.rs`, and `/bootstrap/status`. Swift maps that to
UI readiness through `GuestImageReadinessGate.swift` and the macOS readiness and
recovery models.

Linux hosts can be ready without a macOS guest image. macOS install/deploy flows
must respect the readiness gate before presenting install actions as available.

## macOS Runner Artifact Posture

The macOS runner path is documented in `docs/macos-setup.md`:

- `server-rs -> executor-rs -> vmrunner-macos-rs -> Virtualization.framework`.
- `THEYOS_VMRUNNER_RS_BIN` is the canonical override.
- `THEYOS_VMRUNNER_MACOS_RS_BIN` remains a temporary legacy fallback.
- `vmrunner_macos_ipc` must be signed with the Virtualization entitlement after
  rebuilds.

Do not change runner environment names, signing posture, or socket behavior from
Claw Store docs. Make those changes in focused runner slices with tests.

## Artifact Signature Provenance (P0.1)

Registry manifests can carry a detached signature. The mechanics are in place;
production enforcement is still blocked on a real public key, custody, and policy,
so `ArtifactResolver::new` keeps the unsigned status quo until then.

- `core-rs/src/artifact_signature.rs` verifies a detached P-256 signature over the
  exact `latest.json` bytes; `core-rs/src/artifact_trust.rs` holds the keyring
  (`current`/`next` plus revoked `key_id`s) and the `Required` /
  `OptionalIfAbsent` trust mode. `imagebuilder sign-manifest` writes
  `latest.json.sig.json` from an external signer; the private key never enters the
  process.
- `server-rs/src/artifact_resolver.rs` verifies `latest.json.sig.json` against the
  configured keyring BEFORE parsing the manifest, but only when a trust config is
  supplied via `with_trust`. `new()` (no trust) is the deferred status quo, not a
  signed-but-permissive mode - do not describe it as a signature policy.

Provenance rules (hold these when extending the resolver, a cache, or install flow):

- A local golden (`golden.meta.json` / the installed `rootfs.ext4`) is a cache of
  an already-installed artifact, NOT registry provenance. It does not stand in for
  a verified `latest.json` plus signature.
- A remote registry being unavailable does NOT authorize an unsigned fallback. A
  missing `latest.json.sig.json` (HTTP 404) is "absent" for the trust mode; any
  other fetch error fails closed.
- Unsigned manifests are accepted only for a strictly loopback/local host
  (`localhost`, `127.0.0.0/8`, `::1`) with an explicit `allow_unsigned_loopback`
  override. The override never relaxes a remote, LAN, tailnet, or public host.
- A future persistent manifest cache may only store a `latest.json` plus
  `latest.json.sig.json` pair that was already verified, and must re-verify it
  against the current keyring on read. It must never cache or serve an unsigned or
  unverified remote manifest.

## Swift App Boundaries

Swift has three different concepts that must not be mixed:

- `ClawInstallTarget` is the app/UI vocabulary.
- `ClawMachineTarget` is the stable machine identity for shared view models.
- `ClawAPITarget` is the SoyehtCore wire target.

Only `ClawInstallTargetResolver.swift` should bridge iOS UI selection into
household wire targets. macOS Claw Store screens should pass resolved machine
targets through their root/detail views.

Use these guards when changing Swift routing or legacy access:

- `Swift/TerminalApp/SoyehtTests/ClawRouteUsageTests.swift`
- `Swift/TerminalApp/SoyehtTests/LegacyBoundaryUsageTests.swift`

## Do Not Edit Or Invent

- Do not hand-edit Swift contract fixtures. Sync them from the Rust contract.
- Do not invent route strings in handlers or Swift clients. Add them to the
  Rust route registry first.
- Do not add a new UI endpoint resolver. Use the existing resolver and endpoint
  policy files.
- Do not add `?? .household` fallback behavior.
- Do not construct household routes directly in new UI code.
- Do not duplicate Claw inventory fetch/filter/poll logic outside
  `ClawInventoryService`.
- Do not pass attach tokens in URLs or accept query tokens as auth.
- Do not assume TLS exists on household listeners. The current posture is HTTP
  plaintext on concrete loopback/Tailnet listeners.
- Do not use old plan documents as current architecture truth when they conflict
  with executable contracts, guards, or this map.

## Historical Documents

These files can be useful for context, but they are planning or follow-up docs
and are not current source of truth when they conflict with the files listed
above:

- `Swift/docs/claw-store-score-plan.md`
- `Swift/docs/claw-store-execution-plan.md`
- `Swift/docs/mac-adminhost-routing-follow-up.md`
- `theyos/docs/followup-phase3-cross-repo-contract-drift.md`
- `theyos/docs/followup-ios-claw-installability-fields.md`

## Validation Matrix

Run Rust commands from the `theyos` repo root:

```sh
cargo fmt --all --manifest-path admin/rust/Cargo.toml
cargo test -p server-rs --test claw_store_route_contract --manifest-path admin/rust/Cargo.toml
cargo test -p server-rs --test claw_store_wire_contract --manifest-path admin/rust/Cargo.toml
cargo test -p server-rs --test household_contract_cross_check --manifest-path admin/rust/Cargo.toml
cargo test -p server-rs --test household_pop_gate_completeness --manifest-path admin/rust/Cargo.toml
cargo test -p server-rs --test household_exposure_policy_guard --manifest-path admin/rust/Cargo.toml
git diff --check
```

Run Swift commands from the Swift repo root:

```sh
THEYOS_DIR=<path-to-theyos> scripts/check-cross-repo-fixtures.sh
SOYEHT_SYNC_ONLY=claw-store THEYOS_DIR=<path-to-theyos> scripts/sync-cross-repo-fixtures.sh
swift test --package-path Packages/SoyehtCore --filter 'ClawStoreContractFixtureTests|SoyehtAPIClientKindTests|HouseholdAPIClientTests|ClawInventoryServiceTests|ClawStoreViewModelTargetTests|ClawStoreViewModelServiceAdoptionTests|GuestImageReadinessTests|GuestImagePrepareClientTests'
```

When the full app harness is available, also run the closest filters for:

```sh
ClawRouteUsageTests|LegacyBoundaryUsageTests
InstalledClawsProviderTests|InstalledClawsProviderServiceAdoptionTests|MacClawInstallDecisionTests|MacGuestImageReadinessGateTests|MacGuestImageRecoveryTests
```

For documentation-only changes to this file, run:

```sh
git diff --check
git diff -U0 -- docs/claw-store-architecture.md | rg -nP '^\+.*[^\x00-\x7F]' || true
```
