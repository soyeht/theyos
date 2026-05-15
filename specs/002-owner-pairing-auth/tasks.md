# Tasks: Phase 2 - Owner Pairing and Proof-of-Possession Auth (theyOS)

**Input**: Design documents from `/specs/002-owner-pairing-auth/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md
**Tests**: REQUIRED by protocol-boundary success criteria and constitution.
**Organization**: Tasks are grouped by user story so each story can be implemented and tested independently.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel with other `[P]` tasks in the same phase when files do not overlap.
- **[Story]**: Maps to User Story 1, 2, or 3 from spec.md.
- Paths are absolute under `/Users/macstudio/Documents/theyos/`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Register Phase 2 modules and fixtures without changing behavior.

- [X] T001 Register new `household-rs` modules `person_cert`, `owner_auth`, `pop`, and `caveats` in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/src/lib.rs`
- [X] T002 [P] Add Phase 2 protocol fixture directory and README in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/tests/fixtures/phase2/README.md`
- [X] T003 [P] Add Phase 2 e2e helper scaffold for pairing proof and signed request generation in `/Users/macstudio/Documents/theyos/admin/rust/e2e-rs/tests/phase2_helpers.rs`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared protocol types and validation primitives required by all user stories.

**CRITICAL**: No user story work can begin until this phase is complete.

- [X] T004 [P] Implement `PairingProofContext`, `RequestSigningContext`, canonical CBOR signing bytes, and signature verification helpers in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/src/pop.rs`
- [X] T005 [P] Add unit tests for pairing proof and request signing context canonical bytes in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/tests/pop.rs`
- [X] T006 [P] Implement `PersonCert`, unsigned signing payload, `PersonCert::sign_owner`, and `PersonCert::verify` in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/src/person_cert.rs`
- [X] T007 [P] Add PersonCert sign/verify/tamper tests and no-DeviceCert invariant tests in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/tests/person_cert.rs`
- [X] T008 [P] Implement owner caveat template and caveat evaluator for household operations in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/src/caveats.rs`
- [X] T009 [P] Add caveat template/evaluator tests in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/tests/caveats.rs`
- [X] T010 Implement `HouseholdAuthState`, owner cert storage paths, atomic load/save, and tamper refusal in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/src/owner_auth.rs`
- [X] T011 Update household storage path helpers for `owner_person_cert.cbor` and `household_auth_state.cbor` in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/src/storage.rs`
- [X] T012 [P] Add owner auth-state persistence and tamper tests in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/tests/owner_auth.rs`
- [X] T013 Promote Phase 2 public exports in `/Users/macstudio/Documents/theyos/admin/rust/household-rs/src/lib.rs`

**Checkpoint**: PersonCert, pairing proof, PoP context, caveats, and owner auth-state storage are testable without HTTP.

---

## Phase 3: User Story 1 - First owner claims the household (Priority: P1) MVP

**Goal**: A valid Soyeht iPhone pairing confirmation consumes the active pair token and returns exactly one owner PersonCert.

**Independent Test**: Start from an active Phase 1 pair window, submit a valid confirmation, verify one PersonCert is returned, the token is consumed, and no DeviceCert exists.

### Tests for User Story 1

- [X] T014 [P] [US1] Add pair-device confirm contract tests for success, no active window, wrong nonce, malformed public key, invalid proof, and no DeviceCert response in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/tests/phase2_pair_device_confirm.rs`
- [X] T015 [P] [US1] Add e2e first-owner pairing test for valid confirm under 10 seconds, token consumption, and persisted owner cert in `/Users/macstudio/Documents/theyos/admin/rust/e2e-rs/tests/phase2_owner_pairing.rs`
- [X] T016 [P] [US1] Add e2e concurrent-confirm test asserting exactly one success among 100 attempts in `/Users/macstudio/Documents/theyos/admin/rust/e2e-rs/tests/phase2_owner_pairing_concurrency.rs`

### Implementation for User Story 1

- [X] T017 [US1] Replace Phase 1 confirm stub with `PairDeviceConfirmRequest` parsing and generic failure responses in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/handlers_pair_device.rs`
- [X] T018 [US1] Verify pairing proof against submitted `p_pub`, local `hh_id`, and active nonce in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/handlers_pair_device.rs`
- [X] T019 [US1] Implement atomic first-owner issuance orchestration using `PairWindow::consume_token`, `PersonCert::sign_owner`, and `HouseholdAuthState::save` in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/handlers_pair_device.rs`
- [X] T020 [US1] Add first-owner-already-paired refusal path before token consumption in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/handlers_pair_device.rs`
- [X] T021 [US1] Emit structured security logs for pairing success/failure without raw nonce/signature material in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/handlers_pair_device.rs`

**Checkpoint**: User Story 1 is independently complete when T014-T021 pass.

---

## Phase 4: User Story 2 - Owner authenticates with proof of possession (Priority: P2)

**Goal**: Household-scoped authenticated operations accept Soyeht-PoP signatures from the owner PersonCert and reject bearer-only requests.

**Independent Test**: Pair once, send a signed owner request and a bearer-only request to the same household-scoped route, and verify only the signed request is evaluated.

### Tests for User Story 2

- [X] T022 [P] [US2] Add PoP header parsing and request-context contract tests in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/tests/phase2_pop_auth.rs`
- [X] T023 [P] [US2] Add e2e valid/stale/replayed/tampered/wrong-path PoP request tests in `/Users/macstudio/Documents/theyos/admin/rust/e2e-rs/tests/phase2_pop_auth.rs`
- [X] T024 [P] [US2] Add bearer-only rejection tests for household-scoped authenticated routes in `/Users/macstudio/Documents/theyos/admin/rust/e2e-rs/tests/phase2_bearer_rejection.rs`

### Implementation for User Story 2

- [X] T025 [US2] Implement `SoyehtPoP` parser and typed auth errors in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/household_auth.rs`
- [X] T026 [US2] Implement axum extractor/middleware that loads `HouseholdAuthState`, verifies PersonCert chain, verifies request signature, checks ±60s timestamp, and evaluates caveats in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/household_auth.rs`
- [X] T027 [US2] Register `household_auth` module in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/lib.rs`
- [X] T028 [US2] Add a minimal authenticated household test route or snapshot route protected by `SoyehtPoP` in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/handlers_household.rs`
- [X] T029 [US2] Ensure bearer auth is not accepted by household-scoped authenticated routes while public identity remains unauthenticated in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/household_bootstrap.rs`
- [X] T030 [US2] Emit structured accepted/rejected PoP logs without raw signatures in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/household_auth.rs`

**Checkpoint**: User Story 2 is independently complete when T022-T030 pass.

---

## Phase 5: User Story 3 - Household auth state survives restart (Priority: P3)

**Goal**: theyOS reloads the same owner PersonCert after restart and refuses tampered auth state.

**Independent Test**: Pair once, restart theyOS repeatedly, verify the same cert remains valid for PoP checks, then tamper with storage and verify trust is refused.

### Tests for User Story 3

- [X] T031 [P] [US3] Add 50-cycle owner auth restart e2e test in `/Users/macstudio/Documents/theyos/admin/rust/e2e-rs/tests/phase2_owner_auth_restart.rs`
- [X] T032 [P] [US3] Add tampered owner auth-state startup/load refusal test in `/Users/macstudio/Documents/theyos/admin/rust/e2e-rs/tests/phase2_owner_auth_tamper.rs`

### Implementation for User Story 3

- [X] T033 [US3] Load and validate `HouseholdAuthState` during household bootstrap hot-load in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/household_bootstrap.rs`
- [X] T034 [US3] Add shared server state for validated owner auth alongside `HouseholdState` in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/household_state.rs`
- [X] T035 [US3] Refuse to treat tampered or mismatched owner auth state as trusted without regenerating certs in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/household_bootstrap.rs`
- [X] T036 [US3] Ensure PoP validation uses the hot-loaded owner auth state after restart in `/Users/macstudio/Documents/theyos/admin/rust/server-rs/src/household_auth.rs`

**Checkpoint**: User Story 3 is independently complete when T031-T036 pass.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Documentation, regression, and final cross-repo contract checks.

- [X] T037 [P] Update `/Users/macstudio/Documents/theyos/docs/household-protocol.md` with any final PersonCert, pair-confirm, and PoP contract wording selected by this plan
- [X] T038 [P] Update `/Users/macstudio/Documents/theyos/specs/002-owner-pairing-auth/quickstart.md` if implementation commands differ from planned paths
- [X] T039 Run `cargo fmt --all` in `/Users/macstudio/Documents/theyos/admin/rust`
- [X] T040 Run `cargo clippy --workspace --all-targets -- -D warnings` in `/Users/macstudio/Documents/theyos/admin/rust`
- [X] T041 Run `cargo test --workspace --all-targets` in `/Users/macstudio/Documents/theyos/admin/rust`
- [X] T042 Cross-check theyOS contracts against `/Users/macstudio/Documents/SwiftProjects/iSoyehtTerm/specs/002-owner-device-pairing/contracts/` and record compatibility notes in `/Users/macstudio/Documents/theyos/specs/002-owner-pairing-auth/quickstart.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: depends on Setup; blocks all user stories.
- **US1 (Phase 3)**: depends on Foundational.
- **US2 (Phase 4)**: depends on Foundational and can be implemented with fixtures, but full e2e value depends on US1 pairing.
- **US3 (Phase 5)**: depends on US1 persisted owner auth and US2 PoP validation.
- **Polish (Phase 6)**: depends on desired user stories being complete.

### Parallel Opportunities

- T002 and T003 can run in parallel.
- T004-T009 and T012 can run in parallel after module registration.
- T014-T016 can be written in parallel before US1 implementation.
- T022-T024 can be written in parallel before US2 implementation.
- T031 and T032 can be written in parallel.

## Parallel Example: Foundational

```bash
Task: "Implement pop.rs"
Task: "Implement person_cert.rs"
Task: "Implement caveats.rs"
Task: "Add protocol tests in household-rs/tests/"
```

## Implementation Strategy

### MVP First

1. Complete Setup and Foundational tasks T001-T013.
2. Complete US1 T014-T021.
3. Stop and validate that first-owner pairing returns one PersonCert and no DeviceCert.

### Incremental Delivery

1. Add US2 PoP auth after first-owner pairing works.
2. Add US3 restart durability.
3. Run full polish and cross-repo contract checks.

## Notes

- No commits are performed automatically.
- Do not add DeviceCert behavior in this phase.
- Do not grant household authority through bearer-token session state.
