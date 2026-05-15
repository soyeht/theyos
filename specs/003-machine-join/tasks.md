---
description: "Phase 3 task list — Machine Join Ceremony with Owner Confirmation and Shamir Splitting"
---

# Tasks: Phase 3 - Machine Join Ceremony with Owner Confirmation and Shamir Splitting

**Input**: Design documents from `/specs/003-machine-join/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Test tasks are included throughout because the spec's success criteria require failure-injection, replay, and APNS opacity audits, and the constitution mandates protocol-boundary tests on cert encode/decode/verify, signature, replication, and Shamir round-trip.

**Organization**: Tasks are grouped by user story per the spec's prioritized stories:
- **US1**: Owner-confirmed machine join via remote QR (P1)
- **US2**: Owner-confirmed machine join via LAN auto-discovery (P2)
- **US3**: Atomic Shamir transition with rollback on failure (P1) — non-UI-facing safety property of the ceremony

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Paths are relative to the repository root unless explicitly absolute

## Path Conventions

The Cargo workspace lives under `admin/rust/`. All Rust paths begin there.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Add Phase 3 dependencies, scaffold the new modules, and perform the Adoption-First rename so Phase 2 symbols are out of the way before any new code lands.

- [X] T001 Add Phase 3 dependencies to `admin/rust/household-rs/Cargo.toml`: `vsss-rs` (Shamir GF(256)) and confirm `chacha20poly1305`, `blake3` (with `derive_key` available — already in the standard `blake3` crate API), `p256`, `ciborium`, `zeroize`, `subtle` are pinned at the workspace level. **No HKDF dependency** — the project uses BLAKE3's native KDF mode for all key derivation (per Constitution v2.0.0 enumerated primitives and research `R13`).
- [X] T002 Add Phase 3 dependencies to `admin/rust/server-rs/Cargo.toml`: `a2` (APNS HTTP/2 client) gated behind a `THEYOS_PUSH_DISABLED` env var at runtime; confirm `axum`, `tokio`, `mdns-sd`, `serde_json`, `tracing` are at the expected versions.
- [X] T003 [P] Add the standard BIP-39 English wordlist (2048 entries) as a const array in `admin/rust/household-rs/src/bip39_wordlist.rs`. Source: official BIP-39 English list. Include a `pub const WORDLIST: [&str; 2048]` and a unit test asserting len = 2048.
- [X] T004 Rename `PairWindow` symbol → `PairDeviceWindow` and `pair_window.cbor` file path → `pair_device_window.cbor` across `admin/rust/household-rs/src/pair_device.rs`, `admin/rust/household-rs/src/storage.rs`, `admin/rust/household-rs/src/lib.rs`, `admin/rust/server-rs/src/handlers_pair_device.rs`, `admin/rust/server-rs/src/bonjour_publisher.rs`, and `admin/rust/server-rs/src/state.rs`. Update Phase 2 unit-test fixture paths accordingly. Verify `cargo test --workspace` still passes.
- [X] T005 Add a one-shot in-place migration in `admin/rust/household-rs/src/storage.rs::load_state_dir`: if `pair_window.cbor` exists and `pair_device_window.cbor` does not, rename atomically; otherwise no-op. Add a unit test in `admin/rust/household-rs/tests/storage_migration.rs` covering both branches.
- [X] T005a Migrate the founding-machine self-cert path: in the same `load_state_dir` boot helper, if `machine_cert.cbor` exists at the state-dir root and `machine_certs/<self_m_id>.cbor` does not, atomically rename it into the new directory (creating `machine_certs/` first); otherwise no-op. Update `admin/rust/household-rs/src/machine_cert.rs::load_self_cert` to read exclusively from `machine_certs/<self_m_id>.cbor`. Add a unit test in `admin/rust/household-rs/tests/storage_migration.rs::test_machine_cert_layout_migration` covering both branches.
- [X] T006 [P] Create empty module skeletons committing only `pub use crate::*;` placeholders so subsequent tasks can land in parallel: `admin/rust/household-rs/src/pair_machine.rs`, `admin/rust/household-rs/src/shamir.rs`, `admin/rust/household-rs/src/shard_at_rest.rs`, `admin/rust/household-rs/src/owner_events.rs`, `admin/rust/household-rs/src/fingerprint.rs`, `admin/rust/server-rs/src/handlers_pair_machine.rs`, `admin/rust/server-rs/src/handlers_owner_events.rs`, `admin/rust/server-rs/src/apns_dispatcher.rs`. Wire each into the corresponding `lib.rs` `mod` declarations. `cargo build --workspace` MUST succeed after this task.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Implement the protocol primitives every user story needs: fingerprint, Shamir, shard at rest, MachineCert issuance under household root, the owner-events append log + broadcaster, the opaque APNS dispatcher with its safety lint, the `PairMachineWindow` state machine, and the two-phase commit storage helper. Nothing here is reachable from HTTP yet; that is US1's surface.

⚠️ **CRITICAL**: No user-story phase may begin until every task in this phase is complete and `cargo test --workspace --all-targets` is green.

### Fingerprint (FR-007 / `contracts/fingerprint-derivation.md`)

- [X] T007 [P] Implement `fn fingerprint(m_pub_sec1: &[u8; 33]) -> String` in `admin/rust/household-rs/src/fingerprint.rs` per `contracts/fingerprint-derivation.md` step list. Compute BLAKE3-256, take first 9 bytes, extract six 11-bit groups, look up in `bip39_wordlist::WORDLIST`, join with single ASCII space, all lower-case.
- [X] T008 [P] Add determinism test in `admin/rust/household-rs/tests/fingerprint.rs`: 16 fixed `m_pub` byte vectors → 16 expected fingerprint strings (compute once, lock as expected outputs). Generate the canonical cross-repo file at `specs/003-machine-join/tests/fingerprint_vectors.json` (consumed by the iSoyehtTerm Swift test target) with both `fingerprint` (space-joined string) and `fingerprint_words` (six-element array) fields per entry. Assert that re-running the test reproduces every byte.

### Shamir (FR-011, FR-012 / `contracts/shamir-transition.md`)

- [X] T009 [P] Implement `fn split_2_of_2(secret: &Zeroizing<[u8; 32]>) -> [Zeroizing<[u8; 32]>; 2]` and `fn reconstruct_from_2(shares: [&[u8; 32]; 2]) -> Zeroizing<[u8; 32]>` in `admin/rust/household-rs/src/shamir.rs` using `vsss-rs` configured for GF(256), 32-byte secret. Both functions MUST `Zeroizing` everything that holds plaintext.
- [X] T010 [P] Add round-trip and tamper test in `admin/rust/household-rs/tests/shamir.rs`: 1000 random secrets split-then-reconstruct equals input; reconstruct from one altered shard yields a wrong secret (or panics — the contract is "non-magical"); split-with-wrong-shape inputs is rejected by the wrapper.

### Shard at rest (R13 / FR-013)

- [X] T011 Implement `EncryptedShard` CBOR struct (`{v: u8, index: u8, nonce: [u8;12], ciphertext: Vec<u8>}`) and `fn encrypt_for_self(shard: &Zeroizing<[u8; 32]>, m_priv: &SecretKey, m_pub: &PublicKey, m_id: &str, index: u8) -> EncryptedShard` and `fn decrypt_self(es: &EncryptedShard, m_priv: &SecretKey, m_pub: &PublicKey, m_id: &str) -> Zeroizing<[u8; 32]>` in `admin/rust/household-rs/src/shard_at_rest.rs`. Key derivation: `key = blake3::derive_key(&format!("soyeht-shard-at-rest-v1 m_id={}", m_id), &ecdh_shared_secret_32_bytes)` per `contracts/shamir-transition.md` and research `R13`. AAD = `m_id` UTF-8 bytes. **No HKDF.**
- [X] T012 Implement `fn encrypt_for_peer(shard: &Zeroizing<[u8; 32]>, m_priv_self: &SecretKey, m_pub_peer: &PublicKey, m_id_peer: &str, index: u8) -> EncryptedShard` and `fn decrypt_from_peer(es: &EncryptedShard, m_priv_self: &SecretKey, m_pub_peer: &PublicKey, m_id_self: &str) -> Zeroizing<[u8; 32]>` in the same module — these are the wire-format wrap/unwrap used during 2PC. Same `blake3::derive_key` derivation as T011, with the asymmetric ECDH ingredient: M1 uses `ECDH(M1_priv, M2_pub)` to wrap, M2 uses `ECDH(M2_priv, M1_pub)` to unwrap; both yield the same shared secret.
- [X] T013 [P] Add round-trip tests in `admin/rust/household-rs/tests/shard_at_rest.rs` covering: self-wrap/unwrap, peer-wrap/unwrap (M1 wraps, M2 unwraps), wrong-key fails AEAD, deterministic CBOR encoding equals re-encode bytes, and a CBOR fuzz-corpus seed.

### MachineCert issuance (FR-009, FR-010 / `contracts/machine-cert-cbor.md`)

- [X] T014 Extend `admin/rust/household-rs/src/machine_cert.rs`: add `fn issue_for_candidate(hh_priv: &Zeroizing<[u8; 32]>, hh_id: &str, m_pub: &[u8; 33], hostname: &str, platform: Platform, joined_at: u64) -> MachineCert` and `fn verify_against_household_root(cert: &MachineCert, hh_pub: &[u8; 33]) -> Result<(), CertError>`. Validation rules from `contracts/machine-cert-cbor.md` (deterministic CBOR re-encode equality, recomputed `m_id` matches, signature verifies under `hh_pub`).
- [X] T015 [P] Add tests in `admin/rust/household-rs/tests/machine_cert.rs`: issue then verify happy path; tampered hostname fails verify; tampered signature fails verify; wrong `hh_pub` fails verify; deterministic CBOR property (re-encode after `issue_for_candidate` equals signed bytes).

### `JoinChallenge` and `JoinRequest` validation (FR-009)

- [X] T016 [P] Implement `JoinChallenge` and `JoinRequest` CBOR structs and `fn verify_join_request(req: &JoinRequest, hh_id: &str) -> Result<(), JoinError>` in `admin/rust/household-rs/src/pair_machine.rs` per `data-model.md`. The `JoinChallenge` MUST be `{v=1, purpose="machine-join-request", m_pub, nonce, hostname, platform}` (no `hh_id` field — see research `R4`). Verify `m_pub` decodes as valid SEC1, `nonce` is 32 bytes, `hostname` is 1..=64 UTF-8 bytes, `platform` is one of the three allowed values, `challenge_sig` verifies via `p256` over canonical CBOR(`JoinChallenge` reconstructed from request fields), and reject `m_pub` already in members.
- [X] T017 [P] Add tests in `admin/rust/household-rs/tests/pair_machine.rs`: valid request verifies; bad signature fails; mutated `m_pub` fails; mutated `nonce` fails; mutated `hostname` fails; mutated `platform` fails; non-SEC1 `m_pub` fails decode; canonical-CBOR re-encode of the verified challenge equals signed bytes.

### `PairMachineWindow` state machine (FR-001, FR-016, FR-017)

- [X] T018 Implement `PairMachineWindow` struct, `PairMachineState` enum, and `Arc<PairMachineWindow>` shared state with a `tokio::sync::watch` for observers in `admin/rust/household-rs/src/pair_machine.rs`. Fields per `data-model.md` including `cached_join_request: Option<Bytes>` (the verified deterministic-CBOR bytes of the active ceremony's `JoinRequest`, used at owner-approve time for the `challenge_sig` transitive-binding cross-check). Persist as `pair_machine_window.cbor` via existing `storage::atomic_write_cbor`. Transitions: `idle → staging → awaiting_owner → committed` and any → `aborted`. Singleton invariant: only one window may be `staging` or `awaiting_owner` at a time.
- [X] T019 Add tests in `admin/rust/household-rs/tests/pair_machine.rs`: state-transition matrix happy path; concurrent-second-request rejection while window is open; expiry-after-TTL transitions to `idle`; restart with `awaiting_owner` and an expired `expiry` reads as `idle` on load.

### Owner-events log + broadcaster (FR-019, R8, R10)

- [X] T020 Implement `OwnerEvent` CBOR struct and append log in `admin/rust/household-rs/src/owner_events.rs`: `fn append_event(state_dir: &Path, event: OwnerEvent) -> Result<u64, EventError>` (atomic append + cursor head update + fsync), `fn read_events_since(state_dir: &Path, since: u64) -> Result<Vec<OwnerEvent>, EventError>`, and `fn cursor_head(state_dir: &Path) -> Result<u64, EventError>`. Sign each event with `M_priv` of the issuer per `data-model.md`.
- [X] T021 Add an in-memory `tokio::sync::broadcast::Sender<OwnerEvent>` and `OwnerEventsBroadcaster` wrapper in the same module. `append_event` MUST publish to the broadcaster after a successful disk write. Capacity 32; lagged subscribers re-poll from disk via cursor.
- [X] T022 [P] Add tests in `admin/rust/household-rs/tests/owner_events.rs`: append → read same; cursor monotonicity; concurrent appends produce strictly increasing cursors; broadcast wake within 1 ms; restart preserves cursor head; signature on each event verifies under issuer's MachineCert.

### Owner device push token registry (FR-005d, FR-005e / `contracts/push-token-register.md`)

- [X] T023 [P] Implement `OwnerDevicePushToken` CBOR struct and storage (`owner_device_push_token.cbor` atomic write) in `admin/rust/household-rs/src/owner_events.rs` (same module — these stay coupled). Provide `fn put_owner_push_token(state_dir, token) -> Result<()>` and `fn get_owner_push_token(state_dir) -> Result<Option<OwnerDevicePushToken>>`.
- [X] T024 Add tests in `admin/rust/household-rs/tests/owner_events.rs`: write-then-read round-trip; rotation overwrites; restart preserves; token with `platform != "ios"` is rejected.

### Opaque APNS dispatcher (FR-005b, FR-005c, R11 / `contracts/owner-events.md`)

- [X] T025 Implement `apns_dispatcher` module in `admin/rust/server-rs/src/apns_dispatcher.rs`. Declare exactly four public items and no others: `pub const APNS_TICKLE_BODY: &[u8] = b"{\"aps\":{\"content-available\":1}}";` (the Apple silent-push canonical body — `aps.content-available: 1` is required to wake a backgrounded iPhone), `pub trait ApnsTransport`, `pub enum ApnsError`, and `pub async fn dispatch_tickle(token: &OwnerDevicePushToken) -> Result<(), ApnsError>`. The dispatcher constructs an APNS HTTP/2 request whose body is **exactly** the constant `APNS_TICKLE_BODY` (no `format!`, no `serde_json::json!`, no `serde_json::to_vec`, no other body source — the request builder reads the const directly), with the headers from `contracts/owner-events.md` (`apns-push-type: background`, `apns-priority: 5`, `apns-topic: <bundle>` from build-time config; the `content-available` signal travels in the body, not as a header). The `ApnsTransport` trait abstracts the HTTP/2 client so a spy can be injected in tests. Honor `THEYOS_PUSH_DISABLED=1` by short-circuiting to a `tracing::info!` log and returning `Ok(())` without calling Apple. Append a `const _: fn(&OwnerDevicePushToken) -> _ = dispatch_tickle;` line at the bottom of the file as a compile-time API-shape assertion.
- [X] T026 Add `admin/rust/server-rs/tests/apns_dispatcher_payload.rs`: drive a happy-path Phase 3 ceremony with a spy `ApnsTransport` impl that records every body it would have sent. Assert byte-equality between every captured body and `apns_dispatcher::APNS_TICKLE_BODY`. Assert no captured header value contains any of: an `hh_*` substring, an `m_*` substring, a `p_*` substring, the candidate's hostname, or any of the six fingerprint words.
- [X] T027 Add `admin/rust/server-rs/tests/apns_dispatcher_input.rs`: import `apns_dispatcher::dispatch_tickle` and re-assert at compile time with `const _: fn(&OwnerDevicePushToken) -> _ = dispatch_tickle;` (the same shape T025 ships in the source file, mirrored from the test crate so a future refactor that breaks the API but forgets to update the source-side assertion still fails the test crate's build). Also `pub use admin::rust::server_rs::apns_dispatcher::*;` and assert via `std::any::type_name` that no struct in the module has a field of `Vec<u8>` or `String` typed `body`.
- [X] T028 Add a CI lint script `admin/rust/scripts/lint-apns-payload.sh` and wire it as a dedicated step in `.github/workflows/backend-ci.yml` (running on every PR alongside `cargo build`/`cargo test`/`cargo clippy`). The script runs three checks against `admin/rust/server-rs/src/apns_dispatcher.rs`:
  1. **Body-source check**: reject the build if the file contains any of `format!`, `serde_json::json!`, `serde_json::to_vec`, `serde_json::to_string`, `Vec::from(`, `Vec::extend_from_slice`, `String::from(`, `to_owned()` followed by `into_bytes()`, or any byte/string literal in the file other than the canonical `b"{\"aps\":{\"content-available\":1}}"` (matched literally) plus the supporting build-time / kill-switch / tracing literals enumerated in the script's allowlist.
  2. **Public-API check**: reject the build if `pub` items in the file are not exactly the set `{APNS_TICKLE_BODY, ApnsTransport, ApnsError, dispatch_tickle}` plus the explicitly-enumerated supporting `pub const` / `pub fn` items. Regex covers every `pub`-item kind Rust admits (`use`, `static`, `mod`, `type`, `union`, `extern`, `crate`, `unsafe`) so a future commit cannot smuggle in new `pub` items via the uncovered kinds.
  3. **Body-arg check**: reject the build if `dispatch_tickle`'s signature is not exactly `dispatch_tickle(token: &OwnerDevicePushToken) -> Result<(), ApnsError>` after stripping `async`/whitespace.
  Document each check in a comment block at the top of the script. (Self-test fixtures under `admin/rust/server-rs/tests/fixtures/apns_lint/` with `pass.rs` / `fail.rs` per check are tracked as a follow-up.)

### Two-phase commit storage helper (FR-013, R6 / `contracts/shamir-transition.md`)

- [X] T029 Implement `fn stage_commit_files(state_dir: &Path, items: &[(PathBuf, Vec<u8>)]) -> Result<StagedCommit, StorageError>` and `impl StagedCommit { fn commit(self) -> Result<(), StorageError>; fn rollback(self); }` in `admin/rust/household-rs/src/storage.rs`. `stage_commit_files` writes each as `<path>.staged` with fsync; `commit` renames each `.staged → <path>` then fsyncs the parent directory; `rollback` deletes all `.staged` entries.
- [X] T030 Add boot-time recovery in `admin/rust/household-rs/src/storage.rs::load_state_dir`: detect any leftover `.staged` files; for `household_record.cbor.staged` + `shamir/self_shard.cbor.staged` AND `household_root_sole.cbor` present, expose them via a returned `BootRecoveryNeeded::Phase3CeremonyMaybeCommitted { staged_record, staged_shard }` so the server can drive the recovery flow. For other orphan `.staged` files, delete them with a `warn!` log.
- [X] T031 Add tests in `admin/rust/household-rs/tests/storage_2pc.rs`: stage+commit happy path; stage+rollback removes `.staged`; stage with crash before commit (simulated by leaking the `StagedCommit`) produces detectable orphans; recovery struct surfaces the right state when both staged files plus sole-shard are present.

### CeremonyTxn assembly (R6)

- [X] T032 Implement `CeremonyTxn` in `admin/rust/household-rs/src/pair_machine.rs` per `data-model.md`: holds `Zeroizing` containers for `hh_priv` and plaintext shards, owns the `StagedCommit` handle, exposes `prepare`, `finalize_with_m2`, `commit`, `rollback`. The destructor drops all `Zeroizing` material; `commit` deletes `household_root_sole.cbor` as the **last** step.
- [X] T033 Add tests in `admin/rust/household-rs/tests/pair_machine.rs` covering: `prepare` succeeds and stages files; `commit` deletes sole-shard last; `rollback` leaves sole-shard intact and clears staged files; double-commit is a panic / typed error.

### Foundation gate

- [X] T034 Run `cargo test --workspace --all-targets` and `cargo clippy --workspace -- -D warnings`; both MUST be green before any user-story phase begins. Document the green run hash in a comment on the PR.

---

## Phase 3: User Story 1 — Owner-confirmed machine join via remote QR (P1) 🎯 MVP

**Goal**: Story 1 of the spec — operator runs the installer with `transport=tailscale`, prints QR, owner scans, owner approves with biometry, ceremony completes, M2 has a MachineCert, both machines hold a shard.

**Independent Test**: `cargo test -p e2e-rs phase3_machine_join_remote -- --nocapture` from `quickstart.md` §4.

### QR rendering on candidate side (FR-002, FR-004 / `contracts/pair-machine-url.md`)

- [X] T035 [P] [US1] Add a `pair-machine` subcommand to the install CLI in `admin/rust/server-rs/src/install_cli.rs`: `theyos install --pair-machine --transport tailscale|lan` mints `(M_priv, M_pub)` if not present, generates a 32-byte CSPRNG nonce, determines `hostname` and `platform`, **signs `challenge_sig` at install time** over canonical CBOR `JoinChallenge = {v=1, purpose="machine-join-request", m_pub, nonce, hostname, platform}` using `M_priv`, opens a `PairMachineWindow` carrying the resulting signed `JoinRequest` (so M1 in Story 2 can fetch it via `local/seed`), computes the fingerprint via `fingerprint::fingerprint`, and prints the `soyeht://household/pair-machine?v=1&m_pub=...&nonce=...&hostname=...&platform=...&transport=...&addr=...&challenge_sig=...&ttl=...` URI as a QR and as a plain string. The QR is therefore a self-contained signed credential per `contracts/pair-machine-url.md`.
- [X] T036 [US1] Print the 6-word fingerprint above the QR with the explicit instruction "Verify these six words match what your iPhone shows before approving" in `install_cli.rs`.

### Candidate's pre-household listener (FR-009 / `contracts/join-request.md`)

- [X] T037 [US1] Implement a pre-household HTTP listener in `admin/rust/server-rs/src/handlers_pair_machine.rs::pre_household_router` that exposes `POST /pair-machine/local/finalize` (consumed by M1's 2PC step 11). The router refuses everything else with `401`. Bind it on Tailscale + LAN interfaces; do not require any household-scoped auth (the JoinResponse itself authenticates via the embedded household-signed MachineCert).
- [X] T038 [US1] Implement `POST /pair-machine/local/finalize` handler logic per `contracts/join-request.md`: validate `JoinResponse` (deterministic re-encode, M1 `response_sig` verifies over `JoinResponseUnsigned`, `join_request_hash` matches the active cached `JoinRequest`, MachineCert signatures verify under the `LocalAnchor`-pinned `hh_pub`, decrypt `encrypted_shard` via `shard_at_rest::decrypt_from_peer`, re-encrypt under self-key via `encrypt_for_self`), atomically write `shamir/self_shard.cbor`, `machine_certs/<m1_id>.cbor` (from `peer_list`), `machine_certs/<m2_id>.cbor` (the just-issued cert), `self_m_id` (M2's id), `household_record.cbor`, set `pair_machine_window.cbor.state = committed`, fsync the directory. **No `machine_cert.cbor` self-cert file is written** — the unified layout puts every cert under `machine_certs/<m_id>.cbor` (per H1 / `contracts/machine-cert-cbor.md` Storage section). Return `FinalizeAck`.
- [X] T039 [US1] Add idempotency to `local/finalize`: a second call with the same MachineCert bytes returns the same `FinalizeAck`; a call with different bytes after one already committed returns `401`.
- [X] T040 [US1] Stop the pre-household listener and start the household listener (`server-rs` main router) once `pair_machine_window.cbor.state == committed`. Use a `tokio::sync::watch` from `PairMachineWindow` to drive the swap.
- [X] T041 [US1] Add tests in `admin/rust/server-rs/tests/join_request.rs::test_finalize_idempotency` and `test_finalize_rejects_mutated_response` covering both branches. *(Tests live at `admin/rust/server-rs/tests/pre_household_finalize.rs`.)*

### Founding-machine join-request endpoint (FR-005, FR-009, FR-018 / `contracts/join-request.md`)

- [X] T042 [US1] Implement `POST /api/v1/household/join-request` in `admin/rust/server-rs/src/handlers_pair_machine.rs::founder_join_request_handler`. The external Story 1 handler requires owner `Soyeht-PoP` for `household.add_machine` and verifies the inner `JoinRequest` `challenge_sig` under `m_pub`; Story 2 will reuse the same staging helper in-process after M1 fetches the request from M2. Wire it into `household_listener.rs`.
- [X] T043 [US1] Implement the request flow: verify `JoinRequest` (including `challenge_sig` over reconstructed `JoinChallenge`), check `PairMachineWindow.state == idle`, transition to `staging`, **cache the exact deterministic-CBOR bytes of the verified `JoinRequest` in `PairMachineWindow.cached_join_request`** for later cross-check at owner-approve time. Append an `OwnerEvent{type=join-request, payload={join_request_cbor: <those exact bytes>, fingerprint, expiry}}` signed by M1's `M_priv`, transition to `awaiting_owner` carrying `owner_event_cursor`, and return `JoinRequestAccepted{v, owner_event_cursor, expiry}` as deterministic CBOR. Stories 1 and 2 store byte-identical `cached_join_request` so the owner-approve `challenge_sig` cross-check works the same in both transports.
- [X] T044 [US1] Implement the generic-401 path: any failure (no active sole-shard, owner not paired, m_pub already member, signature invalid, malformed CBOR, window already open) returns `401 {"error":"unauthenticated"}` per R14. Add `tracing::warn!` events distinguishing reasons internally.
- [X] T045 [US1] Wire the replay-cache branch: duplicate `(m_pub, nonce)` checks `PairMachineWindow.cached_response` within window expiry + 60 s grace (R7) and returns cached bytes with `200 OK` when present.
- [X] T045a [US1] Populate `PairMachineWindow.cached_response` with the full `JoinResponse` bytes after successful commit when T058 lands.
- [X] T046 [US1] Add tests in `admin/rust/server-rs/tests/join_request.rs`: happy-path 201; missing/bad owner PoP returns 401 generic; tampered `challenge_sig` returns 401 generic; malformed CBOR returns 401; concurrent second request returns 401 while window is `awaiting_owner`. *(Tests live at `admin/rust/server-rs/tests/phase3_join_request.rs`.)*
- [X] T046a [US1] Add replay-within-grace and replay-after-grace tests when T058 provides cached `JoinResponse` bytes.

### Owner-events long-poll endpoint (FR-005a / `contracts/owner-events.md`)

- [X] T047 [US1] Implement `GET /api/v1/household/owner-events?since=<cursor>` in `admin/rust/server-rs/src/handlers_owner_events.rs::owner_events_long_poll`. Authenticated by the existing `household_auth::SoyehtPoPExtractor`. Decode the cursor (base64url no-pad → CBOR uint).
- [X] T048 [US1] Implement the holding pattern: if `cursor_head > since`, return immediately with all events `cursor_head ≥ cursor > since`; otherwise `tokio::select!` over `broadcast::Receiver<OwnerEvent>` filtered by `cursor > since`, `tokio::time::sleep(45s)`, and the request cancellation token. On broadcast: respond `200 OK` with `OwnerEventsResponse{v=1, events, next_cursor}`. On timeout: respond `204`. Encode response body as deterministic CBOR.
- [X] T049 [US1] Add tests in `admin/rust/server-rs/tests/owner_events.rs`: catch-up returns immediately; idle holds open until event; idle returns 204 at 45s; cancellation closes the connection without writing; bad PoP returns 401.

### Owner approval and decline endpoints (FR-008 / `contracts/owner-events.md`)

- [X] T050 [US1] Implement `POST /api/v1/household/owner-events/<cursor>/approve` in `admin/rust/server-rs/src/handlers_owner_events.rs::owner_approve_handler`. Validate `OwnerApproval` per `data-model.md`: (a) `approval_sig` over canonical `OwnerApprovalContext = {v=1, purpose="owner-approve-join", hh_id, p_id, cursor, challenge_sig, timestamp}` verifies under owner PersonCert's `p_pub`; (b) `cursor` in body equals path parameter and `PairMachineWindow.owner_event_cursor`; (c) `challenge_sig` in body bit-equals `PairMachineWindow.cached_join_request.challenge_sig` (the transitive binding cross-check); (d) `p_id` matches local owner PersonCert's `p_id`; (e) `hh_id` matches local household id; (f) `timestamp` is within ±60 s of server clock. There is no `m_pub_being_joined` field — the `challenge_sig` cross-check provides the same binding more elegantly (any tampering of `m_pub` upstream would have broken `challenge_sig`).
- [X] T051 [US1] On valid approve: drive `CeremonyTxn` through `prepare → finalize_with_m2 → commit`. The handler awaits the 2PC outcome and, on success, returns `OwnerApprovalAck{v=1, machine_cert_hash}`. On any failure during the 2PC, append `OwnerEvent{type=join-cancelled, reason=<...>}` and return generic `401`.
- [X] T052 [US1] Implement `POST /api/v1/household/owner-events/<cursor>/decline` per `contracts/owner-events.md`: transition `PairMachineWindow → aborted`, append `OwnerEvent{type=join-cancelled, reason=declined}`, return `OwnerDeclineAck{v=1}`.
- [X] T053 [US1] Add tests in `admin/rust/server-rs/tests/owner_events.rs`: approve happy path drives commit; approve with `challenge_sig` that does not bit-equal `PairMachineWindow.cached_join_request.challenge_sig` returns 401 + cancel event (this is the transitive-binding regression test — replays an approval from a different ceremony); approve with mismatched cursor returns 401; approve with `timestamp` outside ±60 s returns 401; approve with bad PoP returns 401; decline transitions + records cancel event.

### Push-token registration endpoint (FR-005d / `contracts/push-token-register.md`)

- [X] T054 [US1] [P] Implement `POST /api/v1/household/owner-device/push-token` in `admin/rust/server-rs/src/handlers_owner_events.rs::push_token_register_handler`. Authenticated by `SoyehtPoPExtractor` from owner PersonCert. Validate body `{v=1, platform="ios", push_token}`, persist via `owner_events::put_owner_push_token`, return `200 OK` with `{v=1, updated_at}`.
- [X] T055 [US1] [P] Add tests in `admin/rust/server-rs/tests/push_token.rs`: register happy path; rotation overwrites; non-owner PoP returns 401; missing platform field returns 401.

### Opaque-APNS dispatch on broadcast (FR-005b)

- [X] T056 [US1] Wire `apns_dispatcher::dispatch_tickle` into the `OwnerEventsBroadcaster` in `admin/rust/server-rs/src/handlers_owner_events.rs`: when an event is published AND no long-poll connection currently subscribed (track count via `Arc<AtomicUsize>` on subscribe/drop), spawn a tokio task that calls `dispatch_tickle` with the registered token. If no token registered, log `info` and skip.
- [X] T057 [US1] [P] Add tests in `admin/rust/server-rs/tests/owner_events.rs::test_apns_dispatched_when_no_poll`: spy transport captures the dispatch; assert exact `{"aps":{"content-available":1}}` body (Apple silent-push canonical shape, byte-equal to `APNS_TICKLE_BODY`); assert dispatch did NOT happen when at least one long-poll is active.

### `JoinResponse` assembly + 2PC drive (FR-013, FR-014, R6 / `contracts/shamir-transition.md`)

- [X] T058 [US1] Implement `CeremonyTxn::finalize_with_m2(addr: &str) -> Result<FinalizeAck, CeremonyError>` in `admin/rust/household-rs/src/pair_machine.rs`: builds the `JoinResponse` per `data-model.md`, POSTs to `http://<addr>/pair-machine/local/finalize` (HTTP not HTTPS — pre-household listener has no household-issued cert; underlay + `response_sig` + AEAD shard provide auth/confidentiality), parses ack, verifies `machine_cert_hash == BLAKE3-256(canonical CBOR of MachineCert)`. On hash mismatch, return error (rollback path). M2's cert verification uses the `hh_pub` it already pinned via `LocalAnchor`, NOT the `hh_pub` carried in the response body.
- [X] T059 [US1] Implement `peer_list` assembly: return a `PeerEntry` for M1 carrying `m_id`, `m_pub`, hostname, last-known Tailscale address (if available from local config). M2 uses this to know who to talk to next.
- [X] T060 [US1] Add `push_token_seed` propagation per FR-005e: include the current `OwnerDevicePushToken` in `JoinResponse.push_token_seed` if registered; null if not. M2's `local/finalize` handler persists it via `owner_events::put_owner_push_token`. This is the **Phase 3 implementation** of FR-005e (the household first grows from 1 to 2 in this phase, so the propagation happens here, not in a later phase).

### End-to-end Story 1 test

- [X] T061 [US1] Implement `admin/rust/e2e-rs/tests/phase3_machine_join_remote.rs` per `quickstart.md` §4: spin up M1 (server with Phase 2 fixture + paired owner harness), spin up M2 (server in pre-household mode with `PairMachineWindow.staging` and a self-signed `JoinRequest` already cached), generate QR. The harness owner-iPhone parses the QR, **verifies `challenge_sig` locally** under the QR's `m_pub` over reconstructed `JoinChallenge`, then POSTs the deterministic CBOR `JoinRequest` to M1. Harness polls owner-events, harness submits valid `OwnerApproval`, M1 commits, M2 commits via `local/finalize`. Assert: `machine_certs/<m1_id>.cbor` and `machine_certs/<m2_id>.cbor` present in both state dirs, no leftover `machine_cert.cbor` at root, `household_record.cbor` shows membership=2 + shamir(2,2) + members=[m1_id, m2_id] on both, `household_root_sole.cbor` gone from M1, `shamir/self_shard.cbor` present on each side, `OwnerEvent{type=machine-joined}` at cursor 2. **Timing assertion (SC-001)**: assert that the elapsed time from "iPhone POSTs JoinRequest" to "M2 has persisted its MachineCert" is less than `Duration::from_secs(30)` under the test harness's loopback transport.

### Acceptance gate for US1

- [X] T062 [US1] Run `cargo test -p e2e-rs phase3_machine_join_remote` and confirm all assertions pass. This is the MVP completion checkpoint per `quickstart.md` §4.

---

## Phase 4: User Story 3 — Atomic Shamir transition with rollback (P1)

**Goal**: Story 3 of the spec — exhaustive failure-injection coverage of the ceremony, plus replay idempotency, generic-failure shape audit, and APNS opacity audit. The ceremony's atomicity is already implemented in Phase 2/3; this phase reinforces it with regression tests and recovery paths the happy-path Phase 3 does not exercise.

**Independent Test**: `cargo test -p e2e-rs phase3_atomic_rollback -- --nocapture`, `phase3_replay_idempotent`, `phase3_apns_opacity` all green.

### Failure-injection harness

- [X] T063 [US3] Add a `FailureInjector` test utility in `admin/rust/e2e-rs/src/failure_injector.rs` exposing knobs: drop M2 connection after JoinRequest delivery; drop M2 connection after approval but before finalize POST; force `local/finalize` to write only the cert (skip shard write) and crash; force M1 crash between 2PC steps 10 and 11, between 11 and 12, between 12 and 13.
- [X] T064 [US3] Implement the harness's pluggable hooks via `tokio::sync::Notify`-driven crash points in `admin/rust/server-rs/src/handlers_pair_machine.rs` and `admin/rust/server-rs/src/handlers_owner_events.rs` gated behind `cfg(any(test, feature = "failure-injection"))`. Production builds MUST NOT include them.

### Atomic rollback tests (FR-013 / SC-003)

- [X] T065 [US3] Implement `admin/rust/e2e-rs/tests/phase3_atomic_rollback.rs::test_owner_decline_rolls_back` per `contracts/shamir-transition.md` rollback section: ceremony reaches `awaiting_owner`, harness submits `decline`, assert sole-shard intact, no MachineCert for M2, no `.staged` files, fresh ceremony succeeds.
- [X] T066 [US3] Implement `test_owner_timeout_rolls_back`: ceremony reaches `awaiting_owner`, advance test clock past `expiry`, assert window transitions to `aborted`, sole-shard intact, fresh ceremony succeeds.
- [X] T067 [US3] Implement `test_m2_disconnect_after_approval_rolls_back`: harness disconnects M2 between owner approval and `local/finalize` POST, assert M1 retries up to 3 times, then rolls back, sole-shard intact.
- [X] T068 [US3] Implement `test_m2_finalize_partial_write_rolls_back`: simulate M2 crashing mid-write of `shamir/self_shard.cbor` (leaves a `.staged`), restart M2, assert M2's boot recovery cleans the orphan and reports the ceremony as not-committed; M1's retry observes that and rolls back.
- [X] T069 [US3] Implement `test_m1_crash_between_step10_and_step11_recovers_to_rollback`: M1 sent the POST but lost it (M2 never heard); M1 reboots with `.staged` files + sole-shard still present; recovery probes M2 and finds no commit; deletes `.staged`; ceremony rolls back.
- [X] T070 [US3] Implement `test_m1_crash_between_step11_and_step12_recovers_to_commit`: M1 sent POST and got ack but crashed before rename; M1 reboots; recovery probes M2 and finds `pair_machine_window.cbor.state == committed`; M1 finishes step 12 + step 13; assert final state is fully committed on both sides.
- [X] T071 [US3] Implement `test_m1_crash_between_step12_and_step13_recovers_to_commit`: rename done but sole-shard not yet deleted; recovery deletes sole-shard, proceeds to step 14 (event log).
- [X] T072 [US3] Implement `test_m1_crash_during_step13_is_idempotent`: simulate a partial unlink + reboot; recovery completes the unlink (idempotent on missing-file).

### Recovery boot path (R6 / `contracts/shamir-transition.md`)

- [X] T073 [US3] Implement `fn recover_phase3_ceremony(state_dir, m2_addr) -> Result<RecoveryOutcome, _>` in `admin/rust/household-rs/src/pair_machine.rs` with the **two-state probe** per `contracts/shamir-transition.md` "Recovery on M1 boot": (a) pre-commit probe `GET http://<m2_addr>/pair-machine/local/seed?nonce=<short>` (HTTP — pre-household listener) to detect M2 still in pre-household mode; (b) post-commit probe `GET <m2_addr>/api/v1/household/identity` over the household transport (HTTPS over Tailscale once M2 is committed) to detect M2 already committed. Branch on the responses: pre-commit OK → retry `local/finalize` (idempotent on M2) and finish; post-commit OK with matching `hh_id`/`hh_pub` → finish step 12+13+14; both fail → wait and retry within `RECOVERY_TIMEOUT`. Past timeout → rollback per `FR-013a`. **R6.1 prerequisite**: T073 must consume the `phase3_finalize_ack.marker` written by `owner_approve_handler` to identify pending recoveries — `recover_partial_phase3_commit` preserves `.staged` while the marker exists.
- [X] T074 [US3] Wire `recover_phase3_ceremony` into `server-rs/src/main.rs` startup so any `BootRecoveryNeeded::Phase3CeremonyMaybeCommitted` triggers it before the normal household listener starts.
- [X] T074a [US3] Add `pub const RECOVERY_TIMEOUT: Duration = Duration::from_secs(300)` (5 minutes) to `admin/rust/household-rs/src/pair_machine.rs`. Document in module-level rustdoc that the constant is the deadline at which `recover_phase3_ceremony` rolls back per `FR-013a`, and that the candidate's possibly-orphaned MachineCert is no longer honored after rollback (a returning candidate must re-do the ceremony).

### Replay idempotency (FR-015 / SC-005)

- [X] T075 [US3] Implement `admin/rust/e2e-rs/tests/phase3_replay_idempotent.rs::test_replay_returns_cached_bytes`: complete one ceremony successfully, replay the same `JoinRequest` 100 times within the join window grace; assert exactly one MachineCert exists (file-system stat), exactly one `OwnerEvent{type=machine-joined}` (cursor still 2), and every replayed response is byte-equal to the first.
- [X] T076 [US3] Implement `test_replay_after_grace_returns_401`: same as above but advance test clock past TTL+60s grace; assert next replay returns 401.

### Generic-failure shape audit (FR-017, FR-019a / R14)

- [X] T077 [US3] [P] Implement `admin/rust/e2e-rs/tests/phase3_generic_failures.rs::test_join_request_failures_are_indistinguishable`: trigger six different failure conditions (no active sole-shard, owner not paired, m_pub already member, bad challenge_sig, malformed CBOR, expired window) against `POST /household/join-request`; assert all six responses have identical HTTP status (`401`), identical `Content-Type: application/cbor`, and identical body bytes (deterministic CBOR `{v=1, error="unauthenticated"}`). Repeat the same indistinguishability assertion against the owner-events long-poll, approve, decline, and push-token-register endpoints with their respective failure conditions; assert the deterministic-CBOR error body is byte-equivalent across all five endpoints.

### No-plaintext-HH_priv assertion (SC-004)

- [X] T077a [US3] Add `admin/rust/e2e-rs/tests/phase3_no_plaintext_hh_priv.rs::test_no_plaintext_hh_priv_after_commit`: drive a happy-path Story 1 ceremony to completion, then on each state dir assert (a) `household_root_sole.cbor` does not exist on M1, (b) `household_root_sole.cbor` does not exist on M2, (c) the only files matching `*shard*` are `shamir/self_shard.cbor` (encrypted) on each side, and (d) re-encoding any of those `EncryptedShard` files with the wrong machine private key fails AEAD authentication (defense-in-depth: confirms the at-rest encryption is real, not symbolic). Assert with `subtle::ConstantTimeEq` that no on-disk file under either state dir contains a 32-byte window equal to the original plaintext `HH_priv` scalar generated at Phase 1 bootstrap (the harness retains a copy for this comparison only and zeroizes it after).
- [X] T077b [US1] **External trust anchor for `JoinResponse`** (B7 from PR #28 round 3). Add `POST /pair-machine/local/anchor` per `contracts/local-anchor.md`; mint and persist a 32-byte `anchor_secret` in `PairMachineWindow` at `prepare_candidate` time and embed it in the QR via `to_pair_machine_uri_with_anchor`; gate `POST /pair-machine/local/finalize` on `pinned_hh_pub == response.household_record.hh_pub` AND `pinned_hh_id == response.household_record.hh_id`; persist `pinned_hh_pub` / `pinned_hh_id` on the window snapshot. Cross-repo: iSoyehtTerm gains a matching POST after biometric approval. Tests: `local_anchor_pins_household_for_finalize`, `local_anchor_rejects_wrong_secret`, `local_anchor_rejects_attacker_household_substitution`, `local_anchor_is_idempotent_on_identical_repin`, `local_anchor_rejects_divergent_repin`, `local_finalize_rejects_when_anchor_not_pinned` (all in `pre_household_finalize.rs`).
- [X] T077c [US1] **Round 4 follow-ups for B7 / B5 / on-disk forward-compat** (PR #28 R4). (a) `pin_household_anchor` rolls back the in-memory `pinned_hh_pub` / `pinned_hh_id` if `persist` fails so an iPhone retry does not short-circuit against an in-memory pin that never reached disk (regression test `pin_household_anchor_rolls_back_in_memory_state_on_persist_failure` in `pair_machine_install.rs`). (b) `CeremonyTxn::commit` makes keystore-destroy and sole-shard-unlink best-effort post `staged.commit()` (log + continue, never `?`-propagate after the household has logically grown to N=2). (c) Reorder `local/finalize` gates to match `contracts/local-anchor.md`: `join_request_hash` runs BEFORE the anchor-required + anchor-match gates; the anchor gates run BEFORE any cert-chain verification. (d) Drop `owner_p_cert` from `LocalAnchor` wire shape and from the contract; the field was unverified dead-weight (the `anchor_secret` is the gate). (e) Spec out `500 {v=1, error="internal"}` post-FinalizeAck wire surface in `contracts/owner-events.md` and `spec.md` FR-019a. (f) Remove `#[serde(deny_unknown_fields)]` from `PairMachineWindowSnapshot` (on-disk format must accept unknown fields for rollback safety per `feedback_rollback_prebuilt`); wire types keep it. (g) `local_seed_handler` accepts `Staging | AwaitingOwner`. (h) `verified_founder_cert_from_peer_list` `continue`s past invalid peers instead of aborting (forward-compat for Phase 4+ multi-peer lists).
- [X] T077f [US1] **Round 7 follow-ups: marker semantics flip + preserve-on-error + M2-side rollback** (PR #28 R7). (R7.1) `StagedCommit::commit_preserve_on_error` and `CeremonyTxn::commit_preserve_on_error` introduced — variant of commit that disarms `StagedCommit`'s Drop unlink on partial promotion failure. The plain `commit()` still cleans up; the preserve variant is invoked on M1 once finalize has been launched so the staged set survives for boot-time recovery (`storage::recover_partial_phase3_commit`) to find via the marker. Regression test `staged_commit_preserve_on_error_keeps_remaining_staged_on_failure` in `storage_2pc.rs` injects a rename failure (target final path is a directory) and asserts the surviving `.staged` is preserved on disk. (R7.2/R7.3) `phase3_finalize_ack.marker` semantics flipped from "M2 has FinalizeAck'd" to "M1 intends to drive the ceremony — preserve `.staged` for recovery". `owner_approve_handler` now writes the marker BEFORE invoking `finalize_with_m2`, clears it only for definitive M2 rejects / marker-write failures, and preserves it for ambiguous transport or ack-decode failures. The two crash windows the previous placement left open are closed: (a) crash between `finalize_with_m2 Ok` and marker durable; (b) lost or undecodable `FinalizeAck` response packet (M2 committed, M1's `finalize_with_m2` returned Err). Ambiguous failures now return the contracted 500 while leaving marker + `.staged` evidence for T073/T074 recovery. (R7.4) M2-side rollback in `recover_partial_phase3_commit`: distinguishes M2 (no on-disk record) from M1 (record present at `shamir_n=1`) and unlinks the wider M2 staged set — founder cert + candidate cert + `self_m_id` + `self_shard.cbor` (no `sole` to gate on) + `pair_machine_window.cbor` + `owner_device_push_token.cbor`. Plus `load_state_dir` now runs `recover_partial_phase3_commit` BEFORE `recover_self_m_id_marker` (so the marker recovery never observes a partially-promoted singleton founder cert and writes a wrong `self_m_id`). Regression test `recover_partial_phase3_commit_rolls_back_m2_side_full_staged_set` constructs the partial-commit state with all M2 artifacts and asserts every one is unlinked. (R7.NB1) Remaining `https://` references aligned to `http://` in `contracts/shamir-transition.md` (step 10 + recovery probes), `research.md` pre-commit recovery probe, `docs/household-protocol.md` §5 sequence diagram (`hh_pub` → `household_record`; cert verified against pinned anchor); `contracts/join-request.md` § Required guards rewritten to make the anchor pin the cert-chain trust root (NOT `JoinResponse.household_record.hh_pub`). (R7.NB2) Stale-marker sweep: `storage::clear_stale_phase3_marker_if_post_shamir` runs unconditionally from `load_state_dir` whenever the on-disk record is post-Shamir. Closes the leak where a transient FS error in the handler's clear left a marker on disk indefinitely under steady-state (`.staged` empty short-circuits the recovery clear). Regression tests `stale_phase3_marker_cleared_when_record_post_shamir_and_no_staged` and `stale_phase3_marker_sweep_skips_pre_shamir_record` in `storage_2pc.rs` cover both directions of the gate.
- [X] T077e [US1] **Round 6 follow-ups: recovery wiring + ordering + post-FinalizeAck preservation** (PR #28 R6). (R6.1) Finalize-intent preservation marker: `owner_approve_handler` writes `phase3_finalize_ack.marker` before invoking `finalize_with_m2`; clears it after commit succeeds. `recover_partial_phase3_commit` skips the roll-back branch while the marker exists with a pre-Shamir record so T073/T074's future `recover_phase3_ceremony` driver can probe M2 and reconcile the half-committed ceremony. Regression test `recover_partial_phase3_commit_preserves_staged_when_finalize_ack_marker_present` in `storage_2pc.rs`. (R6.2) `handlers_pair_machine.rs::local_finalize` reorders its staged set so `household_record.cbor` is the LAST entry — record-rename is the canonical "candidate is committed" marker on the M2 side, mirroring the M1-side fix from R5.7. A crash before the record promotion now correctly classifies as "not committed" on next boot through `recover_partial_phase3_commit`. (R6.3) Spec FR-002 carved out for Phase 3 software-key requirement; `contracts/pair-machine-url.md` step 1 explicitly requires `THEYOS_FORCE_SOFTWARE_KEYS=1` on macOS and notes the env var must persist across daemon boots. (R6.4) **Wiring fix**: `try_load_existing` now calls `storage::load_state_dir` BEFORE reading the record, so `recover_partial_phase3_commit` and `recover_post_join_sole_shard` actually run on the server boot path (not just the fresh-install `bootstrap_or_load` path). The R5.7 split-brain fix was dead code at runtime without this. Regression test `try_load_existing_runs_partial_phase3_commit_recovery` in `ceremony_txn.rs` plants `.staged` orphans + post-Shamir record and asserts `try_load_existing` (NOT `load_state_dir`) drives the recovery. (R6.5) `recover_post_join_sole_shard` now gates deletion on `record.shamir_n > 1` AND runs AFTER `recover_partial_phase3_commit` in `load_state_dir`; under the R5.7 ordering, a crash that promoted `self_shard.cbor` but not the record would have caused the previous probe to mis-classify as committed and lose the pre-Shamir root. Regression test `recover_post_join_sole_shard_preserves_sole_when_record_pre_shamir` in `storage_2pc.rs`. (R6.NB1) Stale `https://` references in `docs/household-protocol.md` (§5 + §12 pre-household routes table + §13 browse semantics), `specs/003-machine-join/research.md` (R5 + R6 finalize step + recovery probe), `contracts/bonjour-pair-machine.md`, and `tasks.md` T058/T073/T086 aligned to `http://` per R5.3/B7; finalize trust description corrected from "trusts hh_pub from response" to "trusts hh_pub pinned from LocalAnchor". (R6.NB2) `recover_partial_phase3_commit` and `recover_post_join_sole_shard` now classify a CBOR-undecodable `household_record.cbor` as a tracing crisis (`record_undecodable`) and skip recovery entirely — the previous default-to-pre-Shamir would have unlinked artifacts on a healthy-but-undecodable household. Regression test `recover_partial_phase3_commit_skips_when_record_undecodable` in `storage_2pc.rs`.
- [X] T077d [US1] **Round 5 follow-ups: split-brain recovery, scheme defaults, SE limits, anchor sequencing** (PR #28 R5). (R5.1) `contracts/local-anchor.md` producer flow now requires anchor-before-approve sequencing: iPhone awaits `LocalAnchorAck` from M2 BEFORE POSTing `OwnerApproval` to M1, removing the race where M1's `finalize_with_m2` would hit an unpinned candidate window and abort a valid ceremony. (R5.2) Story 2 (LAN/Bonjour) anchor design is explicitly tracked as Phase 5 follow-up under "Story 2 anchor mechanism" with three candidate sketches; Story 1 closes here. (R5.3) `bonjour_browser::local_seed_url` defaults schemeless TXT addrs to `http://` (matches `local_finalize_url` from B2). (R5.4) `try_load_existing` and `bootstrap_or_load` idempotently re-attempt `destroy_household_keystore_material` on every boot when `record.shamir_n > 1`, closing the B1 invariant in the absence of T073/T074 (regression test `try_load_existing_retries_keystore_destroy_for_post_shamir_household` in `ceremony_txn.rs`). (R5.5+R5.6) Spec FR-021 added: macOS founder + candidate MUST run with `THEYOS_FORCE_SOFTWARE_KEYS=1` for Phase 3 because Shamir splitting and ECDH-shard-decrypt need raw 32-byte EC scalars that SE-backed keys never expose; the `WARN` paths in `owner_approve_handler` and `local_finalize_handler` now carry an actionable `hint` line. (R5.7) `CeremonyTxn` reorders staged files so `household_record.cbor` (the canonical commit marker) promotes LAST, and `storage::recover_partial_phase3_commit` rolls forward post-Shamir orphans or rolls back pre-Shamir orphans (including the candidate cert identified via the staged record); regression tests `recover_partial_phase3_commit_rolls_forward_when_record_post_shamir` and `recover_partial_phase3_commit_rolls_back_when_record_pre_shamir` in `storage_2pc.rs`. Plus the producer-text drift on `owner_person_cert` removed from the `local-anchor.md` step-2 paragraph.

### APNS opacity audit (FR-005c / SC-NA)

- [X] T078 [US3] Implement `admin/rust/e2e-rs/tests/phase3_apns_opacity.rs::test_no_household_data_in_apns`: register a token, drive a full ceremony with the spy transport active, capture every dispatched APNS body, assert each body equals `b"{\"aps\":{\"content-available\":1}}"` exactly. Assert no header value contains a household-derived string (no `hh_*`, `m_*`, `p_*`, fingerprint words, hostname).
- [X] T079 [US3] [P] Implement `admin/rust/server-rs/tests/apns_dispatcher_does_not_see_event.rs`: assert at the type-system level that `apns_dispatcher::dispatch_tickle` cannot accept any household-typed parameter (compile-time check via macro or doc-test that imports the public API and verifies the function signature).

### Acceptance gate for US3

- [X] T080 [US3] Run all `phase3_atomic_rollback`, `phase3_replay_idempotent`, `phase3_apns_opacity`, `phase3_generic_failures` tests and confirm they pass.

---

## Phase 5: User Story 2 — Owner-confirmed machine join via LAN auto-discovery (P2)

**Goal**: Story 2 of the spec — same ceremony as US1 but the founding machine discovers the candidate on Bonjour automatically and self-fetches the JoinRequest, so no QR is involved.

**Independent Test**: `cargo test -p e2e-rs phase3_machine_join_lan -- --nocapture` from `quickstart.md` §5.

### Bonjour publisher updates (FR-003 / `contracts/bonjour-pair-machine.md`)

- [X] T081 [US2] Update `admin/rust/server-rs/src/bonjour_publisher.rs` to subscribe to both `PairDeviceWindow` and `PairMachineWindow` state changes via their watchers. Reflect into TXT records: `pairing=device|machine` (mutually exclusive, present only when a window is open), `pair_role=founder|joiner` (M1 = founder, M2 = joiner), `pair_nonce=<short>`, and on the joiner side `m_pub_b32=<base32 of BLAKE3-128(m_pub)[0..12]>`.
- [X] T082 [US2] Update `admin/rust/household-rs/src/ids.rs` (or equivalent) to expose `fn m_pub_short(m_pub: &[u8; 33]) -> String` returning the 20-char base32-lowercase no-pad encoding of `BLAKE3-128(m_pub)[0..12]`. Add unit test asserting determinism.
- [X] T083 [US2] [P] Add tests in `admin/rust/server-rs/tests/bonjour_pair_machine.rs`: when `PairMachineWindow → staging`, TXT records reflect `pairing=machine, pair_role=...`; when `PairMachineWindow → idle`, TXT records have neither key; only one of `pairing=device|machine` is ever published at a time.

### Pre-household `local/seed` endpoint (R5 / `contracts/join-request.md`)

- [X] T084 [US2] Implement `GET /pair-machine/local/seed?nonce=<base32_short>` in the candidate's pre-household router (`admin/rust/server-rs/src/handlers_pair_machine.rs::pre_household_router`). Guards: `PairMachineWindow.state == staging`, supplied short-nonce equals first 8 bytes of `PairMachineWindow.nonce` (base32-encoded). Response: `200 OK`, `Content-Type: application/cbor`, body = the signed `JoinRequest` CBOR (the candidate signed it at install time when opening the window).
- [X] T085 [US2] Add tests in `admin/rust/server-rs/tests/join_request.rs::test_local_seed_happy_path` and `test_local_seed_wrong_nonce_returns_401`.

### Founder-side Bonjour browser (Story 2 entry point)

- [X] T086 [US2] Implement `admin/rust/server-rs/src/bonjour_browser.rs` (new file): on the founding machine, subscribe to mDNS records of type `_soyeht-household._tcp.local.` matching local `hh_id` and carrying `pair_role=joiner`. On match with a `pair_nonce` not yet seen, resolve the `addr`, GET `http://<addr>/pair-machine/local/seed?nonce=<short>` (HTTP not HTTPS — schemeless TXT defaults to `http://` per R5.3, mirroring `local_finalize_url`'s B2 default), and, on `200 OK` with a valid CBOR body, drive the same staging path as `POST /household/join-request` (i.e., reuse `handlers_pair_machine::founder_stage_join_request` shared helper).
- [X] T087 [US2] Refactor `handlers_pair_machine.rs::founder_join_request_handler` to extract a shared `founder_stage_join_request(req: JoinRequest, source: JoinSource) -> Result<u64, JoinError>` helper used by both the HTTP handler (Story 1) and the Bonjour browser (Story 2). `JoinSource` is informational only and influences `tracing` events.
- [X] T088 [US2] Wire the Bonjour browser into `server-rs/src/main.rs` so it is started alongside the publisher whenever the household has membership=1 and the window is `idle`. It is stopped automatically when membership grows or a window opens.
- [X] T089 [US2] Add tests in `admin/rust/server-rs/tests/bonjour_browser.rs` using a simulated mDNS source: published joiner with the correct `hh_id` is fetched and staged within 2s; published joiner with a wrong `hh_id` is ignored; spoofed TXT pointing `addr` at an attacker host that returns a wrong-`m_pub` JoinRequest is rejected at `verify_join_request` time (signature still verifies, but the seed response still has to claim a candidate `m_pub` and that's what the owner confirmation will surface — so the owner sees the attacker's fingerprint, not M2's; assert this is observable via the `OwnerEvent` payload).

### LAN fallback to Story 1 QR (FR-004 acceptance scenario 3)

- [X] T090 [US2] Implement a 5-second mDNS-availability probe in the candidate's installer (`admin/rust/server-rs/src/install_cli.rs::run_pair_machine`): if mDNS publishing fails or LAN-discovery is unreachable, fall back to the Story 1 QR-only path (the QR is printed unconditionally; the fallback is in the prompt copy: "LAN discovery unavailable — scan the QR with your iPhone").

### End-to-end Story 2 test

- [X] T091 [US2] Implement `admin/rust/e2e-rs/tests/phase3_machine_join_lan.rs` per `quickstart.md` §5: spin up M1 + M2 with a simulated mDNS bus, M2 advertises `pair_role=joiner`, M1's browser detects within 2s and stages the JoinRequest fetched from M2's `local/seed`, harness submits owner approval, ceremony completes. Assert final state is bit-equivalent to Story 1's e2e test (same file layout under `machine_certs/`, same `household_record` shape, same `OwnerEvent` log). **Timing assertions**: (a) M1's browser-to-stage latency MUST be less than `Duration::from_secs(2)` (SC-002 sub-budget); (b) end-to-end ceremony from "M2 publishes Bonjour" to "M2 has persisted its MachineCert" MUST be less than `Duration::from_secs(15)` (SC-002).

### Acceptance gate for US2

- [X] T092 [US2] Run `cargo test -p e2e-rs phase3_machine_join_lan` and confirm all assertions pass.

---

## Phase 6: Polish & Cross-Cutting Concerns

### Observability + audit (FR-019)

- [X] T093 Add structured `tracing` instrumentation across `pair_machine.rs`, `handlers_pair_machine.rs`, `handlers_owner_events.rs`, and `apns_dispatcher.rs` covering: window opened, JoinRequest received, owner prompt forwarded, owner approved, owner declined, owner timed out, ceremony aborted, ceremony committed, Shamir transition committed, APNS dispatched. Ensure no span or event records private keys, raw signatures, full nonces, full shards, or push tokens. Add a unit test in `admin/rust/server-rs/tests/observability_audit.rs` that captures all events from a happy-path ceremony and asserts none of them contain bytes from the source private keys, full nonces, or full shards (compare via `subtle::ConstantTimeEq` between forbidden bytes and span debug-text).

### Cross-repo contract artifacts

- [X] T094 Verify the canonical BIP-39 fingerprint vectors at `specs/003-machine-join/tests/fingerprint_vectors.json` (16 entries with both `fingerprint` string and `fingerprint_words` array) round-trip on the iSoyehtTerm Swift test target. Already documented in `specs/003-machine-join/contracts/fingerprint-derivation.md`; this task gates the cross-repo determinism check.
- [X] T095 [P] Update `docs/household-protocol.md` §13 to include the Phase 3 TXT-record additions (`pair_role`, `m_pub_b32`) and `pairing=machine` value. Mark §6 sole-shard transition as concretely specified by `specs/003-machine-join/contracts/shamir-transition.md`. This is the protocol-level absorption of the Phase 3 plan-time decisions.

### Recovery timeout failure-injection test (FR-013a / R6 / `contracts/shamir-transition.md`)

- [X] T096 Add a test `test_recovery_timeout_rolls_back_when_m2_permanently_lost` in `admin/rust/e2e-rs/tests/phase3_atomic_rollback.rs` that uses the failure injector to simulate M2 becoming permanently unreachable after the owner has approved but before M1's commit, advances the test clock past `pair_machine::RECOVERY_TIMEOUT`, and asserts that M1 has rolled back (no `machine_certs/<m2_id>.cbor` on M1, sole-shard intact, no `.staged` files, household_record still showing membership=1). The constant itself is added in T074a and documented in `contracts/shamir-transition.md`'s Recovery section per FR-013a; this task is the regression test enforcing the documented behavior.

### Operator-facing redundancy notice (FR-012a)

- [X] T097 Lock the exact wording for the operator-facing post-commit notice on the candidate's installer console with `@agente-app` cross-repo (so the iPhone confirmation success-toast and the candidate console message are aligned). Until cross-repo agreement: ship a placeholder string `"Casa now has 2 machines. Until you add a 3rd machine, losing either machine means losing the household. Add another machine soon."` in `admin/rust/server-rs/src/handlers_pair_machine.rs` printed by the candidate after `local/finalize` commits.

### Final regression

- [ ] T098 Run `cargo test --workspace --all-targets`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --check`, and the APNS-payload lint script from T028. All MUST pass.
- [X] T099 Run the cross-repo contract checks per `quickstart.md` §10: read `/Users/macstudio/Documents/SwiftProjects/iSoyehtTerm/specs/003-machine-join/contracts/` (when published by `@agente-app`) and confirm `pair-machine-url`, `owner-events-client`, `fingerprint-derivation`, and `apns-opacity` match the theyos contracts byte-for-byte for the QR shape, the cursor encoding, the BIP-39 derivation, and the empty-payload contract. File any mismatches as cross-repo blockers before declaring Phase 3 complete on `main`.

---

## Dependencies

**Phase ordering** (each phase depends on the previous being green):
1. Phase 1 (Setup, T001–T006) — all blocking; no inter-task ordering except T004/T005 sequential (rename then migration).
2. Phase 2 (Foundational, T007–T034) — blocking gate at T034. Within Phase 2:
   - T007 unblocks T008 (fingerprint impl + test).
   - T009 unblocks T010 (Shamir impl + test).
   - T011, T012 unblock T013 (shard-at-rest tests).
   - T014 depends on having a working sign path (Phase 1 SE/keys already shipped).
   - T018 unblocks T019, T032, T033.
   - T020 unblocks T021, T022, T023, T024.
   - T025 unblocks T026, T027, T028.
   - T029, T030 unblock T031.
3. Phase 3 (US1, T035–T062) — depends on Phase 2 done. Within US1: handler tasks (T037–T046) depend on `PairMachineWindow` (T018) and 2PC helper (T032). Long-poll endpoint (T047–T049) depends on owner-events module (T020/T021). Approve handler (T050–T053) depends on `CeremonyTxn` (T032) and `local/finalize` handler (T038). E2E test T061 depends on T035–T060.
4. Phase 4 (US3, T063–T080) — most failure-injection tests depend on Phase 3 happy-path landing. T073 (recovery boot path) is depended on by T069–T072.
5. Phase 5 (US2, T081–T092) — depends on Phase 3 (US2 reuses `founder_stage_join_request`).
6. Phase 6 (T093–T099) — last; T099 is the cross-repo gate.

**MVP scope**: Phases 1, 2, 3 (T001–T062). At T062 green, the household can grow from 1 to 2 machines via remote QR with full owner approval and atomic ceremony. US3's failure-injection tests (Phase 4) and US2's LAN automatic discovery (Phase 5) are progressive enhancements.

## Parallel execution opportunities

**Within Phase 1**: T003 and T006 are independent of T004/T005.

**Within Phase 2**:
- T007 (fingerprint), T009 (shamir), T011/T012 (shard-at-rest), T014 (machine_cert), T016 (pair_machine req validation), T020 (owner-events), T023 (push-token storage), T025 (apns dispatcher) can all proceed in parallel after T006.
- T008, T010, T013, T015, T017, T022, T024, T026, T027, T031 (the test tasks) parallelize with each other and with their corresponding implementation task once it lands.

**Within Phase 3 (US1)**:
- T035, T036 (installer CLI) parallel with T042–T046 (founder endpoint) — they touch different crates.
- T047–T049 (long-poll), T050–T053 (approve/decline), T054–T055 (push-token register), T056–T057 (apns wiring) parallel after `OwnerEventsBroadcaster` from Phase 2 is ready.
- T037–T041 (M2's pre-household listener) parallel with founder side.

**Within Phase 4 (US3)**: T077 and T079 are independent of the rollback tests.

**Within Phase 5 (US2)**: T081, T084, T086 parallel after Phase 3 lands.

**Within Phase 6**: T095 parallel with T093, T094, T096, T097.

## Implementation strategy

**MVP path (fastest to "household has 2 machines"):**
1. Phase 1 in one PR (Adoption-First rename + scaffolding).
2. Phase 2 in one or two PRs (foundational primitives + tests).
3. Phase 3 in one PR (US1 happy path + e2e test). At T062 green, ship MVP.
4. Phase 4 (US3 failure-injection + recovery) in a follow-up PR. Strongly recommended before any external user installs Phase 3 — the rollback path is a correctness requirement, not a polish feature.
5. Phase 5 (US2 LAN auto-discovery) in a follow-up PR. Lowest-risk, highest UX win.
6. Phase 6 (polish, observability, cross-repo gate) in a final PR before Phase 3 lands on `main`.

**No half-migration on `main` (Constitution IV)**: each PR MUST end with `cargo test --workspace --all-targets` green and the household able to grow from 1→2 (after MVP) and stay there across restarts. Phase 4 and Phase 5 are non-blocking for the household-grows-to-2 capability but blocking for the broader product release (US3 atomicity is a hard requirement; US2 is the Apple-grade UX that justifies shipping at all).

## Total task count

102 tasks across 6 phases (after the 2026-05-06 `/speckit-analyze` remediations: T005a unified MachineCert layout migration, T074a `RECOVERY_TIMEOUT` const, T077a no-plaintext-HH_priv assertion).

| Phase | Tasks | Story | Independent test |
|---|---|---|---|
| 1 Setup | T001–T006 + T005a (7) | — | `cargo build --workspace` succeeds |
| 2 Foundational | T007–T034 (28) | — | `cargo test --workspace --all-targets` green |
| 3 US1 (P1, MVP) | T035–T062 (28) | US1 | `cargo test -p e2e-rs phase3_machine_join_remote` green (with timing assertion <30s) |
| 4 US3 (P1) | T063–T080 + T074a + T077a (20) | US3 | `phase3_atomic_rollback`, `phase3_replay_idempotent`, `phase3_apns_opacity`, `phase3_generic_failures`, `phase3_no_plaintext_hh_priv` green |
| 5 US2 (P2) | T081–T092 (12) | US2 | `cargo test -p e2e-rs phase3_machine_join_lan` green (with timing assertions <2s browse, <15s e2e) |
| 6 Polish | T093–T099 (7) | — | full regression + cross-repo gate |

**Format validation**: every task line follows `- [ ] T### [P?] [Story?] description with file path` per the skill's checklist format requirements.
