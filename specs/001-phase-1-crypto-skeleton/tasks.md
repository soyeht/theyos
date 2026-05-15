# Tasks: Phase 1 — Cryptographic Skeleton (theyOS)

**Input**: Design documents from `/specs/001-phase-1-crypto-skeleton/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md
**Tests**: REQUIRED (SC-004 mandates a test suite covering protocol boundaries; Constitution Engineering Standards enforce the same).
**Organization**: Tasks are grouped by user story to enable independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Maps to user stories from spec.md (US1, US2, US3)
- All paths are absolute under repo root `/Users/macstudio/Documents/theyos/`

## Path Conventions

Rust workspace at `admin/rust/` with the new crate `household-rs/` and existing crates `server-rs/`, `store-rs/`, `e2e-rs/`. Paths shown below match `plan.md` Project Structure.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Workspace plumbing — register the new crate, add new deps, configure log format. No domain logic yet.

- [X] T001 Add new workspace member `household-rs` and shared deps (`p256 = "0.13"` with `ecdsa`+`pkcs8` features, `security-framework = "2"` macOS-only target, `blake3 = "1"`, `ciborium = "0.2"`, `keyring = "3"` Linux-only target, `data-encoding = "2"`, `zeroize`, `mdns-sd = "0.10"` Linux-only target, `qrcode = "0.14"`) in `admin/rust/Cargo.toml`
- [X] T002 Create crate manifest at `admin/rust/household-rs/Cargo.toml` with metadata, edition 2024, dependencies pulled from workspace, plus a `hash-sha256-fallback` cargo feature wiring `sha2`. Dev-deps: `tracing-test = "0.2"` (for log-shape assertions in T024a), `criterion = "0.5"` (for the `e2e-rs` benchmark in T037a)
- [X] T003 [P] Create skeleton `admin/rust/household-rs/src/lib.rs` declaring modules `error`, `ids`, `keys`, `cbor`, `keystore`, `storage`, `household_record`, `machine_cert`, `chain`, `bootstrap` (empty stubs allowed; concrete impls land in later phases)
- [X] T004 [P] Add JSON formatter wired to `THEYOS_LOG_FORMAT` env (default `json` in release, `text` otherwise) in `admin/rust/server-rs/src/main.rs` using `tracing_subscriber::fmt().json()`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Crypto + serialization + I/O primitives shared by all three user stories. Nothing user-visible yet but everything downstream chains from here.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T005 [P] Implement error types `HouseholdError` / `BootstrapError` / `KeystoreError` / `StorageError` carrying structured `stage`, `kind`, `hint` fields (per FR-014) in `admin/rust/household-rs/src/error.rs`
- [X] T006 [P] Implement `HouseholdId`, `MachineId`, base32 (lowercase, no-pad) encoder, and `derive_household_id` / `derive_machine_id` (BLAKE3 default + SHA-256 fallback gated by feature `hash-sha256-fallback`) in `admin/rust/household-rs/src/ids.rs`
- [X] T007 [P] Implement `IdentityKey` trait + software-backed `P256Keypair { public: P256PublicKey (33-byte SEC1), secret: P256SecretScalar (32 bytes, zeroized on Drop) }` with `generate()` (via `p256::SecretKey::random`), `IdentityKey::sign(&self, &[u8]) -> P256Signature` returning 64-byte raw `r || s`, no `Clone`, in `admin/rust/household-rs/src/keys.rs`
- [X] T007a [P] Implement macOS-only `P256SeKeypair` (cfg(target_os = "macos")) wrapping a `SecKey` reference: `create(label, for_subject_signing)` calls `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` + `.privateKeyUsage` (and `.biometryCurrentSet` when `for_subject_signing`); `IdentityKey::sign` calls `SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)` and strips DER to 64-byte raw `r || s`; private `sec_key_ref` non-`Clone`. Honor `THEYOS_FORCE_SOFTWARE_KEYS=1` env var as escape hatch (CI fallback). In `admin/rust/household-rs/src/keys_se.rs`
- [X] T008 [P] Implement `to_canonical_vec<T: Serialize>` and `from_canonical_slice<T: DeserializeOwned>` over `ciborium`, plus debug-mode round-trip canonicality check (encode→decode→re-encode→byte-compare), per `contracts/cbor-schemas.md` in `admin/rust/household-rs/src/cbor.rs`
- [X] T009 [P] Implement OS keystore wrapper (`KeystoreEntry::write/read/delete`) on top of `keyring = "3"`, with typed errors mapped to actionable hints (macOS Keychain denied, Linux Secret Service unavailable → `THEYOS_KEYRING=kernel` hint) in `admin/rust/household-rs/src/keystore.rs`
- [X] T009a [P] Failure-injection tests for `keystore.rs`: mocked `keyring::Entry` returning Keychain-denied error and Secret-Service-unavailable error; assert each maps to the typed error variant carrying the exact `error.hint` strings documented in `data-model.md` keystore section, in `admin/rust/household-rs/tests/keystore_errors.rs`
- [X] T010 [P] Implement `atomic_write_cbor` (write `*.tmp` → fsync → rename → fsync parent dir, mode 0600) and `read_optional_cbor` (returns `Ok(None)` on absent file) in `admin/rust/household-rs/src/storage.rs`
- [X] T010a [P] Failure-injection tests for `storage.rs`: mock filesystem returning ENOSPC during the `*.tmp` write; assert no partial state remains on disk (no orphan `.tmp` file, no `household_record.cbor`) and the typed error carries `error.hint` pointing to disk-space recovery action, in `admin/rust/household-rs/tests/storage_atomic.rs`
- [X] T011 [P] Unit tests for `ids.rs`: identifier regex validation, BLAKE3 path round-trip, SHA-256 fallback path round-trip (gated), tamper detection on `hh_id` recompute mismatch, in `admin/rust/household-rs/tests/ids_roundtrip.rs`
- [X] T012 [P] Unit tests for software `P256Keypair`: ECDSA P-256 sign/verify round-trip with `p256::ecdsa::VerifyingKey`, SEC1 compressed public key serialization round-trip (33-byte form), zeroize-on-drop sanity test on the secret scalar, in `admin/rust/household-rs/tests/keys_signing.rs`
- [X] T012a [P] (macOS-only target) Integration tests for `P256SeKeypair`: create SE-backed keypair, sign a known message, verify with `p256` software verifier on the exported SEC1 public key (cross-impl interop check), assert that attempting to access `sec_key_ref` via debug-formatter never reveals scalar material, assert the `THEYOS_FORCE_SOFTWARE_KEYS=1` escape hatch falls back to `P256Keypair`. Marked `#[cfg(target_os = "macos")]` so Linux runners skip cleanly. In `admin/rust/household-rs/tests/keys_se.rs`
- [X] T013 [P] Unit tests for `cbor.rs`: canonical encoding determinism, decode→encode byte-equality for known fixtures, refusal to decode non-canonical bytes (where applicable), in `admin/rust/household-rs/tests/cbor_roundtrip.rs`

**Checkpoint**: Foundation ready. Each user story below can now proceed (US1 first as MVP).

---

## Phase 3: User Story 1 — Fresh install creates a household identity (Priority: P1) 🎯 MVP

**Goal**: Operator runs `theyos install --household-name "Sample Home"` on a clean machine; theyOS bootstraps Household + Machine identities, persists `HouseholdRecord` and self-signed `MachineCert`, and serves `GET /api/v1/household/identity` over loopback + active Tailscale interfaces. Restart returns the same identity.

**Independent Test**: Per quickstart.md steps 1–6 — install, curl identity, restart, curl identity again, byte-identical response. Conformance test cases C1, C3, C5 (in `contracts/identity-endpoint.md`).

### Implementation for User Story 1

- [X] T014 [P] [US1] Implement `HouseholdRecord` struct + `Serialize`/`Deserialize` (CBOR map keys per `contracts/cbor-schemas.md`) + `validate()` (version=1, hh_id recompute, name length, shamir_k==shamir_n==1, members non-empty) in `admin/rust/household-rs/src/household_record.rs`
- [X] T015 [P] [US1] Implement `MachineCert` struct, `CertType` / `Platform` / `SubjectId` / `Caveat` types (per `data-model.md`), `MachineCert::sign(&hh_key: &dyn IdentityKey, &m_pub, &opts)` (canonical-bytes-without-signature → ECDSA P-256 sign; produces 64-byte raw `r || s`), `MachineCert::verify(&hh_pub: &P256PublicKey)` (canonical-bytes-without-signature → ECDSA P-256 verify via `p256` crate; refuse on `cert_type != Machine`, `derive_machine_id != m_id`, `issued_by != SubjectId::Household(hh_id)`, `!caveats.is_empty()`, signature length != 64 bytes, public key length != 33 bytes), platform auto-derivation (macOS / linux-nix via `/etc/NIXOS` / linux-other) in `admin/rust/household-rs/src/machine_cert.rs`
- [X] T015a [P] [US1] Cert-immutability test (FR-016 third sentence): bootstrap with `gethostname()` mocked to `studio-mac`; read persisted `MachineCert`; change mock to `studio-mac-renamed`; restart theyOS; reload cert; assert `cert.hostname == "studio-mac"` (snapshot at bootstrap is invariant), in `admin/rust/e2e-rs/tests/phase1_identity_hostname_change.rs`
- [X] T016 [P] [US1] Unit tests for `MachineCert`: sign-then-verify round-trip, tamper any byte → verify fails, mismatched `hh_pub` → verify fails, unknown `cert_type` rejected, **`issued_by` set to a non-`Household` subject (e.g., `SubjectId::Person(...)` ) → verify fails (Phase 1 invariant)**, **non-empty `caveats` list → verify fails (Phase 1 invariant)**, in `admin/rust/household-rs/tests/machine_cert.rs`
- [X] T017 [P] [US1] Unit tests for `HouseholdRecord`: validation success path, name-too-long rejection, hh_id-mismatch rejection, version != 1 rejection, in `admin/rust/household-rs/tests/household_record.rs`
- [X] T018 [US1] Implement `bootstrap_or_load(state_dir, opts) -> Result<LoadedIdentity>` (depends T005–T015): generate household + machine keypairs, sign cert, write keystore entries, atomic-write both CBOR files, emit `tracing::info!` per FR-014 stages (`bootstrap.start`, `.key_gen.household`, `.key_gen.machine`, `.keystore.write{which="household"|"machine"}`, `.persist.household_record`, `.persist.machine_cert`, `.endpoint.live` deferred to listener); idempotent path emits single `bootstrap.skip` line carrying `hh_id`/`name`/`created_at`; corrupt-record path returns typed error to caller (refuse to start handled at main) in `admin/rust/household-rs/src/bootstrap.rs`
- [X] T019 [US1] Promote modules to public re-exports + define `LoadedIdentity` (owns `HouseholdRecord`, `MachineCert`, `m_priv`, `hh_priv`) in `admin/rust/household-rs/src/lib.rs`
- [X] T020 [P] [US1] Implement `GET /api/v1/household/identity` handler returning JSON projection `{version, hh_id, hh_pub_b64, name, created_at}` with `Cache-Control: no-store`; return 503 + `{error, code: HOUSEHOLD_NOT_BOOTSTRAPPED, hint}` when shared `LoadedIdentity` not yet ready in `admin/rust/server-rs/src/handlers_household.rs`
- [X] T021 [P] [US1] Implement household listener in `admin/rust/server-rs/src/household_listener.rs`: enumerate active concrete interface addresses (loopback always — `127.0.0.1`/`::1`; every active LAN-class IPv4/IPv6 address (`192.168/16`, `10/8`, `172.16/12`, link-local `169.254/16` and `fe80::/10` excluded); every Tailscale address — name `tailscale*` OR ranges `100.64.0.0/10` / `fd7a:115c:a1e0::/48`); refuse wildcard `0.0.0.0`/`::` by verifying the socket's local addr after bind and aborting on mismatch; spawn one `axum::serve` per concrete address; refresh interface list every 60 s via `tokio::time::interval`, adding/removing listeners idempotently; emit `bootstrap.endpoint.live` per bound address with `interface_class={loopback|lan|tailscale}` field
- [X] T021a [P] [US1] Implement Bonjour publisher (FR-017): publish `_soyeht-household._tcp` service on every active non-loopback interface (LAN + Tailscale) with TXT records `hh_id`, `hh_name`, `m_id`, `proto=1`; on macOS use `dns_sd` via `core-foundation` / `security-framework` ecosystem (or `bonjour-rs`); on Linux use `mdns-sd = "0.10"`; publish on bootstrap completion, unregister cleanly on `SIGTERM`/`SIGINT`. Add `pairing=open` + `pair_nonce=…` TXT entries while a pairing token issued by T023b is unredeemed (keyed by interior mutability shared with `pair_device.rs`). In `admin/rust/server-rs/src/bonjour_publisher.rs` — *Note: SIGTERM/SIGINT clean unregister deferred to polish phase; OS cleans up on process exit and announcements time out client-side.*
- [X] T022 [US1] Wire bootstrap call + listener startup + module registration in `admin/rust/server-rs/src/main.rs` and `admin/rust/server-rs/src/lib.rs`: call `bootstrap_or_load` before HTTP listeners come up; share `Arc<LoadedIdentity>` with handler via axum `State`; bearer-auth middleware and `/api/v1/mobile/*` routes remain untouched (FR-010)
- [X] T023 [US1] Add `theyos install` CLI subcommand parsing `--household-name <Sample Home>` (1..=64 printable Unicode), optional `--hostname-label <studio-mac>` (1..=255), and the **idempotent helper flag `--reissue-pair-qr`** (skips bootstrap path entirely, just opens a fresh pair-receiving window via T023b's `mint_token` and emits a new QR via T023a — for cases where the operator missed the install-time scan). Exit 0 on idempotent rerun (no-`--reissue-pair-qr` rerun on bootstrapped install) and on `--reissue-pair-qr` success. Exit non-zero on any bootstrap failure with formatted error pointing to `error.hint`. In `admin/rust/server-rs/src/main.rs`
- [X] T023a [US1] Implement terminal QR renderer (`render_ansi_qr(uri: &str) -> String`) producing a small ANSI-block QR (UPPER HALF BLOCK / LOWER HALF BLOCK chars, ECC level Q, ~37×37 modules for typical pairing URI lengths) using `qrcode = "0.14"` for the matrix, then compositing two-row-per-line ANSI output for compactness; emit at end of `theyos install` after `bootstrap.endpoint.live` with surrounding text "Scan with Soyeht on your iPhone to claim owner role within 5 minutes" in `admin/rust/household-rs/src/qr_render.rs` + invocation in `admin/rust/server-rs/src/main.rs` (FR-018)
- [X] T023b [US1] Implement pair-device endpoints with **window gating** (FR-018): `PairWindow` state struct (`Arc<RwLock<Option<PairToken>>>` where `PairToken = {nonce: [u8;32], expires_at: Instant, p_id_hint: Option<PersonId>}`); `pair_device::mint_token(p_id_hint, ttl=300s)` atomically replaces any existing token (single token at a time invariant), returns the `soyeht://household/pair-device?...` URI per protocol §11; `POST /api/v1/household/pair-device/initiate` is retrieve-only and returns the current URI; `POST /api/v1/household/pair-device/confirm` validates a non-expired nonce plus device `d_pub` shape, consumes the token, returns `{ consumed: true }`, and closes the window. PersonCert + DeviceCert issuance is explicitly Phase 2 after the iPhone-side handshake design lands. Routes registered conditionally via axum window checks: when `PairWindow.is_none()`, BOTH `/pair-device/initiate` and `/pair-device/confirm` MUST return `404 Not Found` with empty body (route absent — never `403`). `PairWindow` exposes a `subscribe()` channel used by `bonjour_publisher.rs` (T021a) to flip TXT `pairing=open` + `pair_nonce=<short>` in real time. In `admin/rust/household-rs/src/pair_device.rs` + `admin/rust/server-rs/src/handlers_pair_device.rs`. Window opens at install-time auto-mint (T023a) and on operator-triggered `--reissue-pair-qr` flag.
- [X] T024 [US1] e2e test covering identity-endpoint conformance C1, C3, C5 (fresh install → 200 with valid `hh_id` derived from `hh_pub_b64`; two consecutive 200s byte-identical; idempotent install rerun preserves response) plus restart-determinism check, in `admin/rust/e2e-rs/tests/phase1_identity.rs`
- [X] T024a [P] [US1] Log-shape **and timing** assertion test using `tracing-test` capture: assert that a fresh bootstrap emits exactly the FR-014 stage set (`bootstrap.start`, `.key_gen.household`, `.key_gen.machine`, `.keystore.write{which="household"|"machine"}`, `.persist.household_record`, `.persist.machine_cert`, `.endpoint.live`, `.bonjour.published`, `.pair_window.opened`); each entry carries `ts`, `stage`, `elapsed_ms`, `result`; **assert SC-001 hard contract: sum of `elapsed_ms` from `bootstrap.start` to `bootstrap.endpoint.live` is < 2000 ms** (test fails CI if the 2-second budget is breached); idempotent rerun emits exactly one `bootstrap.skip` line with `hh_id`/`name`/`created_at`; injected error case (mocked keystore failure) emits an error-level entry with `error.stage`, `error.kind`, `error.hint`. In `admin/rust/household-rs/tests/bootstrap_logs.rs`
- [X] T024b [US1] Restart-determinism stress test (SC-002, hard contract): 50 boot/curl/kill cycles on a tmpfs-backed state dir, asserting full response body byte-equal across all 50 iterations on both macOS and Linux runners; default-on in `cargo test --workspace` (no `#[ignore]` gate); CI matrix runs on both targets, in `admin/rust/e2e-rs/tests/phase1_identity_restart_stress.rs`
- [X] T024c [P] [US1] Negative-route surface test: assert that `/metrics`, `/api/v1/household/members`, `/api/v1/household/devices`, `/api/v1/household/people` each return 404 from the household listener; assert that `/api/v1/household/identity` is always 200 (or 503 during the bootstrap-incomplete window). For pair-device routes, assert the **window-gating contract**: (a) immediately after install with the operator's pair token still active, both `/api/v1/household/pair-device/initiate` (200) and `/api/v1/household/pair-device/confirm` (4xx without nonce, but route present) are reachable; (b) after consuming the token via T024e or letting TTL expire, both pair-device routes MUST return **404** (route absent — never 403; FR-018 contract); (c) re-running `theyos install --reissue-pair-qr` reopens the window and the routes become reachable again. In `admin/rust/e2e-rs/tests/phase1_identity_surface.rs`
- [X] T024d [P] [US1] e2e Bonjour publication + window-mirror test (FR-017): boot theyOS, browse `_soyeht-household._tcp` from a sibling process (using `mdns-sd` resolver on Linux, `dns-sd -B` shell command on macOS via `Command`); assert SRV record port equals the listener port AND resolves to a reachable IP (curl against that addr/port returns 200 from `/identity`) — confirming FR-008 + FR-017 alignment (the announce points at a real listener); assert TXT records carry `hh_id`, `m_id`, `hh_name`, `proto=1`; **with operator's install-time pair window open**, assert TXT also carries `pairing=open` + `pair_nonce=<short>`; consume the pair token; assert TXT clears `pairing` + `pair_nonce` within 2 s of consume (real-time mirror of `PairWindow` state); reissue via `--reissue-pair-qr`; assert TXT flips back to `pairing=open`; SIGTERM theyOS; assert service unregisters within 2 s. In `admin/rust/e2e-rs/tests/phase1_bonjour.rs`
- [X] T024e [P] [US1] e2e pair-device flow + window contract test (FR-018): (a) hit `POST /api/v1/household/pair-device/initiate` during install-time window → receive URI; parse `soyeht://household/pair-device?…`; generate a P-256 keypair locally; hit `POST /api/v1/household/pair-device/confirm` with the synthesized device pubkey + the nonce; assert Phase 1 response is `{ consumed: true }` after validating `d_pub` shape. (b) Second confirm with same nonce returns **404** (window already closed — token consumption auto-closes window per T023b). (c) Wait for TTL expiry without consuming → assert `pair-device/initiate` returns **404**, Bonjour TXT no longer carries `pairing=open`. (d) Run `theyos install --reissue-pair-qr` → assert window reopens, mint succeeds, prior token is invalidated. PersonCert + DeviceCert verification moves to Phase 2. In `admin/rust/e2e-rs/tests/phase1_pair_device.rs`
- [X] T025 [US1] e2e test covering identity-endpoint conformance C2, C4, C6 (503 when state dir empty, connection refused on `0.0.0.0`-only interface, refuse-to-start when `household_record.cbor` is corrupted), in `admin/rust/e2e-rs/tests/phase1_identity_negative.rs`

**Checkpoint**: User Story 1 fully functional and testable independently. Quickstart.md steps 1–7 green. SC-001, SC-002, SC-003 measurable.

---

## Phase 4: User Story 2 — Identity is verifiable end-to-end (Priority: P2)

**Goal**: A test harness or future Phase 2 caller can load both CBOR records, recompute `hh_id`, verify the MachineCert signature, and confirm `m_pub` consistency. Tampering any byte fails verification.

**Independent Test**: US2 acceptance scenarios 1–3 in spec.md (BLAKE3 round-trip, signature verify, single-bit tamper detection).

### Implementation for User Story 2

- [X] T026 [P] [US2] Implement chain verifier `verify_loaded_chain(record: &HouseholdRecord, cert: &MachineCert) -> Result<()>` checking: `derive_household_id(&record.hh_pub) == record.hh_id`, `cert.hh_id == record.hh_id`, `cert.issued_by == SubjectId::Household(record.hh_id.clone())`, `cert.caveats.is_empty()`, `derive_machine_id(&cert.m_pub) == cert.m_id`, and `cert.verify(&record.hh_pub).is_ok()`, in `admin/rust/household-rs/src/chain.rs`
- [X] T027 [P] [US2] Unit tests for chain verifier: success path, hh_id mismatch, m_id mismatch, signature mismatch, single-byte CBOR tamper on either record fails chain verify (US2 acceptance scenarios 1–3), in `admin/rust/household-rs/tests/chain.rs`
- [X] T028 [US2] e2e test that loads on-disk CBORs from a freshly bootstrapped state dir, calls `verify_loaded_chain`, then mutates each file by one byte and reasserts failure, in `admin/rust/e2e-rs/tests/phase1_identity_chain.rs`

**Checkpoint**: US1 + US2 both pass independently. Phase 2 (proof-of-possession auth) has a verifiable substrate to build on.

---

## Phase 5: User Story 3 — Pre-existing dev/test installs are wiped on upgrade (Priority: P3)

**Goal**: When the upgrader detects legacy schema (`users`, `mobile_sessions`, or `invites` tables) AND `household_record.cbor` does not yet exist, drop those tables atomically and bootstrap normally. Non-interactive (no prompts).

**Independent Test**: Restore a legacy snapshot, run upgrader, confirm tables gone + identity bootstrapped + legacy bearer tokens rejected (US3 acceptance scenarios 1–2).

### Implementation for User Story 3

- [X] T029 [P] [US3] Implement `has_legacy_tables(conn) -> Result<LegacyDetection>` (returns names + row counts of any of `users`/`mobile_sessions`/`invites` present) in `admin/rust/store-rs/src/legacy_migration.rs`
- [X] T030 [US3] Implement `drop_legacy_atomic(conn, detection) -> Result<()>` (single SQLite transaction `BEGIN`/`DROP TABLE`/`COMMIT`, emits `tracing::info!(stage = "migration.legacy_dropped", tables, row_counts)`) in `admin/rust/store-rs/src/legacy_migration.rs` (same file as T029, sequential)
- [X] T031 [US3] Register module in `admin/rust/store-rs/src/lib.rs` and expose function signatures for `bootstrap_or_load` consumer
- [X] T032 [US3] Wire migration into bootstrap path: invoke `has_legacy_tables` + `drop_legacy_atomic` from inside `bootstrap_or_load` BEFORE keypair generation, gated by absence of `household_record.cbor` (no-op once Phase 1+ already ran), in `admin/rust/household-rs/src/bootstrap.rs` (modifies T018)
- [X] T033 [P] [US3] Unit tests for `legacy_migration.rs`: detection on synthetic SQLite (with and without each table), atomic drop verifies post-state, partial-failure rollback, in `admin/rust/store-rs/tests/legacy_migration.rs`
- [X] T034 [US3] e2e test in `admin/rust/e2e-rs/tests/phase1_legacy_migration.rs` (US3 acceptance 1+2): seed pre-Phase-1 SQLite snapshot with `users`+`mobile_sessions`+`invites` rows; run install; assert tables absent, fresh `hh_id` issued, legacy bearer token attempts on still-existing `/api/v1/mobile/*` are rejected because the token store is gone

**Checkpoint**: All three user stories independently functional. Phase 1 ships when polish is done.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Documentation, lint, target-coverage, and the SC-005 quickstart proof.

- [X] T035 [P] Update `admin/rust/README.md` with `household-rs` overview, install/bootstrap walkthrough, and pointer to `specs/001-phase-1-crypto-skeleton/quickstart.md`
- [X] T036 [P] Run `cargo clippy --workspace --all-targets -- -D warnings` and fix any violations introduced by Phase 1 code
- [X] T037 [P] Run `cargo test --workspace --all-targets` on macOS 14+ Apple Silicon and Linux x86_64 targets; record results in PR description (SC-004 cross-target coverage)
- [X] T037a [P] Criterion benchmark with hard p95 assertion for `GET /api/v1/household/identity` (SC-003): 1000 sequential requests on loopback against a pre-bootstrapped fixture, capture p50/p95/p99, **fail CI if p95 ≥ 100 ms**; run on both macOS and Linux runners; in `admin/rust/e2e-rs/benches/phase1_identity.rs`
- [X] T038 SC-005 timed walkthrough on a fresh VM following `specs/001-phase-1-crypto-skeleton/quickstart.md`; record wall-clock; if > 5 min, file blocker bug against quickstart wording

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately.
- **Foundational (Phase 2)**: Depends on Phase 1 — BLOCKS all user stories.
- **US1 (Phase 3)**: Depends on Phase 2. MVP target.
- **US2 (Phase 4)**: Depends on Phase 2 (specifically T014 + T015). Independent of US1 endpoint code, but the e2e test in T028 reuses the on-disk artifacts produced by US1's bootstrap.
- **US3 (Phase 5)**: Depends on Phase 2; T032 modifies T018 (bootstrap path), so US3 implementation completes after US1 implementation is in place.
- **Polish (Phase 6)**: Depends on all desired user stories being complete.

### Within Each User Story

- Models / structs before services (e.g., T014/T015 before T018).
- Services before endpoints (T018 before T020/T021).
- Endpoints + listener before integration tests (T020/T021/T022 before T024/T025).
- Within US3: T029 before T030 (same file); T030 before T032 (T032 calls into T030).

### Parallel Opportunities

- **Setup**: T003 and T004 in parallel after T001/T002 land.
- **Foundational**: T005, T006, T007, T007a, T008, T009, T009a, T010, T010a, T011, T012, T012a, T013 — 13 independent files, all parallel (highest fan-out in the plan).
- **US1**: T014, T015, T015a, T016, T017 in parallel (different files); T018 sequenced after T015; T020 + T021 + T021a in parallel (different `server-rs/src/` files); T022 sequential (touches multiple `server-rs` files); T023a + T023b in parallel with T022 once T015 + T021 are landed; T024a, T024b, T024c, T024d, T024e in parallel after T022 + T023a + T023b are in.
- **US2**: T026 + T027 parallel; T028 sequential.
- **US3**: T029 + T033 parallel; T030 sequential after T029 (same file); T032 sequential (modifies T018); T034 last.
- **Polish**: T035, T036, T037, T037a parallel; T038 sequential (manual run).

---

## Parallel Example: Phase 2 (Foundational)

```bash
# Launch all 13 foundational tasks together (independent files):
Task: "Implement error types in admin/rust/household-rs/src/error.rs"                                # T005
Task: "Implement HouseholdId/MachineId in admin/rust/household-rs/src/ids.rs"                        # T006
Task: "Implement P256Keypair (software, IdentityKey trait) in admin/rust/household-rs/src/keys.rs"   # T007
Task: "Implement P256SeKeypair (macOS-only SE-backed) in admin/rust/household-rs/src/keys_se.rs"     # T007a
Task: "Implement deterministic CBOR helpers in .../household-rs/src/cbor.rs"                          # T008
Task: "Implement keystore wrapper in admin/rust/household-rs/src/keystore.rs"                         # T009
Task: "Failure-injection tests in admin/rust/household-rs/tests/keystore_errors.rs"                   # T009a
Task: "Implement atomic CBOR I/O in admin/rust/household-rs/src/storage.rs"                           # T010
Task: "Failure-injection tests in admin/rust/household-rs/tests/storage_atomic.rs"                    # T010a
Task: "Unit tests in admin/rust/household-rs/tests/ids_roundtrip.rs"                                  # T011
Task: "Unit tests in admin/rust/household-rs/tests/keys_signing.rs"                                   # T012
Task: "(macOS-only) SE integration tests in admin/rust/household-rs/tests/keys_se.rs"                 # T012a
Task: "Unit tests in admin/rust/household-rs/tests/cbor_roundtrip.rs"                                 # T013
```

## Parallel Example: User Story 1

```bash
# Models + their tests, in parallel (different files):
Task: "HouseholdRecord struct in admin/rust/household-rs/src/household_record.rs"  # T014
Task: "MachineCert struct in admin/rust/household-rs/src/machine_cert.rs"          # T015
Task: "MachineCert tests in admin/rust/household-rs/tests/machine_cert.rs"         # T016
Task: "HouseholdRecord tests in admin/rust/household-rs/tests/household_record.rs" # T017
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 (Setup) — T001–T004.
2. Complete Phase 2 (Foundational) — T005, T006, T007, T007a, T008, T009, T009a, T010, T010a, T011, T012, T012a, T013. **Critical gate; blocks everything.**
3. Complete Phase 3 (US1) — T014, T015, T015a, T016, T017, T018, T019, T020, T021, T021a, T022, T023, T023a, T023b, T024, T024a, T024b, T024c, T024d, T024e, T025.
4. **STOP and VALIDATE**: run quickstart.md steps 1–7; SC-001 (<2 s bootstrap) auto-asserted by T024a's `elapsed_ms` sum check; SC-002 (50 restart cycles, byte-equal across all) auto-asserted by T024b; SC-003 (p95 < 100 ms) auto-asserted by T037a benchmark; FR-017 Bonjour TXT contract auto-asserted by T024d; FR-018 pair-window contract auto-asserted by T024c + T024e.
5. Demo and merge as MVP if green.

### Incremental Delivery After MVP

1. Add US2 (T026–T028) — extra confidence for Phase 2 auth substrate.
2. Add US3 (T029–T034) — closes the legacy-wipe story.
3. Polish (T035–T038, T037a) — documentation, lint, SC-005 timing, p95 benchmark.

### Parallel Team Strategy

- 3-dev team after Phase 2 lands:
  - Dev A: US1 (the bulk of the work, MVP gate)
  - Dev B: US2 (small, lands as soon as T015 is in)
  - Dev C: US3 (independent of US1 endpoint work; depends on T015 + T018 surface)
- All converge in Polish.

---

## Notes

- `[P]` tasks = different files, no dependency on incomplete tasks.
- `[Story]` label maps each task to a single user story for traceability.
- Each user story should be independently completable and testable per its acceptance scenarios.
- Constitutional gates (Apple Quality, Capability-Based, Local-First, Adoption-First, Spec-Driven) are re-checked at the end of each user story before moving to the next.
- No commits performed automatically — `feedback_no_auto_commit` requires explicit user authorization for any `git commit`.
- All code, comments, commit messages, PR titles, and tag annotations MUST be in English (`feedback_code_artifacts_in_english`).
- Avoid: vague tasks, same-file conflicts marked `[P]`, cross-story dependencies that break independent testability.
