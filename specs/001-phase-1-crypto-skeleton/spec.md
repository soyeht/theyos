# Feature Specification: Phase 1 — Cryptographic Skeleton (theyOS)

**Feature Branch**: `001-phase-1-crypto-skeleton`
**Created**: 2026-05-06
**Status**: Draft
**Input**: User description: "Phase 1 of Household protocol: cryptographic skeleton in theyOS Rust backend — generate the Household root EC P-256 keypair on first install (Secure Enclave-backed on macOS), generate per-Machine EC P-256 keypair (Secure Enclave-backed on macOS), persist HouseholdRecord and self-signed MachineCert in OS keystore, expose GET /api/v1/household/identity returning the household public key and metadata, publish Bonjour service announcement, emit owner-device pairing QR at install end. Per Constitution v2.0.0 + docs/household-protocol.md §§3-5, §11, §13. No replacement of existing bearer-token auth yet (Phase 2 lands that). Sole-shard mode for the household private scalar by default (single-machine, SE-resident on macOS / kernel-keyring on Linux). Destructive migration acceptable since no production users."

**Reference contract**: `docs/household-protocol.md` §3 (Cryptographic primitives), §4 (Household identity), §5 (MachineCert format, partial — self-signing path only in this phase).

## Clarifications

### Session 2026-05-06

- Q: Should `HH_priv` storage be MUST OS keystore, MAY keystore-or-file, or MUST file-only? → A: MUST OS keystore (Keychain on macOS, Secret Service / kernel keyring on Linux); bootstrap fails non-zero when keystore is unavailable.
- Q: What observability does Phase 1 emit (logs/metrics/tracing)? → A: Structured JSON-line logs for bootstrap milestones (start, key_gen, persist, cert_sign, endpoint_up) with elapsed ms; errors include stage + actionable hint. No `/metrics` endpoint in Phase 1.
- Q: How does `theyos install` behave when rerun on a machine that is already bootstrapped? → A: Idempotent — exit 0 with informational `bootstrap.skip` log line including `hh_id`, `name`, `created_at`. No regeneration, no error.
- Q: Which network interfaces does `/api/v1/household/identity` bind to? → A: Loopback (`127.0.0.1` / `::1`) and any active Tailscale interface only. Reject inbound on all other interfaces (no `0.0.0.0`).
- Q: How are `hostname` and `platform` fields derived for the MachineCert, and what happens if the OS hostname changes later? → A: Snapshot both at bootstrap. `hostname` is the OS hostname unless the operator passes `--hostname-label` (operator value wins). `platform` is auto-derived: `/etc/NIXOS` exists → `linux-nix`; other Linux → `linux-other`; Darwin → `macos`. Subsequent OS hostname changes do NOT update the cert; relabeling is a dedicated future operation.

## User Scenarios & Testing *(mandatory)*

The actors in Phase 1 are the **operator** (Owner, installing or upgrading theyOS) and **automated callers on the member network** (the Soyeht app in Phase 2 onward). Phase 1 does not yet introduce any new end-user-visible behavior beyond install-time bootstrap; its value is foundational — it gives every subsequent phase a verifiable identity to chain signatures from.

### User Story 1 - Fresh install creates a household identity (Priority: P1)

The operator runs the theyOS installer on a clean machine. During the bootstrap step, theyOS generates a brand-new Household identity (EC P-256 keypair, Secure Enclave-backed on macOS) plus a Machine identity (EC P-256 keypair, Secure Enclave-backed on macOS), persists the public material as CBOR, and self-signs a MachineCert that attests this machine as the founding member. theyOS announces itself via Bonjour (`_soyeht-household._tcp`) so future machines on the same LAN discover the household instantly, and emits a single-use owner-device pairing QR at install end so an iPhone can claim the first owner role. After install completes, the identity is queryable via the public identity endpoint and survives restart.

**Why this priority**: Without an identity that traces to the household root, no subsequent phase has anything to chain signatures from. This is the minimum viable foundation.

**Independent Test**: Run `theyos install` on a clean VM. Confirm via `curl http://localhost:<port>/api/v1/household/identity` that a stable `hh_id`, `hh_pub`, and household `name` are returned. Restart theyOS. Confirm the same `hh_id` and `hh_pub` are returned (no regeneration).

**Acceptance Scenarios**:

1. **Given** a clean machine with theyOS not yet installed, **When** the operator runs the installer with `--household-name "Sample Home"`, **Then** theyOS generates Household + Machine keypairs, persists them in CBOR, writes the MachineCert, and exits with success in under 2 seconds.
2. **Given** an installed theyOS with a household identity, **When** theyOS is restarted, **Then** the same `hh_id` and `hh_pub` are loaded without regeneration.
3. **Given** an installed theyOS, **When** any caller on the member network requests `GET /api/v1/household/identity`, **Then** the response contains `hh_id`, `hh_pub`, `name`, `created_at`, `version: 1`, encoded per the contract, and no authentication is required.

---

### User Story 2 - Identity is verifiable end-to-end (Priority: P2)

A developer or an automated test verifies that the persisted MachineCert is cryptographically valid: its signature is by the household root, its `m_pub` matches the machine's loaded public key, and `hh_id` is the BLAKE3-256 of `hh_pub`. This story exists so that Phase 2 (which begins to depend on the cert chain for auth) has a known-good substrate.

**Why this priority**: Catches subtle persistence/encoding bugs at the boundary where Phase 2 will begin signing requests.

**Independent Test**: Run a test harness that loads `HouseholdRecord` and `MachineCert` from disk, recomputes `hh_id` from the loaded public key, verifies the cert signature with the `p256` crate's ECDSA verifier (`p256::ecdsa::VerifyingKey::verify`) against the household public key, and confirms equality of `m_pub` between the record and the cert. All checks pass.

**Acceptance Scenarios**:

1. **Given** a freshly bootstrapped theyOS, **When** a verifier loads the persisted CBOR records, **Then** `hh_id == BLAKE3-256(hh_pub)` (truncated and base32-encoded per §3 hash convention).
2. **Given** a MachineCert from disk, **When** `P256::ECDSA::verify(canonical_cbor_without_signature, signature, hh_pub)` is run with the 64-byte raw `r || s` signature and 33-byte SEC1 public key, **Then** the signature is valid.
3. **Given** any byte of the persisted CBOR is mutated, **When** verification is rerun, **Then** verification fails (no silent acceptance).

---

### User Story 3 - Pre-existing dev/test installs are wiped on upgrade (Priority: P3)

An operator who previously ran an older theyOS (with the legacy `users`/`mobile_sessions`/`invites` schema) upgrades to Phase 1. The upgrader detects the legacy schema, wipes user-affecting tables, and bootstraps a fresh household identity. Existing Claws are removed; bearer tokens are invalidated. The operator is informed of the destructive step and proceeds.

**Why this priority**: The constitution forbids legacy compatibility (Principle IV). This story closes the migration story end-to-end so Phase 1 can ship without dual-path code.

**Independent Test**: Restore a snapshot of pre-Phase-1 theyOS state. Run the upgrader. Confirm that legacy tables are dropped, identity files are absent, then a fresh bootstrap runs as in Story 1. After upgrade, querying any pre-Phase-1 endpoint that depended on bearer auth returns the same answer as a fresh install (legacy state is gone).

**Acceptance Scenarios**:

1. **Given** a theyOS install with legacy `users` and `mobile_sessions` tables populated, **When** the upgrader runs, **Then** the legacy tables are dropped and a new Household identity is bootstrapped.
2. **Given** the upgrade has completed, **When** any client presents a legacy bearer token, **Then** the token is rejected (token store no longer exists).

---

### Edge Cases

- **Storage full at install time** — Bootstrap MUST fail atomically: no partial state written, exit code non-zero, error message names the failed step (key generation, CBOR encode, keystore write).
- **OS keystore locked or unavailable** (e.g., headless Linux without `secret-service`, macOS first boot before login) — Bootstrap MUST refuse to proceed and exit with a clear actionable error pointing to keystore setup steps.
- **Secure Enclave unavailable on macOS** (e.g., `SecKeyCreateRandomKey` returns `errSecNotAvailable` on a Mac without Apple Silicon / T2, or in a CI runner using software-only Keychain) — Bootstrap MUST refuse to proceed (no silent software-only fallback; that would violate FR-007's hardware-isolated-signing requirement). Error MUST name the missing facility and recommend running on Apple Silicon hardware or a T2-equipped Mac.
- **Corrupt persisted record on restart** — theyOS MUST refuse to start, log the file path and corruption type, and exit non-zero. It MUST NOT silently regenerate identity (regeneration on restart would orphan all derived state in later phases).
- **Clock skew at install** — `created_at` uses the OS wall clock; we accept whatever the OS reports. Subsequent phases that depend on monotonic ordering use vector clocks (§10), not wall clock.
- **BLAKE3 library unavailable in target environment** — In Phase 1, BLAKE3 is required on all supported targets (macOS Apple Silicon/Intel, Linux x86_64/aarch64). The SHA-256 fallback path is compiled but disabled in production (per research R2). `version: 1` in `HouseholdRecord` therefore unambiguously implies `BLAKE3-256(hh_pub)`. Reactivating SHA-256 (e.g., for an air-gapped target in a future phase) would require a new `version: 2` and a constitution amendment, not a runtime toggle.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: theyOS MUST generate a fresh EC P-256 keypair `(HH_priv, HH_pub)` for the Household exactly once, on first install. On macOS the keypair MUST be created with `SecKeyCreateRandomKey` and attribute `kSecAttrTokenIDSecureEnclave` so the private scalar resides in the Secure Enclave from creation; the host process never sees the plaintext private scalar. On Linux the keypair is created via the `p256` crate and the private scalar is wrapped at rest in the OS keystore. Re-running install on an already-bootstrapped instance MUST be idempotent: exit code 0, no regeneration, and a single `bootstrap.skip` log line carrying the existing `hh_id`, `name`, and `created_at`. Destructive re-bootstrap is not a function of `theyos install` and requires uninstall first.
- **FR-002**: theyOS MUST generate a fresh EC P-256 keypair `(M_priv, M_pub)` for the Machine on the same first install, with the same Secure Enclave residency rules as `HH_priv`.
- **FR-003**: theyOS MUST compute `hh_id = BLAKE3-256(HH_pub)` (or `SHA-256(HH_pub)` in fallback environments) truncated to 32 bytes and encoded URL-safe base32 lowercase no-padding, per the §3 hash convention. The same convention MUST be applied to derive `m_id`.
- **FR-004**: theyOS MUST persist a `HouseholdRecord` (CBOR, deterministic encoding per RFC 8949 §4.2.1) with fields `version=1, hh_id, hh_pub, name, created_at, shamir_k=1, shamir_n=1, members=[m_id]` (sole-shard mode parameters in this phase).
- **FR-005**: theyOS MUST persist a self-signed `MachineCert` (CBOR, deterministic) for the founding machine, with `issued_by = hh_id` and a valid 64-byte raw `r || s` ECDSA P-256 signature over the canonical bytes (signed via `SecKeyCreateSignature` on macOS, `p256` crate on Linux).
- **FR-006**: On macOS, `M_priv` MUST follow the same Secure Enclave residency rule as `HH_priv` (FR-007): created with `kSecAttrTokenIDSecureEnclave` so the private scalar lives in the SE from creation; signing happens via `SecKeyCreateSignature`. On Linux, `M_priv` lives in the OS keystore (Secret Service via D-Bus, or kernel keyring where unavailable). theyOS MUST NEVER persist `M_priv` as a plaintext file on disk in any mode or on any platform.
- **FR-007**: On macOS theyOS MUST hold `HH_priv` inside the Secure Enclave (`kSecAttrTokenIDSecureEnclave`); the host process MUST NEVER possess the plaintext private scalar. Signing `HH_priv` operations are performed via `SecKeyCreateSignature`, with `kSecAccessControlBiometryCurrentSet` applied so future operator-attestation paths (Phases 5+) gate at the SE on Touch ID / Face ID. On Linux theyOS MUST store `HH_priv` in the OS keystore (Secret Service via D-Bus, or kernel keyring where unavailable). theyOS MUST NOT persist `HH_priv` as a plaintext file on disk in any mode. If the keystore (or SE on macOS) is unavailable at bootstrap, theyOS MUST fail with a non-zero exit and an actionable error naming the missing facility. This is sole-shard mode and is permitted **only while the household has a single machine** (§6).
- **FR-008**: theyOS MUST expose `GET /api/v1/household/identity` returning the JSON projection `{hh_id, hh_pub_b64, name, created_at, version}`. This endpoint MUST NOT require authentication — by design, it returns only public household material (the public key, household name, creation time). The listener MUST bind to **loopback** (`127.0.0.1` and `::1`), **every active LAN interface** (so Bonjour-discovered peers on the same Wi-Fi can reach it — supports user story 2), and **every active Tailscale interface** (`tailscale*` name OR addresses in `100.64.0.0/10` / `fd7a:115c:a1e0::/48`). Binding to wildcard `0.0.0.0` or `::` is **forbidden**; the implementation MUST enumerate concrete interface addresses and bind each one explicitly so loopback-only deployments and air-gapped containers behave correctly. Listener interface set is refreshed every 60 s to pick up `tailscale up` / Wi-Fi reconnect. If no LAN or Tailscale interface is up at startup, the listener still binds to loopback and continues; only loopback is mandatory.
- **FR-009**: theyOS MUST use deterministic CBOR encoding for any signed payload. Non-deterministic encoding is forbidden.
- **FR-010**: theyOS MUST NOT modify, replace, or remove any existing `/api/v1/mobile/*` or `/api/v1/instances/*` endpoints in this phase. Phase 1 is additive at the API layer; Phase 2 begins replacement.
- **FR-011**: When the theyOS upgrader detects a pre-Phase-1 schema (existence of `users`, `mobile_sessions`, or `invites` tables), it MUST drop those tables and remove any persisted bearer tokens before running the bootstrap, per the destructive migration policy.
- **FR-012**: theyOS MUST refuse to start if persisted identity records (`HouseholdRecord` or `MachineCert`) fail to load or fail signature verification. Silent regeneration is forbidden.
- **FR-013**: All cryptographic operations MUST use the primitives named in the Constitution v2.0.0 Engineering Standards (EC P-256 ECDSA, EC P-256 ECDH, BLAKE3-256 with SHA-256 fallback). Public keys are encoded as 33-byte SEC1 compressed form. Signatures are 64-byte raw `r || s`. No alternative curves, hashes, encoding forms, or signature shapes may be introduced in this phase.
- **FR-014**: theyOS MUST emit structured JSON-line logs covering, at minimum, the bootstrap stages `bootstrap.start`, `bootstrap.key_gen.household`, `bootstrap.key_gen.machine`, `bootstrap.persist.household_record`, `bootstrap.persist.machine_cert`, `bootstrap.keystore.write`, `bootstrap.endpoint.live`, and (on idempotent re-run) `bootstrap.skip`. Each entry MUST include `ts` (RFC 3339), `stage`, `elapsed_ms`, and `result` (`ok` or `error`). The `bootstrap.skip` entry MUST additionally carry `hh_id`, `name`, and `created_at`. Error entries MUST include `error.stage`, `error.kind`, and an actionable `error.hint` field naming the next operator action.
- **FR-015**: theyOS MUST NOT expose a `/metrics` endpoint in Phase 1. Metrics scraping is deferred to a later phase when a consumer exists.
- **FR-016**: For the MachineCert, theyOS MUST snapshot `hostname` and `platform` at bootstrap and store them inside the signed cert. `hostname` SHALL default to the OS hostname; if `--hostname-label <value>` is provided to the installer, the operator value MUST be used instead. `platform` MUST be auto-derived: `linux-nix` when `/etc/NIXOS` exists, `linux-other` for any other Linux, `macos` on Darwin. Phase 1 MUST NOT update the cert when the OS hostname changes after bootstrap; relabeling is a dedicated operation introduced in a later phase.
- **FR-017**: theyOS MUST publish a Bonjour service announcement of type `_soyeht-household._tcp` on every active interface (loopback excluded; LAN interfaces and Tailscale interfaces included), with TXT records `hh_id=<hh_id>`, `hh_name=<name>`, `m_id=<m_id>`, `proto=1`, and (only during a pairing window) `pairing=open` plus `pair_nonce=<short nonce>`. The announcement MUST start as part of bootstrap and persist for the lifetime of the process; on shutdown the service MUST be unregistered cleanly. Phase 1 only publishes; the discovery client lands in Phase 3, but the wire format is locked here.
- **FR-018**: At the end of `theyos install`, theyOS MUST atomically (a) mint a single-use owner-device pairing token (random 32-byte nonce, TTL 5 minutes, server-tracked), (b) open a **pair-receiving window**, and (c) render the resulting `soyeht://household/pair-device?v=1&hh_pub=<…>&nonce=<…>&p_id=<…>&ttl=<…>` URI as an ANSI-block QR in the terminal with surrounding text "Scan with Soyeht on your iPhone within 5 minutes to claim owner role". theyOS MUST expose `POST /api/v1/household/pair-device/initiate` and `POST /api/v1/household/pair-device/confirm`. **`initiate` is retrieve-only** — it returns the URI of the currently active token and never mints a fresh one; minting is the sole prerogative of the install-time CLI flow (`theyos install` and `theyos install --reissue-pair-qr`), which requires shell access on the host. This closes the takeover vector where an unauthenticated peer on the LAN/Tailscale could otherwise hit `/initiate` and atomically invalidate the operator's printed QR. **`confirm`** consumes the token, validates the device public key, and (Phase 2) issues PersonCert + DeviceCert; in Phase 1 it returns `{ consumed: true }` and closes the window. Both endpoints are mounted on the same listener as `/identity` (FR-008 interface set), but **gated by the pair-receiving window**: outside the window both endpoints MUST return **404** (route absent — not 403). All `confirm` failure modes (closed window, expired token, wrong nonce, malformed body) MUST also return **404** so an attacker cannot probe for live pairing flows or oracle the right nonce via response codes. The window opens on `theyos install` mint-and-emit, closes when the operator's token is consumed (success path) OR after the TTL expires (timeout). After the window closes, no new tokens are minted unless the operator explicitly re-runs `theyos install --reissue-pair-qr` (Phase 1 supports `--reissue-pair-qr` as an idempotent helper that mints a new window without rebootstrapping). Bonjour TXT records `pairing=open` + `pair_nonce=<short>` MUST mirror the window state in real time per FR-017. Phase 1 implements the routing surface, the QR emission, and the `--reissue-pair-qr` helper; the cert-issuance side of `confirm` and the iPhone-side handler ship in Phase 2. URI grammar MUST match `docs/household-protocol.md` §11 — the install-time variant carries `hh_pub` (the household root key) so the scanning device can verify the household identity before submitting; the `d_pub` form is reserved for the Phase 5+ "person adds a 2nd device" flow.

### Key Entities

- **Household** — Represented on disk by a `HouseholdRecord` (CBOR). Attributes: `version`, `hh_id` (derived), `hh_pub`, `name`, `created_at`, `shamir_k`, `shamir_n`, `members[]`. The household is the root of trust for everything that follows.
- **Machine** — Represented by a `MachineCert` (CBOR, self-signed in Phase 1). Attributes per §5: `m_id`, `m_pub`, `hostname`, `platform`, `joined_at`, `issued_by = hh_id`, `signature`. The cert is what every later phase verifies to establish that this machine belongs to the household.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A clean install completes household + machine bootstrap (key gen including SE round-trip on macOS, persist, listener up, Bonjour publish, pair-device QR mint + render) in **under 2 seconds** on the target hardware (Mac mini M2 / Linux mini i5). Asserted automatically by summing `elapsed_ms` from `bootstrap.start` through `bootstrap.endpoint.live` in T024a's tracing capture.
- **SC-002**: After bootstrap, **100% of subsequent theyOS restarts** load the identity from disk without regeneration. Tested across 50 restart cycles in CI.
- **SC-003**: `GET /api/v1/household/identity` returns within **100 ms p95** under no load, on loopback.
- **SC-004**: The test suite covers, at minimum: deterministic CBOR encode round-trip; ECDSA P-256 sign/verify round-trip (both software-only on Linux and SE-mediated on macOS); `hh_id` derivation round-trip (BLAKE3 and SHA-256 paths); MachineCert self-signature verification; identity persistence across restart; legacy schema wipe on upgrade; Bonjour TXT record contents; QR-pairing URI grammar emission. All tests pass on Linux and macOS targets.
- **SC-005**: An operator who has never seen Soyeht can complete install on a clean VM and reach a successful identity endpoint response in **under 5 minutes** following the documented install steps (covers documentation quality, not just code).

## Assumptions

- **Single-machine scope.** Only one machine in the household exists in Phase 1. Multi-machine joining (and the immediate Shamir split it triggers) is Phase 3. The schema fields `shamir_k=1, shamir_n=1` are set as a sentinel for sole-shard mode.
- **No mobile/app clients connect in this phase.** Phase 2 introduces app pairing; Phase 1 is server-only. The identity endpoint is consumable by automation but not yet by the Soyeht apps.
- **Existing legacy data is disposable.** Per the household architecture memo (2026-05-06): no real users in production, so destructive wipe of legacy `users`, `mobile_sessions`, `invites` tables is acceptable.
- **Existing bearer-token auth remains.** All previously protected endpoints continue to use the legacy bearer token in this phase. Phase 2 replaces it with proof-of-possession.
- **OS keystore is available.** The deployment target has a working OS keystore (macOS Keychain or Linux Secret Service / kernel keyring). Air-gapped or container-without-keystore deployments are not in scope for v0.1.
- **Crypto library availability.** Rust: `p256`, `blake3`, `ciborium`, `security-framework` (macOS-only path for SE) are present. macOS deployment target ≥ 10.13 (Secure Enclave + ANE). On Linux the `p256` crate covers both signing and ECDH in software.
- **Wall-clock timestamps are acceptable.** `created_at` uses OS wall clock. Monotonic ordering is not required at this phase; it arrives with vector clocks in Phase 4.
- **Endpoint is reachable on the member network only.** "Member network" in Phase 1 means loopback and any Tailscale interface theyOS is configured to bind to. No firewall rule changes are required by this phase beyond what theyOS already does.
