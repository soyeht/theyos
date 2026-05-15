# Implementation Plan: Phase 3 - Machine Join Ceremony with Owner Confirmation and Shamir Splitting (theyOS)

**Branch**: `003-machine-join` | **Date**: 2026-05-06 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/003-machine-join/spec.md`

## Summary

Phase 3 admits a second theyOS machine into a Phase-2 single-machine household. The candidate machine M2 generates an EC P-256 machine keypair locally, opens a join window, and either (a) advertises itself on the LAN under the existing `_soyeht-household._tcp` Bonjour service with a join-machine subtype distinguishing it from the Phase-2 pair-device window, or (b) prints a `soyeht://household/pair-machine` QR (the only path when M1 and M2 are not on the same LAN). The founding machine M1 stages the join as an owner event, and the owner iPhone retrieves it through an authenticated long poll over Tailscale; an opaque silent APNS notification is used only to wake the iPhone when no poll is open. After the owner approves with biometry, M1 performs an atomic ceremony that destructively replaces sole-shard root custody with a `(2, 2)` Shamir split, issues exactly one `MachineCert` for M2 signed under the household root, persists its own new shard plus the new household record, and only then returns `MachineCert`, M2's shard, the household record, and a peer list to the candidate. The ceremony rolls back to single-machine sole-shard custody on any pre-commit failure.

The technical approach extends `household-rs` with a new `pair_machine` join-window state (mirroring `pair_device`), `machine_cert` issuance under household root, a `shamir` module wrapping `vsss-rs` for `(2, 2)` GF(256) splits, an `owner_events` stream backed by a CBOR-on-disk append log + an in-memory broadcaster, an `apns_dispatcher` for opaque tickles only, and an anti-phishing `fingerprint` helper. `server-rs` adds the `/api/v1/household/join-request`, `/api/v1/household/owner-events`, and `/api/v1/household/owner-device/push-token` handlers, plus a Bonjour subtype reflector that switches the active TXT record between `pair-device`, `pair-machine`, and idle. No gossip, CRL, invitations, DeviceCert delegation, or Claw migration is in scope; the ceremony's output is a 2-machine household record and matching shards, nothing more.

## Technical Context

**Language/Version**: Rust 1.85, Edition 2024
**Primary Dependencies**: existing `household-rs`, `server-rs`, `store-rs`, `e2e-rs`, `p256`, `blake3`, `ciborium`, `data-encoding`, `zeroize`, `subtle`, `base64`, `axum`, `tokio`, `serde`, `serde_json`, `tracing`; new in this phase — `vsss-rs` (Shamir GF(256) over the 32-byte P-256 scalar), `mdns-sd` (mDNS publish/browse, already present transitively for the Phase-2 publisher; we reuse it), `a2` (APNS HTTP/2 client) gated behind a `THEYOS_PUSH_DISABLED=1` test flag, `tokio-util` broadcast utilities (already available)
**Storage**: deterministic CBOR files under `$THEYOS_STATE_DIR/household/`: new `pair_machine_window.cbor`, `shamir/self_shard.cbor`, `owner_events/log.cbor` (append) + `owner_events/cursor_head.cbor`, `owner_device_push_token.cbor`. **Unified MachineCert layout**: every cert lives at `machine_certs/<m_id>.cbor`, including the founding machine's self-cert. Phase 1's single-file `machine_cert.cbor` path is renamed to `machine_certs/<m1_id>.cbor` in this same change set (Adoption-First sweep, alongside the `pair_window.cbor` → `pair_device_window.cbor` rename). Existing `household_record.cbor`, `owner_person_cert.cbor`, `household_auth_state.cbor` are unchanged in shape. The existing sole-shard custody object in `household_root_sole.cbor` is **destructively removed** when the Shamir transition commits.
**Testing**: `cargo test --workspace --all-targets`; focused unit tests in `household-rs/tests/{pair_machine,machine_cert,shamir,owner_events,fingerprint}.rs`; handler tests in `server-rs/tests/{join_request,owner_events,push_token}.rs`; failure-injection ceremony tests in `e2e-rs/tests/phase3_*.rs`
**Target Platform**: macOS 14+ and Linux x86_64/aarch64 (matches Phase 1 / Phase 2)
**Project Type**: Rust web service and internal protocol crate inside a Cargo workspace
**Performance Goals**: Story 1 (Tailscale, owner-approves) end-to-end <30s; Story 2 (LAN, owner-approves) <15s; long-poll holds idle for 30–60s with sub-millisecond wake on event publish; Shamir split + commit + sole-shard destroy <250ms wall on M1; opaque APNS tickle dispatch <2s under nominal Apple latency
**Constraints**: no gossip, no CRL, no invitations, no DeviceCert, no Claw migration, no third-machine join; APNS payload by contract empty/opaque; founding-machine sole-shard destruction is the **last** step before commit-success and is irreversible; partial states forbidden (atomic ceremony); no plaintext household scalar persisted on disk after commit; no household metadata in any push payload; English artifacts
**Scale/Scope**: exactly one founding machine, exactly one candidate at a time, one owner iPhone, exactly one outstanding owner event during a join, household membership transitions from 1 to 2; this phase does not generalize beyond that

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| # | Principle | Status | Notes |
|---|-----------|--------|-------|
| I | Apple-Grade Quality (no SPOF, no manual ops, automatic discovery/failover, UX hides infrastructure) | PASS | LAN ceremony is fully automatic via Bonjour; remote ceremony needs only QR scan; no host arguments. The (2, 2) Shamir at exactly 2 machines is the protocol-defined minimum and is explicitly surfaced to the operator with the recovery limitation; higher-availability re-sharding is on the roadmap and acknowledged in spec. The atomic ceremony with rollback prevents the partial-state SPOF that "good-enough MVP" would risk. |
| II | Capability-Based Authorization | PASS | `MachineCert` chains to household root; owner approval requires fresh PoP from owner PersonCert under biometry; long-poll and push-token endpoints are PoP-authenticated; no bearer tokens, no role labels. |
| III | Local-First Identity & State | PASS | All authoritative event content travels over the household's Tailscale long poll; Bonjour handles LAN discovery. APNS is used **only** as an opaque wake tickle with empty payload; Apple cannot learn membership, fingerprint, or any household-scoped data from observing tickles. The push-token registry is a household-local artifact replicated within the household, not a central directory. |
| IV | Adoption-First, No Legacy Compatibility | PASS | This phase renames the Phase-2 `pair_window.cbor` → `pair_device_window.cbor` and the Phase-2 `PairWindow` symbol → `PairDeviceWindow` to make symmetric room for `PairMachineWindow`. No parallel old/new code paths; the Bonjour TXT publisher reflects exactly one window state at a time. The single legacy `mobile_token` file is unaffected (already non-household-authoritative since Phase 2). |
| V | Specification-Driven Development | PASS | Spec carries zero `NEEDS CLARIFICATION`. Three open items closed during specify (push transport, fingerprint format, Shamir parameters); plan-time decisions resolved in `research.md` below. All artifacts in English. |

Engineering standards check:

- [x] Apple APIs used precisely (Apple-platform feature on theyOS Mac side: existing Secure Enclave key handling reused unchanged)
- [x] Cryptographic primitives match Engineering Standards (EC P-256 ECDSA, ECDH for shard wrap, BLAKE3-256 (with BLAKE3 native KDF mode for shard-at-rest key derivation — same primitive, dedicated derive_key function), ChaCha20-Poly1305 for shard-at-rest, deterministic CBOR; Shamir GF(256) over the 32-byte P-256 scalar via `vsss-rs` — every primitive already declared by Constitution v2.0.0; no HKDF, no new primitive families)
- [x] No silent error swallowing at protocol boundaries (`pair_machine`, `machine_cert`, `shamir`, `owner_events`, request-PoP all surface typed `JoinError` / `OwnerEventError` variants)
- [x] Tests planned at protocol boundaries (Shamir round-trip, atomic-commit failure injection, fingerprint determinism, replay idempotence, generic-failure shape, APNS payload-opacity assertion)

**Result**: All gates PASS. No entries required in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/003-machine-join/
├── plan.md
├── spec.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── pair-machine-url.md
│   ├── bonjour-pair-machine.md
│   ├── join-request.md
│   ├── owner-events.md
│   ├── push-token-register.md
│   ├── machine-cert-cbor.md
│   ├── shamir-transition.md
│   └── fingerprint-derivation.md
├── checklists/
│   └── requirements.md
└── tasks.md            # written by /speckit-tasks, not this command
```

### Source Code (repository root)

```text
admin/rust/
├── household-rs/
│   ├── src/
│   │   ├── pair_machine.rs           # NEW - PairMachineWindow + state transitions
│   │   ├── machine_cert.rs           # MODIFIED - issue MachineCert under household root for non-self machines
│   │   ├── shamir.rs                 # NEW - (k=2,n=2) split/reconstruct over the 32-byte P-256 scalar
│   │   ├── shard_at_rest.rs          # NEW - per-machine shard encryption (ECDH(M_priv, M_pub) → ChaCha20-Poly1305)
│   │   ├── owner_events.rs           # NEW - append log + broadcaster for owner-targeted events
│   │   ├── fingerprint.rs            # NEW - 6-word BIP-39 fingerprint over BLAKE3-256(M_pub)
│   │   ├── pair_device.rs            # MODIFIED - PairWindow → PairDeviceWindow rename for symmetry
│   │   ├── storage.rs                # MODIFIED - new file paths, atomic two-phase commit helper
│   │   └── lib.rs                    # MODIFIED - re-exports
│   └── tests/
│       ├── pair_machine.rs
│       ├── machine_cert.rs
│       ├── shamir.rs
│       ├── shard_at_rest.rs
│       ├── owner_events.rs
│       └── fingerprint.rs
├── server-rs/
│   ├── src/
│   │   ├── handlers_pair_machine.rs  # NEW - POST /household/join-request
│   │   ├── handlers_owner_events.rs  # NEW - GET /household/owner-events (long-poll), POST /household/owner-device/push-token
│   │   ├── apns_dispatcher.rs        # NEW - opaque APNS tickle, no household payload
│   │   ├── bonjour_publisher.rs      # MODIFIED - reflect pair-device | pair-machine | idle subtypes/TXTs
│   │   ├── household_auth.rs         # UNCHANGED interface, still owns Soyeht-PoP extractor
│   │   ├── handlers_pair_device.rs   # MODIFIED - rename PairWindow uses
│   │   ├── household_listener.rs     # MODIFIED - register the two new route groups
│   │   └── lib.rs                    # MODIFIED - module registration
│   └── tests/
│       ├── join_request.rs
│       ├── owner_events.rs
│       └── push_token.rs
└── e2e-rs/
    └── tests/
        ├── phase3_machine_join_remote.rs   # Story 1 happy path over loopback Tailscale stub
        ├── phase3_machine_join_lan.rs      # Story 2 happy path with simulated Bonjour
        ├── phase3_atomic_rollback.rs       # Story 3 failure injection
        ├── phase3_replay_idempotent.rs     # FR-015
        └── phase3_apns_opacity.rs          # FR-005c, payload audit
```

**Structure Decision**: Keep the protocol primitives — windows, certs, Shamir, fingerprint, owner-event log — in `household-rs` so they are validated identically by handlers and by future replicating peers. Keep HTTP routing, the long-poll holding pattern (axum `Future` with `tokio::select!` over event broadcaster + timeout), the APNS dispatcher, and the Bonjour TXT-reflection plumbing in `server-rs`, where axum state already holds the existing windows and identity. The two-phase commit helper lives in `storage.rs` so any future ceremony reuses the same file-staging discipline. Renaming `PairWindow` → `PairDeviceWindow` is a one-shot Adoption-First sweep done in this PR; no compatibility shim.

## Complexity Tracking

No violations.

## Phase 0 / Phase 1 outputs

- [research.md](./research.md) — closes plan-time decisions (idempotent replay shape, atomic commit ordering, owner-event schema, cursor encoding, poll timeout, Bonjour subtype scheme, library choices, APNS opacity proof, shard-at-rest scheme).
- [data-model.md](./data-model.md) — fully types every persistent and on-the-wire object: `PairMachineWindow`, `JoinRequest`, `JoinChallenge`, `MachineCert`, `ShamirShard`, `EncryptedShard`, `HouseholdRecord` post-join, `OwnerEvent`, `OwnerEventCursor`, `OwnerDevicePushToken`, fingerprint derivation, two-phase commit envelope.
- [contracts/](./contracts/) — wire contracts for QR URI, Bonjour TXT/subtype, join-request endpoint, owner-events endpoint (incl. opaque APNS contract), push-token endpoint, MachineCert CBOR, Shamir transition commit protocol, fingerprint derivation.
- [quickstart.md](./quickstart.md) — end-to-end runbook for the e2e harness covering Stories 1, 2, 3.

After writing all Phase 1 artifacts, the constitution gate is re-evaluated below.

## Post-design Constitution Check

| # | Principle | Status | Notes |
|---|-----------|--------|-------|
| I | Apple-Grade Quality | PASS | Designs in `research.md` and `contracts/owner-events.md` keep the no-manual-host-arg property; the long-poll + opaque APNS hybrid satisfies offline-iPhone wake without sacrificing local-first authority. |
| II | Capability-Based Authorization | PASS | External join-request submission uses owner Soyeht-PoP with `household.add_machine`; Story 2 bypasses only via the in-process staging helper after M1 fetches the candidate request itself. |
| III | Local-First Identity & State | PASS | `contracts/owner-events.md` enforces an APNS payload contract of `{"aps":{"content-available":1}}` — the Apple silent-push canonical shape with no household-derived bytes; a CI lint asserts the dispatcher cannot emit any other payload. |
| IV | Adoption-First | PASS | Two Adoption-First sweeps in the same change set: Phase-2 `PairWindow` → `PairDeviceWindow` symbol rename, and Phase-1 single-file `machine_cert.cbor` → unified `machine_certs/<m_id>.cbor` directory layout for every member's cert (including the founding self-cert). No parallel old/new paths on `main`. |
| V | Specification-Driven Development | PASS | Plan carries no open alternatives; every prior `research.md` row resolves to a single chosen design with rationale. |

Re-check **PASS**.
