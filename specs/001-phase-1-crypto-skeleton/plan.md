# Implementation Plan: Phase 1 — Cryptographic Skeleton (theyOS)

**Branch**: `001-phase-1-crypto-skeleton` | **Date**: 2026-05-06 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-phase-1-crypto-skeleton/spec.md`

## Summary

theyOS gains a **first-class cryptographic identity** distinct from the current bearer-token user model. On first install, a Household root EC P-256 keypair and a Machine EC P-256 keypair are generated **inside the Secure Enclave on macOS** (`kSecAttrTokenIDSecureEnclave`) or, on Linux, in software via the `p256` crate with the private scalar stored in the OS keystore. The two keys are tied together by a self-signed `MachineCert` (CBOR with 64-byte raw `r || s` ECDSA P-256 signatures and 33-byte SEC1 public keys). A new public, unauthenticated endpoint `GET /api/v1/household/identity` exposes the household public key + metadata, bound only to loopback and Tailscale. theyOS publishes a `_soyeht-household._tcp` Bonjour service announcement so future LAN discovery (Phase 3) just works. At the end of `theyos install` the operator sees a single-use owner-device pairing QR (`soyeht://household/pair-device?…`) for the iPhone-side companion (Phase 2). Existing bearer-token auth and `/api/v1/mobile/*` endpoints are not modified — Phase 1 is additive at the legacy API layer.

The technical approach: introduce a new workspace crate `household-rs` for primitives (keypair gen, CBOR codec, `hh_id` / `m_id` derivation, MachineCert signing/verification, OS keystore I/O via the `keyring` crate). `server-rs` mounts the new endpoint and triggers bootstrap during startup. `store-rs` gains the destructive migration step that drops legacy `users`, `mobile_sessions`, `invites` tables on detection. Logs are emitted as JSON lines via the workspace's existing `tracing` + `tracing-subscriber` stack. Sole-shard mode is the default (single-machine plaintext-in-keystore); Phase 3 introduces Shamir splitting.

## Technical Context

**Language/Version**: Rust 1.85 (workspace `rust-toolchain.toml`), Edition 2024
**Primary Dependencies**:
- New: `p256 = "0.13"` (cross-platform ECDSA P-256 + ECDH), `security-framework = "2"` (macOS Secure Enclave via `SecKey`), `blake3 = "1"`, `ciborium = "0.2"`, `keyring = "3"` (Linux only path), `data-encoding = "2"` (URL-safe base32), `mdns-sd = "0.10"` (Linux Bonjour publishing) + `dns_sd` via Core Foundation (macOS Bonjour publishing), `qrcode = "0.14"` + `qrcode-terminal-ansi`-style ANSI block renderer (~50 LoC) for QR emission
- Dev: `tracing-test = "0.2"` (log shape assertions), `criterion = "0.5"` (p95 benchmark)
- Existing reused: `axum`, `tokio`, `serde`, `serde_json`, `tracing`, `tracing-subscriber`, `rand`, `sha2` (BLAKE3 fallback)
- Existing keepers: bearer-auth middleware in `server-rs/src/auth.rs` is untouched; existing `/api/v1/mobile/*` handlers untouched
**Storage**:
- Identity files (CBOR): `$THEYOS_STATE_DIR/household/household_record.cbor` and `machine_cert.cbor` (mode 0600)
- Private keys: `M_priv` and `HH_priv` in OS keystore (`keyring` crate); never on disk in cleartext
- SQLite (`theyos.db`): legacy tables dropped on upgrade; no new tables this phase (event log lands Phase 4)
**Testing**: `cargo test --workspace` for unit + integration; `e2e-rs` workspace member for end-to-end (Linux + macOS targets)
**Target Platform**: macOS 14+ (Apple Silicon, Intel) and Linux x86_64 / aarch64 (NixOS plus generic with Secret Service or kernel keyring)
**Project Type**: Rust web service (axum) inside a Cargo workspace; new internal crate `household-rs` added to the workspace at `admin/rust/household-rs/`
**Performance Goals**:
- Bootstrap end-to-end (key gen + persist + endpoint up) < 2 s wall-clock on Mac mini M2 / Linux i5 (SC-001)
- `GET /api/v1/household/identity` p95 < 100 ms on loopback under no load (SC-003)
**Constraints**:
- Identity endpoint MUST bind only to `127.0.0.1`/`::1` and active Tailscale interfaces; never `0.0.0.0`/`::` (FR-008)
- Idempotent install: rerun is a no-op exit-0 with `bootstrap.skip` log line (FR-001)
- Refuse-to-start on persisted-record corruption or signature failure (FR-012)
- No `/metrics` endpoint in Phase 1 (FR-015)
- All cryptographic operations use the constitution's named primitives only (FR-013, Engineering Standards)
**Scale/Scope**:
- Single household, single machine in this phase (members[] cardinality = 1)
- Endpoint expected hit rate: low (operator + automation only, no app clients yet)
- Changeset estimate: new crate ~600 LoC + ~200 LoC integration in `server-rs` + ~50 LoC migration in `store-rs`

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design. See `.specify/memory/constitution.md`.*

| # | Principle | Status | Notes |
|---|-----------|--------|-------|
| I | Apple-Grade Quality (no SPOF, no manual ops, automatic discovery/failover, UX hides infrastructure from non-technical users) | PASS | Idempotent install (no manual ops); automatic loopback+Tailscale binding; structured logs make failures actionable; sole-shard mode is documented as transitional and replaced automatically when Phase 3 lands. No SPOF concerns at single-machine bootstrap (the SPOF question is the household identity itself, addressed by Shamir in Phase 3). |
| II | Capability-Based Authorization (signed certs chain to household root; no RBAC; no bearer for household ops; UI rendered from local cert) | PASS | Phase 1 introduces the cryptographic substrate (root keypair, self-signed MachineCert) that capabilities chain from. The `/identity` endpoint is intentionally unauthenticated by design (returns only public material) and therefore does not require the proof-of-possession middleware that Phase 2 introduces. No RBAC introduced. |
| III | Local-First Identity & State (no central cloud control plane; Bonjour + Tailscale only) | PASS | Identity material is generated and stored locally; OS keystore is the only secret store; endpoint binds only to loopback + Tailscale. No outbound calls during bootstrap. |
| IV | Adoption-First, No Legacy Compatibility (no parallel old/new code paths; phase ends end-to-end functional) | PASS | The destructive migration (drop legacy `users` / `mobile_sessions` / `invites`) is part of Phase 1's bootstrap (FR-011); existing bearer auth on `/api/v1/mobile/*` is **temporarily** retained because Phase 1 is the additive substrate. Phase 2 removes the bearer path entirely. There is no fork/flag governing which code path runs. |
| V | Specification-Driven Development (closed plan, no open alternatives; English artifacts; spec exists before implementation) | PASS | Spec v0.1 is closed, ratified product decisions are recorded, clarification round complete (5/5), this plan selects one option per technical choice (no "we could do A or B" left). All artifacts in English. |

Engineering standards check:

- [x] Apple APIs used precisely (Apple-platform features only; N/A in pure Rust backend code) — N/A in this Rust crate; the macOS Keychain access goes through the `keyring` crate which uses `Security.framework` correctly
- [x] Cryptographic primitives match **Constitution v2.0.0** Engineering Standards (EC P-256 ECDSA + ECDH, BLAKE3-256/SHA-256, ChaCha20-Poly1305, Shamir GF(256)) — Phase 1 uses ECDSA P-256 + BLAKE3 + Secure Enclave residency on Apple platforms; ECDH/ChaCha20-Poly1305/Shamir arrive in later phases. Public keys are 33-byte SEC1, signatures are 64-byte raw `r || s`
- [x] No silent error swallowing at protocol boundaries — bootstrap aborts non-zero on any keystore/persistence/signature failure; verification on load aborts startup; no `unwrap_or_default` on signature paths
- [x] Tests planned at protocol boundaries — see Phase 1 Design (data-model + contracts) and SC-004

**Result**: All gates PASS. No entries needed in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/001-phase-1-crypto-skeleton/
├── plan.md              # This file
├── spec.md              # Feature spec (closed)
├── research.md          # Phase 0 — library + storage + binding decisions
├── data-model.md        # Phase 1 — Household / Machine / MachineCert in Rust types
├── quickstart.md        # Phase 1 — operator quickstart for fresh install + verification
└── contracts/
    ├── identity-endpoint.md   # HTTP contract for GET /api/v1/household/identity
    └── cbor-schemas.md        # Canonical CBOR schemas for HouseholdRecord and MachineCert
```

### Source Code (repository root)

```text
admin/rust/
├── Cargo.toml                         # workspace — add `household-rs` member, add new shared deps
├── household-rs/                      # NEW crate
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                     # re-exports
│       ├── ids.rs                     # hash convention + base32 encoder, hh_id/m_id derivation
│       ├── keys.rs                    # P-256 keypair: P256Keypair (software) + P256SeKeypair (macOS SE-backed) behind IdentityKey trait
│       ├── cbor.rs                    # deterministic CBOR encode/decode helpers
│       ├── household_record.rs        # HouseholdRecord struct + (de)serialization
│       ├── machine_cert.rs            # MachineCert struct, sign, verify
│       ├── keystore.rs                # OS keystore wrapper: SE attribute set on macOS via security-framework, keyring crate on Linux
│       ├── storage.rs                 # filesystem layout under $THEYOS_STATE_DIR/household/
│       ├── bootstrap.rs               # orchestrates first-install vs idempotent paths
│       ├── pair_device.rs             # NEW — owner-device pairing token mint + redeem (one-shot, TTL 5min)
│       └── qr_render.rs               # NEW — ANSI block QR renderer for terminal output of soyeht:// URIs
├── server-rs/
│   └── src/
│       ├── handlers_household.rs      # NEW — GET /api/v1/household/identity handler
│       ├── handlers_pair_device.rs    # NEW — POST /api/v1/household/pair-device/{initiate,confirm}
│       ├── household_listener.rs      # NEW — picks loopback + active Tailscale interfaces
│       ├── bonjour_publisher.rs       # NEW — _soyeht-household._tcp service announce (cross-platform via mdns-sd Linux + dns_sd macOS)
│       ├── lib.rs                     # MODIFIED — register new modules
│       └── main.rs                    # MODIFIED — bootstrap call + listener wiring + Bonjour publish + QR emission at install end
└── store-rs/
    └── src/
        └── instance_db.rs             # MODIFIED — legacy schema detection + drop migration

tests/
├── household-rs/                      # unit tests inside the crate (CBOR round-trip, sign/verify, hh_id derivation)
└── e2e-rs/
    └── tests/
        └── phase1_identity.rs         # NEW e2e — fresh install, restart, idempotent rerun, identity endpoint
```

**Structure Decision**: New workspace crate `household-rs` colocated with existing crates under `admin/rust/`. Rationale: (1) crypto primitives have no dependency on `server-rs` or `store-rs` and are reusable by other crates (terminal-rs, claw-rs in later phases will need cert validation); (2) keeping crypto isolated makes the audit surface narrow and the test boundary clean; (3) the existing workspace pattern already separates concerns this way (`core-rs`, `store-rs`, etc.). The endpoint handler lives in `server-rs/handlers_household.rs` next to the other `handlers_*.rs` files for consistency.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

No violations. Section intentionally empty.
