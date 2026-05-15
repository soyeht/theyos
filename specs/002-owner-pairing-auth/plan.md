# Implementation Plan: Phase 2 - Owner Pairing and Proof-of-Possession Auth (theyOS)

**Branch**: `002-owner-pairing-auth` | **Date**: 2026-05-06 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/002-owner-pairing-auth/spec.md`

## Summary

Phase 2 completes the backend half of install-time owner pairing. The Phase 1 pair-device window stops being a stub: `POST /api/v1/household/pair-device/confirm` now verifies the active nonce, verifies a P-256 proof from the submitted person public key, consumes the token atomically, issues exactly one owner `PersonCert` signed by the household root, persists it under the household state directory, and returns it to the Soyeht app. After pairing, household-scoped authenticated endpoints use Soyeht proof-of-possession request signatures and PersonCert caveats; bearer tokens do not grant household authority.

The technical approach extends the existing `household-rs` crate with PersonCert, caveat evaluation, pairing proof verification, owner auth-state persistence, and request PoP verification. `server-rs` upgrades the pair-device confirm handler and introduces reusable household auth middleware/extractors for new household-scoped routes. Existing legacy `/api/v1/mobile/*` bearer-token flows remain only as non-household legacy surface; they are not accepted by `/api/v1/household/*` authenticated operations.

## Technical Context

**Language/Version**: Rust 1.85, Edition 2024
**Primary Dependencies**: Existing `household-rs`, `server-rs`, `store-rs`, `e2e-rs`; existing `p256`, `blake3`, `ciborium`, `data-encoding`, `zeroize`, `subtle`, `base64`, `axum`, `tokio`, `serde`, `serde_json`, `tracing`
**Storage**: Deterministic CBOR files under `$THEYOS_STATE_DIR/household/`: new `owner_person_cert.cbor` and `household_auth_state.cbor`; existing `pair_window.cbor`, `household_record.cbor`, `machine_cert.cbor` remain
**Testing**: `cargo test --workspace --all-targets`; focused `household-rs` unit tests; `server-rs` handler tests; `e2e-rs` pairing/auth tests
**Target Platform**: macOS 14+ and Linux x86_64/aarch64, matching Phase 1
**Project Type**: Rust web service and internal protocol crate inside a Cargo workspace
**Performance Goals**: Valid pair confirmation completes in <10s end-to-end; PoP verification p95 <25ms on loopback under no load; restart auth-state load <500ms
**Constraints**: No bearer-token authority for household-scoped operations; no DeviceCert in this phase; no second-machine join, invitations, revocation, gossip, or Claw-management migration; generic auth failures must not reveal nonce/window internals
**Scale/Scope**: Single household, founding machine, exactly one first owner PersonCert; request auth validates against locally persisted owner cert only

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design. See `.specify/memory/constitution.md`.*

| # | Principle | Status | Notes |
|---|-----------|--------|-------|
| I | Apple-Grade Quality (no SPOF, no manual ops, automatic discovery/failover, UX hides infrastructure from non-technical users) | PASS | Pairing remains QR + app-confirmed; no manual host/token entry added. Single-machine root custody is inherited from Phase 1 and explicitly bounded until multi-machine joining. |
| II | Capability-Based Authorization (signed certs chain to household root; no RBAC; no bearer for household ops; UI rendered from local cert) | PASS | PersonCert is the first person capability cert; PoP replaces bearer for household-scoped authenticated routes. No role table is introduced. |
| III | Local-First Identity & State (no central cloud control plane; Bonjour + Tailscale only) | PASS | Pairing and auth state are local files; no cloud identity or telemetry dependency. |
| IV | Adoption-First, No Legacy Compatibility (no parallel old/new code paths; phase ends end-to-end functional) | PASS | Household-scoped operations reject bearer tokens in this phase. Legacy mobile endpoints may remain only for non-household migration surface and cannot grant household authority. |
| V | Specification-Driven Development (closed plan, no open alternatives; English artifacts; spec exists before implementation) | PASS | Spec is closed, checklist is green, and this plan selects concrete wire/storage contracts. |

Engineering standards check:

- [x] Apple APIs used precisely (Apple-platform features only; N/A in Rust backend except existing Secure Enclave key use from Phase 1)
- [x] Cryptographic primitives match Engineering Standards (EC P-256 ECDSA, BLAKE3-256, deterministic CBOR; no new primitives)
- [x] No silent error swallowing at protocol boundaries
- [x] Tests planned at protocol boundaries

**Result**: All gates PASS. No entries required in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/002-owner-pairing-auth/
├── plan.md
├── spec.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── person-cert-cbor.md
│   ├── pair-device-confirm.md
│   └── proof-of-possession.md
└── tasks.md
```

### Source Code (repository root)

```text
admin/rust/
├── household-rs/
│   ├── src/
│   │   ├── person_cert.rs        # NEW - owner PersonCert schema, sign, verify
│   │   ├── owner_auth.rs         # NEW - persisted owner auth state
│   │   ├── pop.rs                # NEW - pairing proof + request PoP context/verify
│   │   ├── caveats.rs            # NEW - owner caveat templates and evaluator
│   │   ├── pair_device.rs        # MODIFIED - consume path feeds cert issuance
│   │   ├── storage.rs            # MODIFIED - owner auth-state paths
│   │   └── lib.rs                # MODIFIED - re-exports
│   └── tests/
│       ├── person_cert.rs
│       ├── owner_auth.rs
│       ├── pop.rs
│       └── caveats.rs
├── server-rs/
│   ├── src/
│   │   ├── handlers_pair_device.rs  # MODIFIED - returns owner PersonCert
│   │   ├── household_auth.rs        # NEW - axum extractor/middleware for Soyeht-PoP
│   │   ├── handlers_household.rs    # MODIFIED - household auth-state visibility tests
│   │   └── lib.rs                   # MODIFIED - module registration
│   └── tests/
│       └── household_auth.rs
└── e2e-rs/
    └── tests/
        ├── phase2_owner_pairing.rs
        ├── phase2_pop_auth.rs
        └── phase2_owner_auth_restart.rs
```

**Structure Decision**: Keep protocol primitives in `household-rs` so both server handlers and future crates validate the exact same cert/signature logic. Keep HTTP routing and request extraction in `server-rs`, where axum state already holds `PairWindow` and `LoadedIdentity`. Persist owner auth state alongside Phase 1 household CBOR files to keep the root of trust and derived person cert under one audited storage boundary.

## Complexity Tracking

No violations.
