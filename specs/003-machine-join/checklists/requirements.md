# Specification Quality Checklist: Phase 3 - Machine Join Ceremony

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-05-06
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No implementation details (languages, frameworks, APIs)
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
- [x] All mandatory sections completed

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Success criteria are technology-agnostic (no implementation details)
- [x] All acceptance scenarios are defined
- [x] Edge cases are identified
- [x] Scope is clearly bounded
- [x] Dependencies and assumptions identified

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria
- [x] User scenarios cover primary flows
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification

## Notes

- All three originally-flagged open items closed during specify (2026-05-06):
  - Owner-confirmation transport: hybrid long-poll over Tailscale + opaque APNS tickle (FR-005, FR-005a–e).
  - Anti-phishing fingerprint: six BIP-39 English words from first 66 bits of BLAKE3-256(M_pub_SEC1) (FR-007).
  - Shamir parameters at first 2-machine state: (k=2, n=2), no extra custodian, with operator-facing redundancy notice and explicit deferral of higher-availability re-sharding to a later phase (FR-012, FR-012a, FR-012b).
- Eight `/speckit-analyze` findings remediated (2026-05-06):
  - **C1** Story 1 protocol gap closed: QR carries the candidate's `challenge_sig` plus signed-bound `hostname` and `platform` (FR-004 updated, protocol §11 updated, `contracts/pair-machine-url.md` rewritten). One-hop iPhone → M1 path, no iPhone↔M2 connectivity required.
  - **H1** Unified `machine_certs/<m_id>.cbor` layout for every member's cert (including the founding self-cert). One-shot Adoption-First migration alongside the `pair_window.cbor` rename. New task T005a.
  - **H2** Shard-at-rest key derivation switched from HKDF-SHA256 to BLAKE3 native KDF (`blake3::derive_key`). All references purged. Constitution stays at v2.0.0 with no amendment needed.
  - **H3** APNS opacity now enforced by three independent layers: compile-time API-shape assertion, runtime spy-transport test, source-level lint with self-test fixtures. T025/T026/T027/T028 all rewritten.
  - **M1** FR-005e wording fixed: token replication happens in this phase (where the household first grows from 1→2), not "later".
  - **M2** New FR-013a + Edge Case "Permanent post-approval candidate loss" + new T074a `RECOVERY_TIMEOUT` const + T096 regression test for orphan-MachineCert behavior.
  - **M3** Timing assertions added to T061 (SC-001 <30s) and T091 (SC-002 <15s, <2s browse). New T077a no-plaintext-HH_priv assertion task (SC-004).
  - **M4** New FR-019a forces deterministic-CBOR error bodies on every Phase 3 endpoint; legacy JSON `{"error":"unauthenticated"}` shape replaced with deterministic CBOR `{v=1, error="unauthenticated"}`.
  - **M5** Recovery probe path now two-state: `local/seed` pre-commit + `/api/v1/household/identity` post-commit. No new endpoints, reuses Phase 1's identity surface.
- Cross-repo dependency on iSoyehtTerm: the iPhone side must implement matching fingerprint derivation, long-poll cursor format, opaque-APNS handler, **and the QR `challenge_sig` verification step** (the iPhone refuses tampered QRs locally before contacting M1). Owner of that alignment is the iSoyehtTerm spec (`@agente-app`).
