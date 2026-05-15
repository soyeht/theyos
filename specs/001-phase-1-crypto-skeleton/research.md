# Phase 0 — Research & Decisions

**Feature**: Phase 1 Cryptographic Skeleton (theyOS)
**Date**: 2026-05-06

This document resolves the open technology choices identified during plan creation. Each entry records the **decision**, the **rationale**, and the **alternatives considered & rejected**.

---

## R1 — OS keystore wrapper crate

**Decision**: Use the `keyring` crate (v3.x) for both macOS Keychain and Linux Secret Service / kernel keyring access.

**Rationale**:
- Single API across macOS (`Security.framework` via Core Foundation) and Linux (`secret-service` D-Bus, with kernel keyring fallback for headless / no-D-Bus environments).
- Maintained by the Rust crypto/cli ecosystem; widely used in cli tools like `cargo-credential-keyring`.
- Synchronous API matches the bootstrap path which is one-shot at startup (no need for async keystore I/O).
- Returns typed errors that translate cleanly into the actionable `error.hint` field required by FR-014 (e.g., "Linux Secret Service unavailable — install `gnome-keyring` or run with `THEYOS_KEYRING=kernel`").

**Alternatives considered**:
- **`security-framework` (macOS) + `secret-service` (Linux) as separate direct dependencies**. Rejected: forces two code paths in `keystore.rs`, doubles the conditional `#[cfg]` matrix, and we lose the proven kernel-keyring fallback that ships in `keyring`.
- **Custom file-based encrypted store with passphrase derivation (Argon2)**. Rejected: violates Q1 clarification (MUST OS keystore); regresses the security model and adds passphrase UX that the operator must remember across restarts.
- **`tokio-keyring` async wrapper**. Rejected: bootstrap is a one-shot synchronous flow; adding an async dependency for this is gratuitous.

---

## R2 — Hash function: BLAKE3 vs SHA-256 default

**Decision**: BLAKE3 is the **default and required** path. The "SHA-256 fallback" mentioned in the protocol spec §3 applies only to platforms where BLAKE3 cannot be used; for Phase 1 (Linux x86_64/aarch64 + macOS Apple Silicon/Intel) BLAKE3 is always available, so SHA-256 is **not** activated. The fallback code path is implemented and tested but unreachable in production targets.

**Rationale**:
- BLAKE3 is materially faster on the supported platforms; no measured downside.
- `blake3` crate (v1.x) is mature, has `no_std`-capable variants, and ships SIMD optimizations.
- The protocol spec already records the chosen hash inside `HouseholdRecord` (`version=1` implies BLAKE3 by default), so re-derivation by future tooling has no ambiguity.
- Keeping the SHA-256 path implemented (behind `cfg(feature = "hash-sha256-fallback")`) costs nothing and unblocks any future air-gapped target.

**Alternatives considered**:
- **SHA-256 only** (drop BLAKE3). Rejected: BLAKE3 is the protocol-preferred hash; defaulting to SHA-256 just because it's already in `Cargo.toml` is the kind of "good enough" shortcut Principle I forbids.
- **Make hash function configurable per-install via env var**. Rejected: invariant identifiers should not depend on operator configuration; reproducibility of `hh_id` derivation is a debuggability property.

---

## R3 — On-disk file layout for CBOR records

**Decision**:
```
$THEYOS_STATE_DIR/household/
├── household_record.cbor    (mode 0600, owner = theyos process user)
└── machine_cert.cbor        (mode 0600, owner = theyos process user)
```
where `$THEYOS_STATE_DIR` defaults to `/var/lib/theyos` on Linux and `~/Library/Application Support/theyos` on macOS, falling back to `$XDG_STATE_HOME/theyos` if set, matching the existing convention used by other theyOS state directories.

**Rationale**:
- CBOR records contain only public material (public keys, identifiers, metadata). Private keys live in the OS keystore and are never written to these files.
- File permissions 0600 are belt-and-suspenders; the actual confidentiality boundary is the keystore.
- A dedicated subdirectory (`household/`) prevents collision with the existing top-level state files (`bootstrap-token`, `theyos.db`, `claws/`).
- Atomic write pattern: write to `*.cbor.tmp` then `rename(2)` — guarantees a partially-written record is never observed by a reader on restart.

**Alternatives considered**:
- **Store CBOR records inside SQLite (`theyos.db`) as BLOBs**. Rejected: identity records are read once at startup and conceptually distinct from the operational state SQLite holds; mixing them complicates the destructive migration in FR-011. Filesystem keeps the boundary obvious.
- **Store private keys in the same `household/` directory in encrypted form**. Rejected: violates Q1 clarification (MUST OS keystore).
- **Single combined file**. Rejected: the two records have independent verification paths; keeping them separate makes the "corrupt one file" recovery story crisp.

---

## R4 — Listener binding strategy for `/api/v1/household/identity`

**Decision**: Add a separate axum `Router` mounted on a **dedicated listener** that binds to `127.0.0.1`, `::1`, and any active Tailscale interface (detected by enumerating interfaces matching `tailscale*` or with addresses in `100.64.0.0/10` and `fd7a:115c:a1e0::/48`). The endpoint is **not** mixed into the existing public listener that may be exposed via Cloudflare/cloudflared. Detection runs at startup and on a low-frequency refresh (every 60 s) to pick up Tailscale interface changes after `tailscale up`.

**Rationale**:
- Mixing into the existing public listener would inherit whatever bind address that listener uses (today some deployments expose `0.0.0.0`); FR-008 explicitly forbids that.
- A dedicated listener gives the security boundary at the OS socket level rather than per-route filtering, matching Principle III ("Bonjour + Tailscale only").
- Periodic refresh handles the case where `tailscale up` is run after `theyos start`; the contract still says presence of Tailscale is not a precondition (FR-008 last sentence).

**Alternatives considered**:
- **Per-route middleware that checks `RemoteAddr` against an allow-list**. Rejected: defense-in-depth is fine but the primary boundary should be at bind level — application-level filtering is more bug-prone.
- **Bind once at startup, never refresh interface list**. Rejected: forces operator to restart theyOS after Tailscale changes; fails Apple-grade "no manual ops".
- **Listen on `::` and reject in middleware**. Rejected: same concern as the per-route option, plus exposes a port to ConnTrack scanners.

---

## R5 — JSON-line logging integration

**Decision**: Use the workspace's existing `tracing` + `tracing-subscriber` stack with a new `JsonFormatter` layer enabled when `THEYOS_LOG_FORMAT=json` (default in production builds, `text` in `cargo run` development). Bootstrap stages emit `tracing::info!(stage = "bootstrap.key_gen.household", elapsed_ms = …, result = "ok")` etc. Errors emit at `error!` level with the additional `error.stage`, `error.kind`, `error.hint` fields.

**Rationale**:
- `tracing-subscriber` already has `with_env_filter` + `with_format` plumbing in `server-rs/src/main.rs`; adding a JSON formatter is a one-call change.
- Structured fields are first-class in `tracing`; no need for ad-hoc `serde_json::json!()` log macros that pollute the call sites.
- Default-on-in-prod / default-text-in-dev keeps developer ergonomics without sacrificing the production format.

**Alternatives considered**:
- **`slog` with `slog-json` formatter**. Rejected: would mean introducing a parallel logging stack to the workspace's existing `tracing`. No.
- **Hand-rolled JSON via `serde_json` per stage**. Rejected: loses span correlation, breaks consistency with existing handler logs.

---

## R6 — Idempotent install detection

**Decision**: Idempotence is detected by the presence of a valid `household_record.cbor` whose embedded `hh_id` matches `BLAKE3-256(hh_pub)`. If the file is present and verifies, emit `bootstrap.skip` and return success. If the file is present but verification fails, refuse to start (FR-012). If the file is absent, run full bootstrap.

**Rationale**:
- Verifying the record's self-consistency (hash of stored `hh_pub` equals the stored `hh_id`) on every start gives FR-012's corruption check for free at the same code path.
- No marker file or separate "install completed" sentinel is needed; the record's existence + validity is the marker.

**Alternatives considered**:
- **Database row indicating bootstrap completion**. Rejected: ties identity bootstrap to SQLite availability; SQLite is operational state, not identity state.
- **Lock file**. Rejected: lock files are for concurrent-process coordination, not for idempotence detection across restarts.

---

## R7 — Destructive migration trigger and visibility

**Decision**: On startup, before bootstrap runs, `store-rs` checks `theyos.db` for the legacy tables (`users`, `mobile_sessions`, `invites`). If any are present **and** `household_record.cbor` does not yet exist, the migration drops those tables atomically (single transaction) and logs `migration.legacy_dropped` with table names and row counts. If `household_record.cbor` already exists, no migration runs (we're already on Phase 1+). The migration is non-interactive: per the constitution's "Adoption-First" principle and the "no production users" status, we do not prompt.

**Rationale**:
- Coupling migration to "first bootstrap" guarantees it runs exactly once.
- Logging the dropped row counts gives operators a record of what was lost without prompting (a prompt on a non-interactive systemd start would hang).
- Atomic transaction prevents half-migrated state if the process is killed mid-migration.

**Alternatives considered**:
- **Prompt operator interactively before dropping**. Rejected: theyOS may run as a systemd service or under launchd with no terminal; constitution says no manual ops.
- **Dump dropped data to a backup file**. Rejected: by product decision the data is considered disposable. A backup adds complexity for value we agreed not to deliver.
- **Skip migration; expect operator to wipe manually**. Rejected: violates Principle IV (no parallel old/new); we'd ship with both schemas live.

---

## R8 — Phase 1 scope decisions tied to the canonical 12 user stories (RESOLVED 2026-05-06)

**Status:** all three points resolved by Owner on 2026-05-06; this section is kept for traceability and as the change-log for the constitution v1.0.0 → v2.0.0 amendment.

**R8.1 — DECIDED: option (a) — Constitution amendment to EC P-256 root.** R8.1-b (envelope SE-wrap of Ed25519) was rejected because it leaks the private scalar to RAM at sign time, defeating the hardware-isolated-signing property that defines Apple's identity-key design. Constitution v2.0.0 ratified the same day. R8.1-a delivers SE-native signing for `HH_priv`, `M_priv`, `P_priv`, `D_priv` — biometric-gated when needed, hardware-enforced unconditionally.

**R8.2 — DECIDED: enters Phase 1.** QR pairing URI emission + initiate/confirm endpoints. See FR-018.

**R8.3 — DECIDED: enters Phase 1.** Bonjour `_soyeht-household._tcp` publishing. See FR-017.

---

The 12-story UX target was ratified on 2026-05-06 (see project memory `project_household_user_stories`). Reviewing Phase 1 against those stories revealed three points where Phase 1, as currently specified, does not fully fund the destination. None block Phase 1 acceptance; all three need an explicit go/no-go before locking the substrate, because deferring may require a `version: 2` cert / record format later.

### R8.1 — Secure Enclave on Mac (story 1) — STATUS: deferred, decision required

**Story 1 says**: "a chave-raiz Ed25519 nasce, fica guardada no **Secure Enclave** do Mac."

**Phase 1 specifies**: `HH_priv` in macOS Keychain via `keyring` crate. Keychain ≠ Secure Enclave.

**Technical conflict**: Apple's Secure Enclave only supports EC P-256, not Ed25519. The constitution Engineering Standards lock Ed25519 for signing.

**Three resolution paths**:
- **R8.1-a — Constitution amendment to EC P-256 root**: MAJOR version bump on the constitution; everything that signs gets touched; ECDSA is fine cryptographically; loses Ed25519 homogeneity.
- **R8.1-b — SE-backed envelope**: keep Ed25519 root, but seal `HH_priv` with an SE-backed P-256 wrap key (`kSecAttrTokenIDSecureEnclave`). Ciphertext lives in Keychain; unwrap requires touching the SE (biometric optional). Linux falls back to kernel keyring as already specified. ~2 days of extra work in Phase 1, no constitution change.
- **R8.1-c — Status quo (Keychain only)**: Phase 1 ships as currently specified; story 1's "Secure Enclave do Mac" wording becomes inaccurate; constitution unchanged.

**Recommended**: R8.1-b. Keeps the protocol homogeneous, gets actual SE backing on Apple platforms (story 1's promise), zero constitution churn. Cost is acceptable.

**Action**: requires explicit go/no-go from Owner. Until decided, FR-007 stays as written (Keychain only).

### R8.2 — QR pairing emission at install end (story 1) — STATUS: deferred to Phase 2

**Story 1 ends with**: "aparece um QR pequeno: escaneie com seu iPhone para parear. Owner escaneia. iPhone vira o primeiro device pessoal."

**Phase 1 ends with**: a curl-able identity endpoint. No QR, no `soyeht://household/pair-device` URI emission.

**Position**: deferred to Phase 2 (which is where the iPhone receiver lives). The QR alone, without an iPhone-side handler, is decoration. However, the URI scheme grammar (`soyeht://household/pair-device?token=…&hh_id=…&endpoint=…`) and the pairing-token CBOR shape MUST be specified in `docs/household-protocol.md` during Phase 1 so Phase 2 has a fixed contract. **This is the only Phase-1 obligation derived from story 1's QR**: lock the wire format, defer the implementation.

**Action**: add a §11 to `docs/household-protocol.md` defining the URI scheme + token format. Outside the scope of Phase 1 implementation tasks but inside the cross-repo contract responsibility of this phase.

### R8.3 — Bonjour announcement at single-machine install (story 2) — STATUS: deferred, low risk

**Story 2 says**: the second machine instantly sees "Sample Home detectada nesta rede" via Bonjour/mDNS.

**Constitution Principle III** mandates: "Discovery MUST be Bonjour/mDNS on local networks."

**Phase 1 specifies**: loopback + Tailscale binding only. No Bonjour publishing.

**Position**: Phase 1 has a single machine; nothing to discover. The Bonjour publishing only matters when the second machine arrives in Phase 3 looking for the casa. We can either:
- **R8.3-a**: publish Bonjour from Phase 1 onward (TXT records: `hh_id`, `version=1`, `name`, short fingerprint of `hh_pub`). ~1 day to add `mdns-sd` (Linux) + `dns_sd` via Core Foundation (macOS); locks the TXT record format early.
- **R8.3-b**: defer publishing to Phase 3 with the discovery client. Risk: discovering late that TXT shape needs additional fields breaks Phase 3 bootstrapping.

**Recommended**: R8.3-a if we add it without scope creep on the discovery side; otherwise R8.3-b is acceptable since the TXT record is small and easy to revise before any consumer exists. **Default in this plan**: R8.3-b (defer).

**Action**: at minimum, document the TXT record schema in `docs/household-protocol.md` §12 during Phase 1 (cross-repo contract), even if implementation lands in Phase 3.

---

## Summary

All NEEDS CLARIFICATION items resolved. Phase 1 design proceeds with:

| Concern | Choice |
|---|---|
| Keystore | `keyring` crate v3 |
| Hash | BLAKE3 default; SHA-256 fallback compiled but disabled in production targets |
| File layout | `$THEYOS_STATE_DIR/household/{household_record,machine_cert}.cbor` 0600 |
| Listener | Dedicated axum router on loopback + active Tailscale; refresh every 60 s |
| Logging | `tracing` JSON formatter; `THEYOS_LOG_FORMAT=json` default in prod |
| Idempotence | Presence + self-verification of `household_record.cbor` |
| Legacy migration | Atomic table drop on first bootstrap; non-interactive |
| Cert format extensibility | `issued_by: SubjectId` (polymorphic) and `caveats: Vec<Caveat>` (Phase 1: empty Vec, validator rejects non-empty) reserved in CBOR schema to prevent breaking change in Phase 5 (capability delegation) |
| Secure Enclave on Mac | **DECIDED — R8.1-a**: Constitution v2.0.0 mandates EC P-256 ECDSA + ECDH; identity keys created via `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`; signing via `SecKeyCreateSignature` |
| QR pairing emission | **In Phase 1** (FR-018) — initiate/confirm endpoints + ANSI block QR rendered at end of `theyos install`; iPhone-side handler ships in Phase 2 |
| Bonjour announcement | **In Phase 1** (FR-017) — `_soyeht-household._tcp` published from bootstrap; discovery client ships in Phase 3 |
