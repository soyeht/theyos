# Quickstart: Phase 3 Machine Join

## Prerequisites

- Phase 2 implemented and passing (`cargo test -p e2e-rs phase2_*`).
- A fresh household state directory or a Phase-2 fixture with one paired owner PersonCert.
- Two machines or two state directories simulating two machines (the e2e harness runs both in-process).

## 1. Build

```bash
cd /Users/macstudio/Documents/theyos/admin/rust
cargo build --workspace
```

## 2. Stand up the founding machine M1

```bash
export THEYOS_HOUSEHOLD_STATE_DIR_M1="$(mktemp -d)"
export THEYOS_FORCE_SOFTWARE_KEYS=1
export THEYOS_PUSH_DISABLED=1   # APNS dispatcher logs intent only, does not call Apple
./target/debug/server --state-dir "$THEYOS_HOUSEHOLD_STATE_DIR_M1" install --household-name "Sample Home"
./target/debug/server --state-dir "$THEYOS_HOUSEHOLD_STATE_DIR_M1" install --reissue-pair-qr  # Phase 2 pair-device QR
cargo test -p e2e-rs phase2_owner_pairing -- --nocapture                                       # provision owner PersonCert
```

After this M1 has a household and one paired owner.

## 3. Stand up the candidate M2

```bash
export THEYOS_HOUSEHOLD_STATE_DIR_M2="$(mktemp -d)"
./target/debug/server --state-dir "$THEYOS_HOUSEHOLD_STATE_DIR_M2" install --pair-machine --transport tailscale
```

The installer prints the `soyeht://household/pair-machine` QR and the 6-word fingerprint. M2 binds its pre-household listener on a loopback port.

## 4. Story 1 — remote QR, owner approves

```bash
cargo test -p e2e-rs phase3_machine_join_remote -- --nocapture
```

Expected:
- One `OwnerEvent{type=join-request}` is appended to M1's log within 1 s of the harness POSTing the JoinRequest to M1.
- The harness owner-iPhone double polls `/owner-events` and observes the event with cursor `1`.
- The harness submits a valid `OwnerApproval`; M1 issues `MachineCert(M2)`, performs the (2, 2) Shamir split, and POSTs `JoinResponse` to M2's `local/finalize`.
- After commit, both state dirs carry `household_record.cbor` with `shamir_k=2, shamir_n=2, members=[m1_id, m2_id]`.
- `household_root_sole.cbor` is gone from M1's state dir.
- `shamir/self_shard.cbor` exists on each side.
- `OwnerEvent{type=machine-joined}` is appended at cursor `2`.

## 5. Story 2 — LAN auto-discovery, owner approves

```bash
cargo test -p e2e-rs phase3_machine_join_lan -- --nocapture
```

Expected:
- M2 publishes Bonjour with `pairing=machine, pair_role=joiner, pair_nonce=...`.
- M1's browser detects within 2 s and fetches `JoinRequest` via M2's `local/seed` endpoint.
- M1 stages the same `OwnerEvent{type=join-request}` as Story 1.
- Owner approval and 2PC commit proceed identically.
- Final state on disk is bit-equivalent to the Story 1 outcome.

## 6. Story 3 — atomic rollback under failure injection

```bash
cargo test -p e2e-rs phase3_atomic_rollback -- --nocapture
```

Expected: every injected failure (owner decline, owner timeout, M2 disconnect after JoinRequest, M2 disconnect after approval, M2 finalize-write fails, M1 crash between step 10 and step 11) ends with M1 in single-machine sole-shard mode (no `MachineCert` for M2 issued, `household_root_sole.cbor` intact, no `.staged` files left, `shamir_k`/`shamir_n` unchanged or absent) AND a fresh ceremony with the same or different candidate succeeds afterwards.

## 7. Replay idempotency

```bash
cargo test -p e2e-rs phase3_replay_idempotent -- --nocapture
```

Expected: 100 replays of a single completed `JoinRequest` (same `m_pub`+`nonce`) within the join window TTL produce one `MachineCert`, one Shamir transition, and bit-equivalent `JoinResponse` bytes returned every time. After TTL: replays return `401`.

## 8. APNS payload opacity audit

```bash
cargo test -p server-rs apns_dispatcher_payload -- --nocapture
cargo test -p server-rs apns_dispatcher_input -- --nocapture
cargo test -p e2e-rs phase3_apns_opacity -- --nocapture
```

Expected: every recorded APNS dispatch has body bytes equal to `b"{\"v\":1}"` and no household metadata, fingerprint, or `m_*` typed parameter passes through the dispatcher's input.

## 9. Full regression

```bash
cargo test --workspace --all-targets
```

Success means Phase 1 / Phase 2 still pass and Phase 3's contracts are green.

## 10. Cross-repo contract check

Compared against `/Users/macstudio/Documents/SwiftProjects/iSoyehtTerm/specs/003-machine-join/contracts/`:

- `pair-machine-url.md`: matches `soyeht://household/pair-machine?v=1&m_pub=<base64url 33-byte SEC1>&nonce=<base64url 32 bytes>&transport=...&addr=...&ttl=<unix-seconds>`.
- `owner-events-client.md`: matches the long-poll cursor encoding (base64url-no-pad of CBOR uint), event signature verification under issuer's MachineCert, and decline/approve POST shapes.
- `fingerprint-derivation.md`: Swift implementation passes the canonical `specs/003-machine-join/tests/fingerprint_vectors.json` produced by the Rust harness, byte-equivalent. Each entry exposes both `fingerprint` (string) and `fingerprint_words` (array) so each side picks the form matching its assertion convention.
- `apns-opacity.md`: confirms iSoyehtTerm's silent-push handler reacts to `{"aps":{"content-available":1}}` (Apple silent-push canonical shape) with no payload-derived state and immediately re-polls `/owner-events` over Tailscale.
