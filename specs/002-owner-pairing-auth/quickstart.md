# Quickstart: Phase 2 Owner Pairing and Proof-of-Possession Auth

## Prerequisites

- Phase 1 cryptographic skeleton implemented and passing.
- `cargo test --workspace --all-targets` passes before starting.
- A fresh household state directory or a Phase 1 bootstrapped fixture.

## 1. Build

```bash
cd /Users/macstudio/Documents/theyos/admin/rust
cargo build --workspace
```

## 2. Start theyOS with Phase 1 household identity

```bash
export THEYOS_HOUSEHOLD_STATE_DIR="$(mktemp -d)"
export THEYOS_FORCE_SOFTWARE_KEYS=1
./target/debug/server
```

In another shell:

```bash
./target/debug/server install --household-name "Sample Home" --reissue-pair-qr
```

The install output includes a `soyeht://household/pair-device?...` URI.

## 3. Confirm owner pairing with the test harness

The Phase 2 test harness generates a P-256 person keypair, signs the pairing proof, and posts:

```bash
cargo test -p e2e-rs phase2_owner_pairing -- --nocapture
```

Expected:

- exactly one `PersonCert` is returned
- the pair token is consumed
- no `DeviceCert` is returned or persisted
- `owner_person_cert.cbor` and `household_auth_state.cbor` exist under the household state dir

## 4. Verify proof-of-possession auth

```bash
cargo test -p e2e-rs phase2_pop_auth -- --nocapture
```

Expected:

- signed owner request succeeds for an owner-allowed household operation
- bearer-only request to the same household operation fails
- replayed, stale, tampered-body, and wrong-path signatures fail
- the protected Phase 2 smoke route is `/api/v1/household/snapshot`

## 5. Verify restart durability

```bash
cargo test -p e2e-rs phase2_owner_auth_restart -- --nocapture
```

Expected:

- the same owner PersonCert validates after 50 restart cycles
- tampering with the stored cert prevents household auth from loading as trusted

## 6. Full regression

```bash
cargo test --workspace --all-targets
```

Success means Phase 1 identity behavior still works and Phase 2 owner pairing/auth contracts are green.

## 7. Cross-repo contract check

Compared against `/Users/macstudio/Documents/SwiftProjects/iSoyehtTerm/specs/002-owner-device-pairing/contracts/`:

- `pair-device-url.md`: matches `soyeht://household/pair-device?v=1&hh_pub=<base64url 33-byte P-256>&nonce=<base64url 32-byte>&ttl=<unix-seconds>`.
- `pairing-client-flow.md`: confirm request matches `v`, `nonce`, `p_pub`, `display_name`, and `proof_sig`; response returns one PersonCert and no DeviceCert.
- `proof-of-possession-client.md`: header matches `Authorization: Soyeht-PoP v1:<p_id>:<unix_seconds>:<signature_b64url>` and signs deterministic CBOR over method, path/query, timestamp, and BLAKE3 body hash.
