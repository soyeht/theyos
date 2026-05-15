# Fixture: owner_cert_auth.cbor

Cross-language test fixture for `POST /bootstrap/teardown` owner-auth validation
(contract: `specs/005-soyeht-onboarding/contracts/bootstrap-teardown.md`).

## Contents

`../owner_cert_auth.cbor` — CBOR map with:

| Key | Type | Description |
|---|---|---|
| `seed` | text | Derivation seed string (for reproducibility) |
| `hh_pub` | bstr (33 bytes) | Household P-256 public key (SEC1 compressed) |
| `owner_pub` | bstr (33 bytes) | Registered owner P-256 public key |
| `hh_id` | text | Household ID (`hh_<52-char base32>`) |
| `m_id` | text | Machine ID (`m_<52-char base32>`) |
| `base_ts` | uint | Base Unix timestamp used for the fixture |
| `variants` | map | 5 named TeardownRequest CBOR byte strings |

### Variants

| Key | Expected server response | Why |
|---|---|---|
| `valid` | 200 OK | Well-formed, correct signature, ts within ±300s |
| `sig_mismatch` | 401 | Signature is all-zero bytes (r=0, fails ECDSA verify) |
| `ts_skew` | 401 | `ts` is 400 seconds behind base_ts (> 300s gate) |
| `nonce_replay` | 401 | Identical bytes to `valid`; send after `valid` for 401 |
| `unknown_signer` | 401 | `signed_by` key not in household's owner-cert set |

**Note on `nonce_replay`**: the fixture consumer must POST `valid` first, then
immediately POST `nonce_replay` (same bytes, same nonce) to trigger the 401.
On a freshly-initialized state, `nonce_replay` alone behaves like `valid`.

## Derivation

All key material is derived from:

```
seed  = b"soyeht-onboarding-owner-cert-fixture-2026"
owner_scalar  = BLAKE3(seed || b"owner")    → 32 bytes → P-256 scalar
machine_scalar = BLAKE3(seed || b"machine") → 32 bytes → P-256 scalar
hh_scalar      = BLAKE3(seed || b"household") → 32 bytes → P-256 scalar
unknown_scalar = BLAKE3(seed || b"unknown")  → 32 bytes → P-256 scalar (not registered)
nonce          = BLAKE3(seed || b"nonce:" || b"fixture-v1") → 32 bytes
```

**Offline-only fixture**: `BASE_TS = 1_746_921_600` (2025-05-11 00:00:00 UTC). Any live
engine will reject the `valid` variant with a `ts_skew` 401 because the timestamp is in
the past. This fixture is for offline unit/contract tests only — not live engine integration.

TeardownRequest fields signed: canonical CBOR (RFC 8949 §4.2.1) of
`TeardownPayload { v, op, hh_id, m_id, nonce, ts, signed_by }` — see
`handlers_bootstrap.rs` for the Rust definition.

## Regenerating

From the repo root:

```sh
cargo run --manifest-path admin/rust/Cargo.toml \
  -p server-rs --bin gen-owner-cert-fixture -- \
  admin/rust/server-rs/tests/fixtures/owner_cert_auth.cbor
```

Regenerate when:
- `TeardownRequest`/`TeardownPayload` field names or types change.
- The canonical CBOR encoding in `household_rs::cbor` changes.
- Additional variants are needed.

After regenerating, re-run Rust and Swift test suites to verify byte-equal output.

## Cross-language use

iSoyehtTerm imports this fixture in `SoyehtCore` tests (agente-front T080b) via
a build-phase script that copies `owner_cert_auth.cbor` into the test bundle.
Swift parses the outer CBOR map, extracts `owner_pub` + each variant, then
exercises the Swift `TeardownRequest` parser and ECDSA verifier against the
known-good `valid` entry and the known-bad entries.
