# theyOS Rust Workspace

This workspace contains the Rust services and libraries that back the theyOS
admin daemon, VM execution path, and Phase 1 household identity substrate.

## Household Identity (`household-rs`)

`household-rs` owns the Phase 1 cryptographic skeleton:

- P-256 household and machine identity keys.
- `hh_...` and `m_...` identifier derivation from compressed SEC1 public keys.
- Canonical CBOR encoding for `HouseholdRecord` and `MachineCert`.
- Atomic persistence under the household state directory.
- Idempotent `bootstrap_or_load` for fresh install and restart paths.
- Pair-device token/window primitives used by the install-time QR flow.

The server crate wires these primitives into:

- `theyos install --household-name <name>` for first bootstrap.
- `theyos install --reissue-pair-qr` for a fresh pairing window.
- `GET /api/v1/household/identity` on the dedicated household listener.
- `_soyeht-household._tcp` Bonjour publication while the daemon is running.

## Bootstrap Walkthrough

From this directory:

```bash
cargo build --workspace --release
THEYOS_FORCE_SOFTWARE_KEYS=1 \
THEYOS_HOUSEHOLD_STATE_DIR=/tmp/theyos-household \
./target/release/server install --household-name "Sample Home"
```

Production macOS installs use Secure Enclave keys by default. The
`THEYOS_FORCE_SOFTWARE_KEYS=1` override is for CI and developer machines that
cannot access a hardware-backed key path.

The full operator walkthrough and acceptance checks are maintained in:

```text
../../specs/001-phase-1-crypto-skeleton/quickstart.md
```
