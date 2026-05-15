# Quickstart — Phase 1 Cryptographic Skeleton

**Audience**: developers and operators who want to verify Phase 1 end-to-end on a fresh machine.

This walkthrough corresponds to **SC-005** in the spec ("operator who has never seen Soyeht reaches a successful identity endpoint response in under 5 minutes").

---

## Prerequisites

- A clean machine matching one of the supported targets:
  - **macOS 14+ on Apple Silicon, or Intel with T2 chip** (Secure Enclave required by FR-007). Pre-T2 Intel Macs are not supported in Phase 1; bootstrap will refuse with `error.kind = "se.unavailable"`.
  - Linux x86_64 or aarch64 with one of: `gnome-keyring`, `kwallet`, or kernel keyring (`THEYOS_KEYRING=kernel`)
- Rust 1.85 toolchain (matches `admin/rust/rust-toolchain.toml`)
- `curl`, `jq` for verification
- (For CI on Intel-no-T2 GitHub runners only) `THEYOS_FORCE_SOFTWARE_KEYS=1` env var to skip the SE check; production hardware MUST NOT use this flag

If you previously ran a pre-Phase-1 build of theyOS, **note**: the destructive migration in this phase will drop the legacy `users`, `mobile_sessions`, and `invites` tables. Per project decision (no production users) this is expected.

---

## Step 1 — Build

```bash
cd /path/to/theyos/admin/rust
cargo build --workspace --release
```

Expected: `target/release/server` and the new `household-rs` library compile clean. No warnings about missing deps.

## Step 2 — Configure runtime env

Choose a household name (1–64 printable Unicode characters) and a state directory.

```bash
export THEYOS_STATE_DIR=/var/lib/theyos          # compatibility alias; THEYOS_HOUSEHOLD_STATE_DIR also works
export THEYOS_HOUSEHOLD_PORT=8091                # household listener port
export THEYOS_LOG_FORMAT=text                    # easier to read interactively; default in production is "json"
```

## Step 3 — Start the daemon

In terminal A:

```bash
./target/release/server
```

Expected daemon logs before bootstrap:

```
INFO bootstrap.cold no household identity on disk; /identity will return 503 until `theyos install` runs
INFO bootstrap.endpoint.live bound_count=...
```

At this point `/identity` returns `503 HOUSEHOLD_NOT_BOOTSTRAPPED`, which is expected.

## Step 4 — Bootstrap

In terminal B, with the same env vars:

```bash
./target/release/server install \
    --household-name "Sample Home" \
    --hostname-label "studio-mac"
```

Expected install stdout/logs (text formatter; redacted hashes shown shorter than reality):

```
INFO bootstrap.start
INFO bootstrap.key_gen.household elapsed_ms=8  result=ok backing=secure_enclave   # macOS
INFO bootstrap.key_gen.machine   elapsed_ms=7  result=ok backing=secure_enclave   # macOS
                                                                                  # (Linux: backing=software)
INFO bootstrap.keystore.write    which=household result=ok
INFO bootstrap.keystore.write    which=machine   result=ok
INFO bootstrap.persist.household_record path=/var/lib/theyos/household/household_record.cbor result=ok
INFO bootstrap.persist.machine_cert    path=/var/lib/theyos/household/machine_cert.cbor    result=ok

Scan with Soyeht on your iPhone within 5 minutes to claim owner role:

  ████ ▄▄▄▄ ████  ▄▄  ██▄▄  ████
  ██  █ ▀▀ █  ██  ████  ████  ██
  ████  ▄▄  ████ ▄  ▀ ██▀▄  ████
  …  (small ANSI-block QR rendered here, ~37×37 modules)

(URI: soyeht://household/pair-device?v=1&hh_pub=…&nonce=…&ttl=1714973100&p_id=…)
```

Expected daemon logs in terminal A within ~2 seconds:

```
INFO bootstrap.hot_loaded hh_id=hh_kxqz... name="Sample Home" created_at=1714972800
INFO pair_window.opened source=snapshot_reload
INFO bonjour.published service=_soyeht-household._tcp port=8091   # when a non-loopback interface is bound
```

Total wall-clock from `INFO bootstrap.start` to the printed QR block: < 2 seconds (SC-001).

If your machine has no Tailscale interface up, you'll see only the loopback bindings — that's expected (FR-008 last sentence). Bonjour announcement still publishes on whatever non-loopback interfaces ARE up.

## Step 5 — Query the identity endpoint

```bash
curl -s http://127.0.0.1:8091/api/v1/household/identity | jq
```

Expected (lengths abbreviated; `hh_pub_b64` is 44 base64 chars representing 33 SEC1-compressed P-256 bytes):

```json
{
  "version": 1,
  "hh_id": "hh_kxqzvnfp7y2t3r6q4s8w9b5cdjm0a1e2g3h4i5j6k7l8m9n0p1",
  "hh_pub_b64": "AnZb1Tr6QwlJYK5sP6Qd1c0VwEbR7Hh4mIvUk2N3oP4MA",
  "name": "Sample Home",
  "created_at": 1714972800
}
```

## Step 6 — Verify cryptographic consistency

```bash
HH_PUB_B64=$(curl -s http://127.0.0.1:8091/api/v1/household/identity | jq -r .hh_pub_b64)
HH_ID=$(curl -s http://127.0.0.1:8091/api/v1/household/identity | jq -r .hh_id)

# Recompute hh_id locally and compare
RECOMPUTED=$(printf 'hh_%s' "$(echo -n "$HH_PUB_B64" | base64 -d | b3sum --no-names | xxd -r -p | base32 -w 0 | tr 'A-Z' 'a-z' | tr -d '=')")
[ "$HH_ID" = "$RECOMPUTED" ] && echo OK || echo MISMATCH
```

Expected: `OK`.

(The exact base32 invocation differs between platforms — the test suite (`e2e-rs/tests/phase1_identity.rs`) does this with a Rust helper; the shell version is illustrative.)

## Step 7 — Verify idempotence

Run install again with the same arguments:

```bash
./target/release/server install --household-name "Sample Home" --hostname-label "studio-mac"
```

Expected stdout:

```
INFO bootstrap.skip hh_id=hh_kxqz...p1 name="Sample Home" created_at=1714972800
```

Exit code: `0`. No regeneration.

## Step 8 — Verify restart determinism

```bash
pkill -f 'target/release/server'
./target/release/server
curl -s http://127.0.0.1:8091/api/v1/household/identity | jq
```

The returned `hh_id`, `hh_pub_b64`, `name`, `created_at` MUST be byte-identical to step 5.

## Step 9 — Negative path: corrupt the record

```bash
# Append a junk byte to corrupt the file
echo x >> $THEYOS_STATE_DIR/household/household_record.cbor

# Restart — must refuse to start
./target/release/server ; echo exit=$?
```

Expected: exit code non-zero, error log line at `error` level with `error.stage=load.household_record`, `error.kind=cbor.parse|cert.signature|hh_id.mismatch`, and an `error.hint` naming the recovery action.

## Step 10 — Cleanup (optional)

```bash
rm -rf $THEYOS_STATE_DIR/household
# Remove keystore / SE entries — exact command depends on platform
# macOS (SE-resident keys are kSecClassKey, not GenericPassword):
#   security delete-key -l 'com.soyeht.theyos.household.<hh_id>'
#   security delete-key -l 'com.soyeht.theyos.machine.<m_id>'
# Linux (kernel keyring or Secret Service):
#   secret-tool clear service com.soyeht.theyos account 'household.private_key.<hh_id>'
#   secret-tool clear service com.soyeht.theyos account 'machine.private_key.<m_id>'
```

After cleanup, step 2 runs as a fresh install again.

---

## What this proves

Completing the steps above demonstrates:

- **SC-001**: bootstrap completes in < 2 s on the target hardware.
- **SC-002**: identity is loaded (not regenerated) on restart.
- **SC-003**: identity endpoint responds quickly (manual `curl` is dominated by network/startup; the e2e suite measures p95).
- **SC-004**: cryptographic round-trip (sign + verify, hash + recompute) holds (Step 4).
- **SC-005**: walkthrough is achievable in under 5 minutes with this document (you've just done it).

Anything that does **not** hold above indicates a Phase 1 regression and blocks merging.
