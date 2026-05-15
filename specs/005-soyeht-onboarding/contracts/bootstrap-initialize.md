# Contract: `POST /bootstrap/initialize`

Per spec FR-003.

## Purpose

Mint the casa identity. The single moment in the lifetime of a fresh engine where `(hh_priv, hh_pub)` is generated and persisted. After this call succeeds, the engine has a permanent identity.

## Preconditions

Engine MUST be in state `uninitialized` or `ready_for_naming`. Calling this in any other state returns 409.

## Wire shape

### Request

```
POST /bootstrap/initialize HTTP/1.1
Host: 127.0.0.1:8091
Content-Type: application/cbor
Content-Length: …

InitializeRequest = {
  "v":         1,
  "name":      tstr,                ; UTF-8, 1..=64 bytes after sanitization
}
```

`name` validation:
- Trimmed of leading/trailing whitespace.
- ASCII control characters (< 0x20 except space) rejected.
- Length after trim: 1 to 64 bytes UTF-8.
- May contain: letters (any Unicode), digits, spaces, `'`, `-`, `.`, `,`, `&`. Other punctuation rejected to keep it display-safe in Bonjour TXT.

No auth required for this call (engine is in pre-identity state — there's no cert chain to authenticate against yet).

### Success response

```
HTTP/1.1 200 OK
Content-Type: application/cbor

InitializeResponse = {
  "v":              1,
  "hh_id":          tstr,                ; "hh_<base32>"
  "hh_pub":         bstr(.size 33),      ; SEC1-compressed P-256
  "name":           tstr,                ; the sanitized name as persisted
  "pair_qr_uri":    tstr,                ; "soyeht://household/pair-device?…"
  "created_at":     uint,                ; unix seconds
}
```

After this response, engine is in `named_awaiting_pair` and Bonjour publisher is publishing `_soyeht-household._tcp.` with `pairingState=device`.

### Failure responses

- **400 Bad Request** — body not valid CBOR, or `name` validation failed. Body: `{v:1, error:"invalid_name", reason: tstr}`.
- **409 Conflict** — engine not in `uninitialized` or `ready_for_naming`. Body: `{v:1, error:"already_initialized", state: tstr}`. Caller should call `/bootstrap/teardown` first if intent is to recreate.
- **500 Internal** — keypair gen failed, persistence error. Body: `{v:1, error:"keygen_failed"}` or similar. Caller can retry.

## Engine-side processing order

1. **State gate** — verify engine state ∈ `{uninitialized, ready_for_naming}`. Otherwise 409.
2. **CBOR re-encode** — body decodes as `InitializeRequest` AND its canonical re-encoding is byte-equal to the request body. Otherwise 400 (`invalid_cbor`).
3. **Name sanitize** — apply rules above. If empty after trim or > 64 bytes or contains forbidden chars → 400 (`invalid_name`).
4. **Acquire init lock** — Tokio mutex on `BootstrapState`. Concurrent callers wait or get 409.
5. **Keygen** — P-256 keypair generation:
   - macOS: prefer Secure Enclave via `kSecAttrTokenIDSecureEnclave`. Fall back to software keystore if `THEYOS_FORCE_SOFTWARE_KEYS=1` (Phase 3 carve-out).
   - Linux: kernel keyring (or software fallback if `THEYOS_FORCE_SOFTWARE_KEYS=1`).
6. **Derive `hh_id`** — `hh_id = "hh_" + base32_lowercase(BLAKE3(hh_pub_sec1))[0..16]` (16 leftmost bytes of digest, base32-encoded).
7. **Persist** — atomic write of `household-state/identity.json` (public material) and `household-state/secrets/hh.priv.bin` (private material; SE-bound or encrypted with master key for software fallback). Then atomic write of `household-state/identity.bootstrap_state` set to `named_awaiting_pair`.
8. **Update Bonjour** — transition publisher from `_soyeht-setup._tcp.` to `_soyeht-household._tcp.` with TXT including the new identity + `pairingState=device`.
9. **Mint pair-device window** — call existing Phase 2 `PairDeviceWindow::with_persistence` to open the first owner-pairing window; populate `pair_qr_uri`.
10. **Return** — `InitializeResponse` with all fields filled.

If any step 5+ fails, atomic rollback: rm tmp files, transition state machine back to where it was, return 500.

## Idempotency

This call is **NOT** idempotent. Repeating with the same name on a `ready_for_naming` engine creates a new keypair (different `hh_id`). Calling on `named_awaiting_pair` returns 409 — caller must teardown first if they want to redo.

## Tests

- Contract test: shape validation, CBOR roundtrip, sanitize edge cases.
- Integration test: state transition `ready_for_naming` → `named_awaiting_pair` with persistence verified on disk.
- Integration test: 409 on second call without teardown.
- Integration test: 500 rollback on injected keygen failure (use `failure-injection` feature in server-rs).
