# Contract: `POST /bootstrap/teardown`

Per spec FR-004 (updated by Clarifications 2026-05-09 — owner cert auth required).

## Purpose

Atomic destruction of casa state on a single machine. Reverts engine to `uninitialized`. Used for "recomeçar do zero" if user wants to recreate the casa, or to remove a member machine from a casa.

## Preconditions

Engine MUST have a casa (state ∈ `{named_awaiting_pair, ready, recovering}`). Calling this on `uninitialized` or `ready_for_naming` returns 409.

## Wire shape

### Request

```
POST /bootstrap/teardown HTTP/1.1
Host: 127.0.0.1:8091
Content-Type: application/cbor

TeardownRequest = {
  "v":          1,
  "op":         "teardown",            ; constant string (defense in depth: prevents cert reuse for other ops)
  "hh_id":      tstr,                  ; target casa
  "m_id":       tstr,                  ; target machine (this engine's m_id)
  "nonce":      bstr(.size 32),        ; CSPRNG, single-use within 24h
  "ts":         uint,                  ; unix seconds, ≤ 5 min skew from engine clock
  "signed_by":  bstr(.size 33),        ; SEC1-compressed P-256 — owner device cert pubkey (D_pub)
  "signature":  bstr(.size 64),        ; r||s P-256 ECDSA over deterministic CBOR of all above EXCEPT `signature`
}
```

The `signature` is produced on iPhone after user passes Face ID / Touch ID gate. SoyehtCore exposes `OwnerCertSigner.signTeardown(hh_id, m_id) async throws -> TeardownRequest`; the call internally:

1. Computes `nonce` (CSPRNG 32 bytes).
2. Computes `ts` (current unix seconds).
3. Calls `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Delete 'Sample Home'?")`. Returns nil if user cancels.
4. Builds the unsigned envelope.
5. Signs with `D_priv` from Secure Enclave (passes biometric ACL gate; SE returns signature without exporting key).
6. Returns the full signed `TeardownRequest`.

### Success response

```
HTTP/1.1 200 OK
Content-Type: application/cbor

TeardownAck = {
  "v": 1,
  "torn_at": uint,                     ; unix seconds when state was wiped
}
```

After this response, engine is in `uninitialized`, all listeners unbound except `/bootstrap/*` and `/health`. Bonjour reverts to `_soyeht-setup._tcp.`.

### Failure responses

- **400 Bad Request** — CBOR re-encode fail, op != "teardown", malformed fields. Body: `{v:1, error:"invalid_request"}`.
- **401 Unauthorized** — cert chain validation fail, signature verification fail, replay (nonce reused), clock skew >300s. Body: `{v:1, error:"unauthorized"}`. Generic to avoid leaking validation step (prevents probing).
- **409 Conflict** — engine state doesn't allow teardown (uninitialized / ready_for_naming). Body: `{v:1, error:"no_household_to_teardown", state:tstr}`.

## Engine-side validation order

All steps MUST pass in order before any destructive action.

1. **State gate** — engine state ∈ `{named_awaiting_pair, ready, recovering}`. Otherwise 409.
2. **CBOR re-encode** — body decodes as `TeardownRequest` AND its canonical re-encoding is byte-equal to the request body. Otherwise 400.
3. **`op` constant check** — `op == "teardown"`. Otherwise 400.
4. **Field shape checks** — `signed_by` is valid SEC1-compressed P-256 point; `nonce` is 32 bytes; `ts` reasonable; `m_id` matches this engine's `m_id`; `hh_id` matches this engine's `hh_id`. Otherwise 400.
5. **`ts` skew** — `|now - ts| ≤ 300` seconds. Otherwise 401.
6. **Replay check** — `nonce` not in `recent-nonces/` cache (24h). Otherwise 401.
7. **Cert chain validation** — `signed_by` (D_pub) is in the household's known device cert set, validated up to `hh_pub` via Phase 2 cert chain. Otherwise 401.
8. **Signature verification** — ECDSA verify (`signature`, deterministic CBOR re-encoding of body minus `signature` field, `signed_by`). Otherwise 401.
9. **Persist nonce** — write `recent-nonces/<nonce-hex>` (atomic).
10. **Atomic teardown** — `rm -rf` `household/` via temp-rename pattern (`<state_dir>/household/` → `<state_dir>/household.tearing-down/`, then `rm -rf` async). Engine refuses concurrent reads via Tokio RwLock.
11. **State transition** — write `identity.bootstrap_state` = `uninitialized` (this is the last write; if anything before it crashes, on next boot the engine reconstructs from partial state and re-tears-down to completion).
12. **Unbind listeners** — Phase 2/3 endpoints removed; `/bootstrap/*` + `/health` retained.
13. **Reset Bonjour** — publisher transitions to `_soyeht-setup._tcp.`.
14. **Return** — `TeardownAck` with `torn_at`.

## Replay protection

- `nonce` cache retains last 24h of nonces. Cache is bounded (max 100k entries, oldest evicted).
- `ts` skew window of 300s combined with single-use nonce makes the replay window effectively impossible.

## Idempotency

This call is **NOT** idempotent — once teardown succeeds, the household is gone. Calling again returns 409 (`no_household_to_teardown`).

## Tests

- Contract: signature shape, validation step order (each step independently fails with expected 400/401).
- Integration: end-to-end teardown via SoyehtCore client + Face ID stub.
- Integration: replay attack returns 401 on second call with same nonce.
- Integration: clock skew detection (engine clock manipulation in test harness).
- Integration: torn write recovery — kill engine after step 10 but before step 11; restart engine; verify state machine reconstructs to `uninitialized` cleanly.
