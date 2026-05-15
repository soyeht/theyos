# Contract — `GET /api/v1/household/identity`

**Feature**: 001-phase-1-crypto-skeleton
**Stability**: v1 (additive in Phase 1; consumed by app starting Phase 2)

---

## Summary

Returns the public identity of the household this machine belongs to. The endpoint is unauthenticated by design — it only exposes public material — and is bound only to loopback and Tailscale interfaces.

## Request

```
GET /api/v1/household/identity HTTP/1.1
Host: <theyos-host>
Accept: application/json
```

- **Authentication**: none. Any caller reachable on the bound interfaces may call it.
- **Idempotent**: yes. Safe to retry.

## Response

### 200 OK — household exists

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Cache-Control: no-store
```

```json
{
  "version": 1,
  "hh_id": "hh_kxqzvnfp7y2t3r6q4s8w9b5cdjm0a1e2g3h4i5j6k7l8m9n0p1",
  "hh_pub_b64": "aZb1Tr...A==",
  "name": "Sample Home",
  "created_at": 1714972800
}
```

| Field | Type | Notes |
|---|---|---|
| `version` | uint | Schema version. `1` in this phase. |
| `hh_id` | string | Stable household identifier (`hh_` + URL-safe base32 lowercase no-padding). |
| `hh_pub_b64` | string | 33-byte SEC1-compressed P-256 public key, base64-standard with padding (44 chars). |
| `name` | string | Operator-supplied household name. UTF-8, 1–64 printable characters. |
| `created_at` | uint | Unix seconds when the household was bootstrapped. |

The response does **not** carry: machine information, members list, shamir parameters, or any private material. Those belong to authenticated endpoints introduced in Phase 2+.

### 503 Service Unavailable — household not yet bootstrapped

```http
HTTP/1.1 503 Service Unavailable
Content-Type: application/json; charset=utf-8
```

```json
{
  "error": "not_bootstrapped",
  "code": "HOUSEHOLD_NOT_BOOTSTRAPPED",
  "hint": "Run `theyos install` to bootstrap a household."
}
```

Returned only during the narrow window when theyOS is running but bootstrap hasn't completed (e.g., keystore came up after the HTTP listener). Should be transient.

## Listener binding (FR-008)

The route is mounted on a dedicated axum `Router` whose `TcpListener` binds to:

- `127.0.0.1:<port>` and `[::1]:<port>` (always)
- Each active interface whose name matches `tailscale*` OR whose address falls in `100.64.0.0/10` or `fd7a:115c:a1e0::/48` (refreshed every 60 s)

Binding to `0.0.0.0` or `::` is **forbidden**. Implementation MUST verify the bound socket's local address before considering the listener live; if a non-allowed address binds, the listener is closed and an error is logged.

## Headers

- `Cache-Control: no-store` — clients that learn `hh_id` must ask the host again on each connect (a household could change identity if uninstalled-and-reinstalled).
- No CORS headers — the endpoint is not intended for browsers; the only consumers are the Soyeht apps (starting Phase 2) and operator tooling (`curl`).

## Status code summary

| Status | Meaning |
|---|---|
| 200 | Identity returned. |
| 503 | theyOS is up but identity bootstrap not complete yet (transient). |

The endpoint never returns 4xx in Phase 1; there is no auth to fail and no path parameters to validate.

## Conformance test cases

These map 1:1 to e2e tests in `e2e-rs/tests/phase1_identity.rs`:

1. **C1**: Fresh install → `GET /api/v1/household/identity` returns 200 with valid JSON; `hh_id` matches `BLAKE3-256(b64decode(hh_pub_b64))` derivation.
2. **C2**: theyOS running but no `household_record.cbor` on disk → 503 with `code=HOUSEHOLD_NOT_BOOTSTRAPPED`.
3. **C3**: Two consecutive 200 responses return byte-identical bodies (stability).
4. **C4**: Request from `0.0.0.0` interface (when running theyOS in a container without Tailscale) → connection refused at TCP level (not 403 from app code).
5. **C5**: After `theyos install` rerun (idempotent), the response is unchanged — same `hh_id`, same `created_at`.
6. **C6**: After tampering with `household_record.cbor` on disk and restarting theyOS, the process refuses to start; the endpoint never becomes available.
