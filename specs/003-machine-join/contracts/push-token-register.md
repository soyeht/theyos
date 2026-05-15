# Contract: `POST /api/v1/household/owner-device/push-token`

Registers (or rotates) the Apple push token for the owner iPhone.

## Authentication

Soyeht-PoP under the owner PersonCert. The header `<p_id>` must equal the persisted owner PersonCert's `p_id`.

## Request

- Content-Type: `application/cbor`
- Body: deterministic CBOR

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `platform` | text | MUST be `ios` in this phase |
| `push_token` | bytes | Apple-issued device token (typical 32 bytes) |

## Response

- `200 OK`, body `{v=1, updated_at: uint}` (deterministic CBOR).
- `401 Unauthorized` for any auth failure.

## Server behaviour

- Atomically write `owner_device_push_token.cbor` carrying `{v, p_id, platform, push_token, updated_at}`.
- Notify in-memory dispatcher to use the new token for any future tickle.
- After the Phase 3 join ceremony commits, the new household member M2 receives the most recent token in its `JoinResponse.push_token_seed`.

## Rotation

Owner iPhone POSTs again with the new token; the previous token is overwritten. There is no token-history; previous tokens are not retained.

## Privacy contract

The token is treated as a household-private artifact. It MUST NOT be sent to any non-household network endpoint other than Apple's APNS HTTP/2 service when actually dispatching a tickle. CI lint asserts the `owner_device_push_token.cbor` file is read only by `apns_dispatcher` and `handlers_owner_events` (the registration handler and the join-time replication path).
