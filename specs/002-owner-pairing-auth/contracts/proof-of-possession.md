# Contract: Soyeht Proof-of-Possession

## Header

Household-scoped authenticated requests use:

```http
Authorization: Soyeht-PoP v1:<p_id>:<unix_seconds>:<signature_b64url>
```

Bearer tokens do not grant household-scoped authority.

## Signing Context

`signature_b64url` is a 64-byte raw P-256 ECDSA signature over deterministic CBOR:

```cbor
{
  "v": 1,
  "method": "GET",
  "path_and_query": "/api/v1/household/snapshot?x=y",
  "timestamp": 1714972800,
  "body_hash": h'...'       ; BLAKE3-256 over exact request body bytes
}
```

For requests without a body, `body_hash` is BLAKE3-256 over the empty byte string.

## Validation

theyOS validates:

1. Header scheme and fields are well-formed.
2. Timestamp is within ±60 seconds of server wall clock.
3. `p_id` matches the persisted first owner PersonCert.
4. PersonCert verifies against the household root and is time-valid.
5. Signature verifies against `PersonCert.p_pub`.
6. The request maps to an operation allowed by PersonCert caveats.

## Replay and Tamper Behavior

- Same signature outside the timestamp window is rejected.
- Same signature over a different method, path, query, or body is rejected.
- Bearer-only requests to household-scoped authenticated operations are rejected.
- Failure responses are generic and do not reveal whether the cert, signature, timestamp, or caveat check failed.
