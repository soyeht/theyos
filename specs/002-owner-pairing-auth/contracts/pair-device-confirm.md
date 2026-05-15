# Contract: Pair Device Confirm

## Endpoint

`POST /api/v1/household/pair-device/confirm`

Available only while an install-time pair window is active. Outside the active window, behavior remains indistinguishable from Phase 1 closed-window behavior.

## Request

Headers:

```http
Content-Type: application/json
```

Body:

```json
{
  "v": 1,
  "nonce": "base64url-32-byte-nonce",
  "p_pub": "base64url-33-byte-sec1-p256-public-key",
  "display_name": "Owner",
  "proof_sig": "base64url-64-byte-raw-p256-signature"
}
```

`proof_sig` signs deterministic CBOR:

```cbor
{
  "v": 1,
  "purpose": "pair-device-confirm",
  "hh_id": "hh_...",
  "nonce": h'...',
  "p_pub": h'...'
}
```

## Success Response

Status: `200 OK`

```json
{
  "v": 1,
  "hh_id": "hh_...",
  "p_id": "p_...",
  "person_cert_cbor": "base64url-deterministic-cbor-person-cert",
  "capabilities": [
    "claws.list",
    "claws.create",
    "claws.delete",
    "claws.use",
    "claws.assign",
    "household.invite",
    "household.revoke",
    "household.add_machine"
  ]
}
```

No DeviceCert field is returned.

## Failure Response

Closed window, expired token, wrong nonce, malformed body, invalid public key, invalid proof, first owner already paired, and concurrent loser attempts all return a generic failure shape that does not reveal which validation step failed. The response MUST NOT echo the active nonce or cert internals.

## Atomicity Contract

On success, theyOS atomically:

1. Verifies the active pair token.
2. Verifies `proof_sig`.
3. Signs the PersonCert.
4. Persists owner auth state.
5. Consumes and closes the pair window.

Exactly one concurrent request can complete this sequence.
