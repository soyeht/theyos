# POST /api/v1/household/sign-machine-cert

Mobile-first add-Mac proxy-signing flow. The iPhone orchestrates between a
fresh Mac engine and an existing household engine that still has local
`HH_priv`. The existing engine signs both the Mac's `MachineCert` and the
Mac's accept-household `join_challenge`, then returns opaque CBOR bytes for
the iPhone to forward to `/bootstrap/accept-household/confirm`.

All request and response bodies are canonical CBOR. Top-level maps and nested
maps are closed: unknown or duplicate keys are invalid.

Endpoint: `POST /api/v1/household/sign-machine-cert`

Auth: `Soyeht-PoP v1` over the request body, using the same household request
signing context as existing household endpoints. The signer must be present in
the local membership/auth state and must be permitted for
`household.add_machine`.

State gate: accepted only when the engine has a loaded household identity with
local `HH_priv`. Engines that are uninitialized, recovering, post-Shamir
without `HH_priv`, or follower engines with `is_follower=true` return
`409 household_not_initialized`.

Request:

```cbor
{
  "v": 1,
  "kind": "machine",
  "subject": {
    "m_id": tstr,
    "m_pub": bstr .size 33,
    "hostname": tstr,           ; 1..=64 UTF-8 bytes, no controls
    "platform": "macos" / "linux-nix" / "linux-other"
  },
  "challenge": bstr             ; exact join_challenge bytes from accept-household
}
```

Server actions:

1. Validate PoP using method, path+query, timestamp, and BLAKE3 body hash.
2. Verify the PoP signer's `person_id` is in the local membership/auth state
   and has `household.add_machine`.
3. Verify `kind == "machine"`.
4. Verify `subject.m_pub` is a compressed P-256 public key and
   `derive_machine_id(m_pub) == subject.m_id`.
5. Validate `subject.hostname` and `subject.platform`.
6. Build a `MachineCert` with:

```cbor
{
  "v": 1,
  "m_id": subject.m_id,
  "type": "machine",
  "hh_id": local hh_id,
  "m_pub": subject.m_pub,
  "caveats": [],
  "hostname": subject.hostname,
  "platform": subject.platform,
  "issued_by": local hh_id,
  "joined_at": server_now
}
```

7. Canonically encode the cert sign-bytes using the same rule documented in
   `accept-household.md`: sort map keys by bytewise lexicographic order of
   each key's canonical CBOR encoding, then sign those bytes with local
   `HH_priv`.
8. Embed the raw P-256 ECDSA `r || s` signature as `signature` and canonical
   CBOR encode the full `MachineCert`.
9. Sign the raw `challenge` bytes directly with local `HH_priv`; do not
   length-prefix or re-encode them.
10. Append an owner-events audit entry with type
    `sign_machine_cert_for_proxy` and payload:

```cbor
{
  "actor_person_id": tstr,
  "target_m_id": tstr,
  "joined_at": uint,
  "hostname": tstr,
  "platform": tstr
}
```

Response:

```cbor
{
  "v": 1,
  "machine_cert": bstr,              ; canonical CBOR of full signed cert
  "challenge_signature": bstr .size 64,
  "m_id": tstr,
  "joined_at": uint
}
```

## Errors

| HTTP | Error | Condition |
| --- | --- | --- |
| 400 | `invalid_cbor` | Body is not canonical CBOR, has duplicate/unknown keys, wrong version, or wrong structural shape. |
| 400 | `invalid_subject` | `kind` is not `machine`, `m_pub` is not a compressed P-256 point, `m_id` does not derive from `m_pub`, or hostname/platform validation fails. |
| 401 | `invalid_pop` | PoP signature is missing, malformed, expired by replay window, or does not verify. |
| 403 | `not_a_member` | PoP signer is not present in local membership/auth state or lacks `household.add_machine`. |
| 409 | `household_not_initialized` | Engine has no usable local `HH_priv`, including uninitialized/recovering, post-Shamir without `HH_priv`, or follower `is_follower=true`. |
| 500 | `internal_error` / `keygen_failed` | Audit append, filesystem, encoding, or signing backend failure. |

## Client Notes

The response `machine_cert` is opaque to the iPhone. The iPhone forwards it as
the `machine_cert` field in `/bootstrap/accept-household/confirm`.

The response `challenge_signature` is the raw P-256 ECDSA `r || s` signature
over the exact request `challenge` bytes. The iPhone forwards it as
`challenge_sig` in `/bootstrap/accept-household/confirm`.
