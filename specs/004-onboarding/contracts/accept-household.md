# POST /bootstrap/accept-household

Mobile-first add-Mac flow. The owner iPhone holds `HH_priv`; the fresh engine
mints only its local machine key and waits for the iPhone to return a
household-signed `MachineCert`.

All request and response bodies are canonical CBOR. Top-level maps are closed:
unknown or duplicate keys are invalid. The `hh_id` value uses the existing
engine derivation (`hh_` + base32-lower-no-pad BLAKE3-256 of compressed
`hh_pub`), matching `POST /bootstrap/initialize`.
Code reference: `admin/rust/household-rs/src/ids.rs::derive_household_id`.

## Prepare

Endpoint: `POST /bootstrap/accept-household`

State gate: accepted only when `BootstrapState` is `uninitialized` or
`ready_for_naming`. Otherwise return `409 already_initialized`.

Request:

```cbor
{
  "v": 1,
  "hh_id": tstr,
  "hh_pub": bstr .size 33,
  "hh_name": tstr,              ; 1..=32 UTF-8 chars, no controls
  "invitation_token": bstr .size 32
}
```

Server actions:

1. Consume `invitation_token` from the setup-invitation cache. The token must
   exist, be unspent, and expire no later than one hour from the server's
   current time.
2. Verify `hh_pub` is a compressed P-256 public key and
   `derive_household_id(hh_pub) == hh_id`.
3. Persist a follower `HouseholdRecord` with no local household private key.
4. Mint and persist local `M_priv`/`M_pub`.
5. Build canonical CBOR for:

```cbor
{
  "v": 1,
  "hh_id": tstr,
  "m_pub": bstr .size 33,
  "machine_nonce": bstr .size 32,
  "timestamp": uint
}
```

6. Persist `BootstrapState=ready_for_naming`.

Response:

```cbor
{
  "v": 1,
  "m_id": tstr,
  "m_pub": bstr .size 33,
  "join_challenge": bstr,
  "challenge_sig_required": true
}
```

## Confirm

Endpoint: `POST /bootstrap/accept-household/confirm`

State gate: accepted only when `BootstrapState` is `ready_for_naming` and a
pending accept-household record exists. Otherwise return `409`.

Request:

```cbor
{
  "v": 1,
  "m_id": tstr,
  "machine_cert": bstr,
  "challenge_sig": bstr .size 64
}
```

Server actions:

1. Verify `m_id` matches pending accept-household state.
2. Verify `challenge_sig` under `hh_pub` over the original canonical
   `join_challenge` bytes.
3. Decode and verify `machine_cert`: household issuer, signature under
   `hh_pub`, `hh_id` match, and subject `m_pub`/`m_id` match the local machine
   key. No expiry field exists in the current certificate schema.
4. Atomically persist `HouseholdRecord`, `machine_certs/<m_id>.cbor`, and
   `self_m_id`.
5. Transition `ready_for_naming -> named_awaiting_pair -> ready`.
6. The normal household Bonjour publisher advertises
   `_soyeht-household._tcp` with `bootstrap_state=ready`.

### MachineCert Sign-Bytes

The iPhone signs the canonical CBOR for `MachineCert` with the `signature`
field omitted. The signed map contains exactly these fields:

```cbor
{
  "v": 1,
  "m_id": tstr,
  "type": "machine",
  "hh_id": tstr,
  "m_pub": bstr .size 33,
  "caveats": [],
  "hostname": tstr,
  "platform": "macos" / "linux-nix" / "linux-other",
  "issued_by": tstr,            ; same household id as hh_id
  "joined_at": uint
}
```

Map keys are sorted by bytewise lexicographic order of each key's canonical
CBOR encoding, matching
`admin/rust/household-rs/src/cbor.rs::to_canonical_vec`. This is a raw
encoded-key byte comparison, not a field declaration order and not a separate
semantic string comparison. For the fields above, the canonical order is:
`v`, `m_id`, `type`, `hh_id`, `m_pub`, `caveats`, `hostname`, `platform`,
`issued_by`, `joined_at`.

Using the worked example below, the `MachineCert` sign-bytes are:

```text
aa617601646d5f696478366d5f716d7a76707961326c366662356574727069736a727070636b6761637168376e683774646e67706261777a6f73356933777961616474797065676d616368696e656568685f6964783768685f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e327832323372327166366167697271656d5f707562582103d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf367636176656174738068686f73746e616d656b6578616d706c652d6d616368706c6174666f726d656d61636f73696973737565645f6279783768685f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e327832323372327166366167697271696a6f696e65645f61741a6a0cf980
```

Signing those bytes with the worked example's iPhone household key
(`HH_priv = 1111111111111111111111111111111111111111111111111111111111111111`)
produces this raw P-256 ECDSA `r || s` signature:

```text
ee63cd2552688da87114802f1e30eb60af9b801a92d1f5a88ff8c290ee7b420b0d8c76eeb3d2cba2cec91f9c909203e77956d0f8eff57e1e2842366a2c2fe73a
```

The final `machine_cert` embeds that signature as the `signature` field and is
then canonical CBOR encoded again.

Response:

```cbor
{
  "v": 1,
  "bootstrap_state": "ready",
  "m_id": tstr,
  "hh_id": tstr
}
```

## Errors

| HTTP | Error | Condition |
| --- | --- | --- |
| 400 | `invalid_cbor` | Body is not canonical CBOR, has duplicate/unknown top-level keys, wrong version, or wrong structural shape. |
| 400 | `invalid_request` | Fixed-size non-crypto fields have the wrong size. |
| 400 | `invalid_name` | `hh_name` is empty, too long, or contains controls. |
| 404 | `invitation_not_found` | `invitation_token` is unknown to the setup-invitation cache. |
| 409 | `already_initialized` | Prepare called outside `uninitialized`/`ready_for_naming`. |
| 409 | `accept_household_not_pending` | Confirm called outside the pending accept state. |
| 410 | `invitation_expired_or_spent` | `invitation_token` expired, exceeds the one-hour TTL cap, or was already consumed. |
| 422 | `crypto_validation_failed` | P-256 key validation, household-id derivation, challenge signature, or `MachineCert` validation fails. |
| 500 | `internal_error` / `keygen_failed` | Keystore, filesystem, or unexpected internal failure. |

## State Diagram

No new `BootstrapState` variant is introduced. The durable pending
accept-household record is separate on-disk state while the serialized
`BootstrapState` remains `ready_for_naming`.

| Endpoint | State Before | State After |
| --- | --- | --- |
| `POST /bootstrap/accept-household` | `uninitialized` | `ready_for_naming` |
| `POST /bootstrap/accept-household` | `ready_for_naming` | `ready_for_naming` |
| `POST /bootstrap/accept-household/confirm` | `ready_for_naming` with pending accept-household record | `ready` |

```text
uninitialized
  └─ POST /bootstrap/accept-household
       → ready_for_naming
            └─ POST /bootstrap/accept-household/confirm
                 → named_awaiting_pair
                      → ready
```

During confirm the handler persists the intermediate
`named_awaiting_pair` state and immediately persists `ready` after the
follower identity is loaded.
