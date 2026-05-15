# Contract: PersonCert CBOR

## Purpose

Defines the deterministic CBOR certificate theyOS issues for the first owner.

## Schema

```cbor
PersonCert = {
  "v": 1,
  "type": "person",
  "hh_id": "hh_...",
  "p_id": "p_...",
  "p_pub": h'...',          ; 33-byte SEC1 compressed P-256 public key
  "display_name": "Owner" / "Owner",
  "caveats": [Caveat...],
  "not_before": 1714972800,
  "not_after": null,
  "nonce": h'...',          ; 16 random bytes
  "issued_at": 1714972800,
  "issued_by": "hh_...",
  "signature": h'...'       ; 64-byte raw P-256 ECDSA r || s
}

Caveat = {
  "op": "claws.list" / "claws.create" / "claws.delete" / "claws.use" /
        "claws.assign" / "household.invite" / "household.revoke" /
        "household.add_machine",
  "scope": {"all": true} / {"owned_by_self": true} / {"specific": ["c_..."]} / null,
  "constraints": null / {...}
}
```

## Signing Bytes

The signature is computed over deterministic CBOR of the same map without the `"signature"` key.

## Required Owner Caveats

The first owner cert MUST contain:

- `claws.list` with `{all:true}`
- `claws.create` with `{all:true}`
- `claws.delete` with `{all:true}`
- `claws.use` with `{all:true}`
- `claws.assign` with `{all:true}`
- `household.invite` with null scope
- `household.revoke` with null scope
- `household.add_machine` with null scope

## Validation Rules

- `v == 1`
- `type == "person"`
- `hh_id` equals local household id
- `p_id == hash(p_pub)` using the household protocol identifier convention
- `p_pub` is valid 33-byte SEC1 compressed P-256
- `issued_by` is the local household root subject, encoded as the same
  `SubjectId::Household` text shape used by `MachineCert`
- `signature` verifies with `HouseholdRecord.hh_pub`
- `not_before <= now`; `not_after == null` or `now < not_after`
- no DeviceCert is required or embedded
