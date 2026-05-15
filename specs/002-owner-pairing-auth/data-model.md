# Data Model: Phase 2 - Owner Pairing and Proof-of-Possession Auth

## PairingProofContext

Canonical CBOR signed by the Soyeht app's newly generated `P_priv` before theyOS issues a PersonCert.

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `purpose` | text | MUST be `pair-device-confirm` |
| `hh_id` | text | MUST equal the local household id |
| `nonce` | bytes | 32-byte active pair nonce |
| `p_pub` | bytes | 33-byte SEC1 compressed P-256 public key |

Validation:
- CBOR MUST be deterministic.
- Signature MUST be 64-byte raw P-256 ECDSA `r || s`.
- `p_pub` MUST derive to the submitted `p_id`.

## PersonCert

The first owner capability certificate signed by the household root.

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `type` | text | MUST be `person` |
| `hh_id` | text | MUST equal local household id |
| `p_id` | text | Derived from `p_pub` |
| `p_pub` | bytes | 33-byte SEC1 compressed P-256 public key |
| `display_name` | text | App-provided value or `Owner`; 1..=64 UTF-8 bytes |
| `caveats` | array | MUST contain owner caveat template |
| `not_before` | int | Unix seconds, <= `issued_at` |
| `not_after` | int/null | `null` for no expiry in this phase |
| `nonce` | bytes | 16 random bytes for cert uniqueness |
| `issued_at` | int | Unix seconds |
| `issued_by` | text | `SubjectId::Household` encoding, serialized as the bare `hh_...` household id |
| `signature` | bytes | 64-byte raw P-256 ECDSA signature by household root |

State transitions:
- `Draft` -> `Signed` only after pair token consumption succeeds.
- `Signed` -> `Persisted` after atomic write of owner auth state.
- Tampered or unverifiable certs are never loaded as valid.

## Caveat

Capability constraint already reserved by Phase 1 and activated for PersonCert.

| Field | Type | Rules |
|---|---|---|
| `op` | text | One of the protocol operation strings |
| `scope` | map/null | `{all:true}`, `{owned_by_self:true}`, `{specific:[...]}`, or null as required by op |
| `constraints` | map/null | Optional; Phase 2 supports empty/null only for owner template |

Owner template:
- `claws.list` all
- `claws.create` all
- `claws.delete` all
- `claws.use` all
- `claws.assign` all
- `household.invite`
- `household.revoke`
- `household.add_machine`

## HouseholdAuthState

Persisted local state used by theyOS to validate future owner requests.

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `hh_id` | text | MUST equal `HouseholdRecord.hh_id` |
| `owner_person_cert` | PersonCert | MUST verify against household root |
| `created_at` | int | Unix seconds of first successful owner pairing |
| `updated_at` | int | Equals `created_at` in this phase |

Storage:
- `owner_person_cert.cbor` contains the signed PersonCert for direct fixture loading.
- `household_auth_state.cbor` contains the envelope used by server startup.
- Both writes use existing atomic CBOR write semantics.

## RequestSigningContext

Canonical CBOR signed by `P_priv` for household-scoped requests.

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `method` | text | Uppercase HTTP method |
| `path_and_query` | text | Exact request target excluding scheme/host |
| `timestamp` | int | Unix seconds, accepted within ±60 seconds |
| `body_hash` | bytes | BLAKE3-256 over request body bytes; hash of empty body for no body |

Validation:
- Header `p_id` must match persisted owner PersonCert.
- Signature verifies against `PersonCert.p_pub`.
- PersonCert verifies against household root before caveats are evaluated.
- Request operation must map to an allowed caveat.

## PairDeviceConfirmRequest

HTTP JSON body for the pair-device confirm endpoint.

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `nonce` | base64url string | 32-byte pair nonce |
| `p_pub` | base64url string | 33-byte SEC1 compressed P-256 public key |
| `display_name` | string/null | Optional; defaults to `Owner` |
| `proof_sig` | base64url string | 64-byte raw P-256 signature over PairingProofContext |

## PairDeviceConfirmResponse

HTTP JSON response on success.

| Field | Type | Rules |
|---|---|---|
| `v` | uint | MUST be `1` |
| `hh_id` | string | Local household id |
| `p_id` | string | Owner person id |
| `person_cert_cbor` | base64url string | Deterministic CBOR PersonCert |
| `capabilities` | array | Human-readable operation names for app state |

No DeviceCert fields are present in this phase.
