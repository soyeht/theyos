# Contract — Canonical CBOR Schemas

**Feature**: 001-phase-1-crypto-skeleton
**Encoding**: Deterministic CBOR per RFC 8949 §4.2.1 (sorted map keys lexicographically by encoded key bytes, definite-length, shortest-form integers).

These schemas are **on-disk and over-the-wire** representations. Every field name shown is a CBOR text string used as a map key. Future phases (4+) will replicate these payloads via gossip; the encoding contract is locked here so signatures stay verifiable.

---

## `HouseholdRecord` (CBOR map)

```
{
  "v":           1,                       ; uint, currently 1 (wire field name is "v" — matches docs/household-protocol.md §4 §5)
  "hh_id":       "hh_kxqz...p1",          ; tstr, length 55 (hh_ + 52 base32 chars)
  "hh_pub":      h'aabbccdd...',          ; bstr (33 bytes, SEC1-compressed P-256 public key)
  "name":        "Sample Home",             ; tstr, 1..=64 UTF-8 printable
  "created_at":  1714972800,              ; uint, Unix seconds
  "shamir_k":    1,                       ; uint, MUST be 1 in Phase 1
  "shamir_n":    1,                       ; uint, MUST be 1 in Phase 1
  "members":     ["m_abcd...01"]          ; array of tstr, length 1 in Phase 1
}
```

**Validation on load**:
- All keys present; no unknown keys (forward-compat is handled by `version`, not by ignoring unknown fields in the same `version`).
- `hh_id` MUST equal `derive_household_id(hh_pub)`; this guards against tampered records.
- `shamir_k == shamir_n == 1` (Phase 1 invariant; future phases relax).

**Signature**: this record itself is **not** signed. Its integrity is rooted in `hh_id == BLAKE3-256(hh_pub)` plus the OS file permissions; the `MachineCert` is what carries a signature back to `hh_pub`.

---

## `MachineCert` (CBOR map)

```
{
  "v":           1,                       ; uint, currently 1 (wire field name is "v" — matches docs/household-protocol.md §4 §5)
  "type":        "machine",               ; tstr, fixed in Phase 1
  "hh_id":       "hh_kxqz...p1",          ; tstr
  "m_id":        "m_abcd...01",           ; tstr
  "m_pub":       h'1234abcd...',          ; bstr (33 bytes, SEC1-compressed P-256 public key)
  "hostname":    "mac-studio.local",      ; tstr, 1..=255
  "platform":    "macos",                 ; tstr, one of: "macos" | "linux-nix" | "linux-other"
  "joined_at":   1714972800,              ; uint, Unix seconds
  "issued_by":   "hh_kxqz...p1",          ; tstr — Phase 1: MUST be the hh_id; format reserves room for "p_..." / "d_..." / "m_..." prefixes in Phase 5+ (delegation)
  "caveats":     [],                      ; array — Phase 1: MUST be empty; Phase 5+ carries capability caveats (claws.create, claws.use:specific(id), expires_at, scope:member(p_id))
  "signature":   h'5566...'               ; bstr (64 bytes raw `r || s` ECDSA P-256 signature; NOT DER)
}
```

**Why `issued_by` is a tagged-prefix string and `caveats` is reserved now**: user stories 4, 5, 7, 10, 11 (see project memory `project_household_user_stories`) require capability delegation — Owner's owner cert signing a power-user cert for his pai (US4), a hyper-restricted `claws.use:specific(...)` cert for his mãe (US5), a derived device cert from pai's iPhone to his iPad (US10), and capability rotation (US11). If Phase 1 locks the CBOR map without these slots, Phase 5 has to introduce `version: 2` and break compatibility. Reserving the slots now (with empty/root-only values enforced by the Phase 1 validator) keeps the wire format stable across the whole roadmap.

### Canonical bytes for signing

The signature covers the deterministic CBOR encoding of the **same map with the `signature` field omitted entirely** (not zeroed, not present). Sender:

```
canonical = encode_canonical(map_without("signature"))
sig       = ECDSA-P256::sign(canonical, hh_priv)        // 64 bytes raw r || s
                                                        //   on macOS: SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256) → strip DER
                                                        //   on Linux: p256::ecdsa::SigningKey::sign
final     = encode_canonical(map_with("signature" => sig))
```

Verifier:

```
parsed     = decode(bytes)
sig        = parsed["signature"]                         // 64 bytes raw r || s
canonical  = encode_canonical(remove_key(parsed, "signature"))
ok         = ECDSA-P256::verify(canonical, sig, hh_pub_from(record))
                                                         //   p256 crate (cross-platform); SEC1 compressed pubkey
```

Implementations MUST NOT use "sign over the file as written then re-write with signature appended" — that pattern produces non-deterministic canonical bytes if the encoder ever changes map ordering.

### Validation on load

1. `v == 1`, `type == "machine"`.
2. `derive_machine_id(m_pub) == m_id`.
3. `issued_by == hh_id` (Phase 1 invariant: the prefix-tagged string MUST be the household id, not any other subject).
4. `caveats == []` (Phase 1 invariant: any non-empty caveats list is rejected; capability semantics arrive in Phase 5 with a `version: 2` cert).
5. `ECDSA-P256::verify(canonical_without_signature, signature, hh_pub_from_HouseholdRecord) == Ok`.
6. `hostname` and `platform` well-formed.

Any failure → process refuses to start (FR-012).

---

## Hash convention

```
hash_bytes  = BLAKE3-256(public_key_bytes)        ; 32 bytes
trunc       = hash_bytes                          ; full 32 bytes (no truncation needed in v0.1)
b32         = base32_lower_no_pad(trunc)          ; 52 chars: alphabet "abcdefghijklmnopqrstuvwxyz234567"
hh_id       = "hh_" || b32                        ; 55 chars total
m_id        = "m_"  || b32                        ; 54 chars total
```

The fallback path uses `SHA-256` instead of `BLAKE3-256`; the fallback path is feature-gated and not enabled on the supported Phase 1 platforms.

---

## CBOR encoder requirements

The Rust crate `ciborium` emits canonical CBOR by default for the value model used here (BTreeMap with string keys, no floating-point, no tags). Implementation in `household-rs/src/cbor.rs` provides a `to_canonical_vec<T>(value: &T) -> Result<Vec<u8>>` helper that:

1. Serializes via `ciborium::ser::into_writer`.
2. Verifies the output is canonical by round-tripping (decode + re-encode + byte-compare). Mismatch is a programming bug and aborts (this is a debug-mode invariant; release builds skip the round-trip check after a `cargo test` proof for each schema).

---

## Forward-compatibility note

Phase 4 and later will introduce CBOR map members not present here (e.g., `peers` for gossip routing). Those will only appear under `version >= 2`. Implementations MUST refuse to load a record whose `version` exceeds their max-supported value.
