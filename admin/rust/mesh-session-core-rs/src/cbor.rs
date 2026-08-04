//! Canonical (RFC 8949 deterministic) CBOR encode/decode.
//!
//! B-SESSAO v6 §3 requires: sorted map keys, shortest form, definite length,
//! and closed decoding that rejects unknown/duplicate/null/trailing/
//! non-canonical input. `ciborium` already emits shortest-form scalars and
//! definite-length collections when serializing a `Value`, so canonicality
//! reduces to: sort every map's entries by the byte-wise order of their own
//! canonical encoding, then require the re-serialized bytes to match the
//! input exactly.
//!
//! **Hardened 2026-08-04, independent audit of `911409eb`:** no B-SESSAO
//! schema uses CBOR tags, floats, or non-text map keys — `reject_disallowed`
//! now rejects all three explicitly, at every depth (recursing into map
//! *keys* as well as values, which the original `canonicalize` did not do),
//! rather than silently passing them through a catch-all match arm. The
//! same pass also rejects null and duplicate keys (duplicate detection is
//! now a hash-set membership check, not the original's `O(n^2)` `Vec::
//! contains` scan). Both `to_canonical_vec` (encode) and `verify_canonical`
//! (decode) now run this pass, so the encoder can no longer emit bytes the
//! decoder would then reject — the original let `to_canonical_vec` produce
//! a null/duplicate that `from_canonical_bytes` on the very same bytes
//! would refuse.

use ciborium::Value;
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashSet;
use std::io::Cursor;

use crate::error::CborError;

/// Serialize `value` as canonical CBOR bytes. Refuses to emit anything
/// [`verify_canonical`] would later reject — see the module-level hardening
/// note.
pub fn to_canonical_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut raw = Vec::new();
    ciborium::ser::into_writer(value, &mut raw).map_err(|_| CborError::Encode)?;
    let parsed: Value =
        ciborium::de::from_reader(Cursor::new(&raw)).map_err(|_| CborError::Encode)?;
    reject_disallowed(&parsed)?;
    let canonical = canonicalize(parsed);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&canonical, &mut out).map_err(|_| CborError::Encode)?;
    Ok(out)
}

/// Decode `bytes` as `T`, rejecting anything that is not exactly the closed,
/// canonical encoding of `T` (`#[serde(deny_unknown_fields)]` on `T` supplies
/// the "unknown field" half; this function supplies canonical/duplicate/
/// null/trailing/tag/float/non-text-key rejection).
pub fn from_canonical_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CborError> {
    verify_canonical(bytes)?;
    ciborium::de::from_reader(Cursor::new(bytes)).map_err(|_| CborError::UnknownField)
}

/// Structural-only canonical check, usable on a raw map body before it is
/// known which concrete type (if any) it should decode into.
pub fn verify_canonical(bytes: &[u8]) -> Result<(), CborError> {
    let mut cursor = Cursor::new(bytes);
    let parsed: Value = ciborium::de::from_reader(&mut cursor).map_err(|_| CborError::Decode)?;
    if cursor.position() as usize != bytes.len() {
        return Err(CborError::TrailingBytes);
    }
    reject_disallowed(&parsed)?;
    let canonical = canonicalize(parsed);
    let mut re_encoded = Vec::new();
    ciborium::ser::into_writer(&canonical, &mut re_encoded).map_err(|_| CborError::Encode)?;
    if re_encoded != bytes {
        return Err(CborError::NonCanonical);
    }
    Ok(())
}

/// Canonical byte encoding of a single `Value`, used only as a sort/compare
/// key — never emitted directly.
fn encode_key(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).expect("Value serialization is infallible");
    out
}

/// Sorts every map's entries by canonical key encoding, recursing into
/// both values *and* array elements. Does not need to recurse into map
/// keys or tag payloads itself — [`reject_disallowed`] runs first on every
/// call path into this function ([`to_canonical_vec`], [`verify_canonical`])
/// and rejects tags and non-text keys outright, so this function never
/// actually observes either shape in practice. It stays total (no panics)
/// regardless: unrecognized shapes just pass through `other => other`
/// unchanged, and the caller's `reject_disallowed` pass is what makes that
/// safe.
fn canonicalize(v: Value) -> Value {
    match v {
        Value::Map(entries) => {
            let mut sorted: Vec<(Value, Value)> = entries
                .into_iter()
                .map(|(k, val)| (k, canonicalize(val)))
                .collect();
            sorted.sort_by_key(|(k, _)| encode_key(k));
            Value::Map(sorted)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        other => other,
    }
}

/// Rejects, at every depth (map values, map *keys*, and array elements):
/// `null`, CBOR tags, floats, non-text map keys, and duplicate map keys.
/// No B-SESSAO schema uses the first three shapes, so — per the audit
/// finding that the previous version silently passed unrecognized `Value`
/// variants through a `_ => Ok(())` catch-all — every recognized shape is
/// named explicitly and anything else is rejected by an exhaustive-in-
/// intent final arm, not assumed safe.
fn reject_disallowed(v: &Value) -> Result<(), CborError> {
    match v {
        Value::Null => Err(CborError::NullNotAllowed),
        Value::Tag(_, inner) => {
            let _ = inner; // rejected regardless of what it contains
            Err(CborError::TagNotAllowed)
        }
        Value::Float(_) => Err(CborError::FloatNotAllowed),
        Value::Map(entries) => {
            let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(entries.len());
            for (k, val) in entries {
                if k.as_text().is_none() {
                    return Err(CborError::NonTextKey);
                }
                reject_disallowed(k)?;
                if !seen.insert(encode_key(k)) {
                    return Err(CborError::DuplicateKey);
                }
                reject_disallowed(val)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                reject_disallowed(item)?;
            }
            Ok(())
        }
        Value::Integer(_) | Value::Bytes(_) | Value::Text(_) | Value::Bool(_) => Ok(()),
        _ => Err(CborError::DisallowedShape),
    }
}

/// Strip the exactly-one top-level `"sig"` entry from `canonical_bytes`
/// (which must already be canonical — checked, not assumed), re-serialized
/// canonically. Private: this is narrow, internal plumbing for deriving a
/// signature preimage from a schema known (by the caller, which controls
/// the type) to carry exactly one `sig` field — not a general "remove any
/// key" utility, and it never silently tolerates zero or multiple matches
/// the way the pre-hardening version did.
fn without_sig_field(canonical_bytes: &[u8]) -> Result<Vec<u8>, CborError> {
    verify_canonical(canonical_bytes)?;
    let parsed: Value =
        ciborium::de::from_reader(Cursor::new(canonical_bytes)).map_err(|_| CborError::Decode)?;
    let Value::Map(entries) = parsed else {
        return Err(CborError::Decode);
    };
    let sig_count = entries
        .iter()
        .filter(|(k, _)| k.as_text() == Some("sig"))
        .count();
    if sig_count != 1 {
        return Err(CborError::MissingOrDuplicateSigField);
    }
    let filtered: Vec<(Value, Value)> = entries
        .into_iter()
        .filter(|(k, _)| k.as_text() != Some("sig"))
        .collect();
    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(filtered), &mut out).map_err(|_| CborError::Encode)?;
    Ok(out)
}

/// Canonical CBOR of `value` with its one `sig` field removed — the
/// signing/verification preimage for any schema with exactly one `sig`
/// entry (the outer K_mesh-signed auth frames, per v6 §3's frozen
/// `signed_preimage = type_byte || canonical_cbor(unsigned_body)`
/// formula). Fails if `value` does not serialize to canonical bytes with
/// exactly one `sig` entry.
pub fn unsigned_preimage_body<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    let full = to_canonical_vec(value)?;
    without_sig_field(&full)
}

/// Does the raw bytes of a canonical CBOR map contain the reserved `"type"`
/// text key at the top level? Used by the post-handshake frame decoder
/// (wire.rs) — B-SESSAO v6 §3 requires the body map to be closed against
/// this key because `type` lives outside the CBOR, in the frame's leading
/// byte.
pub fn map_has_top_level_key(bytes: &[u8], key: &str) -> Result<bool, CborError> {
    let parsed: Value =
        ciborium::de::from_reader(Cursor::new(bytes)).map_err(|_| CborError::Decode)?;
    match parsed {
        Value::Map(entries) => Ok(entries.iter().any(|(k, _)| k.as_text() == Some(key))),
        _ => Err(CborError::Decode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        b_field: u32,
        a_field: u32,
        c_field: String,
    }

    fn raw_bytes(v: Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&v, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn round_trip_is_canonical_and_sorted() {
        let s = Sample {
            b_field: 2,
            a_field: 1,
            c_field: "x".into(),
        };
        let bytes = to_canonical_vec(&s).unwrap();
        // a_field ("a_field") sorts before b_field ("b_field") in the
        // canonical map, even though the struct declares b_field first.
        verify_canonical(&bytes).unwrap();
        let back: Sample = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn red_unsorted_keys_rejected_both_directions() {
        let bytes = raw_bytes(Value::Map(vec![
            (Value::Text("b_field".into()), Value::Integer(2.into())),
            (Value::Text("a_field".into()), Value::Integer(1.into())),
            (Value::Text("c_field".into()), Value::Text("x".into())),
        ]));
        assert_eq!(verify_canonical(&bytes), Err(CborError::NonCanonical));
        assert!(from_canonical_bytes::<Sample>(&bytes).is_err());
    }

    #[test]
    fn red_non_shortest_form_integer_rejected() {
        // ciborium's Value::serialized integer path always picks the
        // shortest encoding, so hand-encode a longer-than-necessary form:
        // 0x18 0x05 is the 1-byte-argument encoding of the small value 5,
        // which canonically must be encoded as 0x05 alone (5 fits in the
        // initial byte itself).
        let mut bytes = vec![0xa1]; // map(1)
        bytes.push(0x61);
        bytes.push(b'a'); // text(1) "a"
        bytes.extend_from_slice(&[0x18, 0x05]); // non-shortest-form uint 5
        // The map key must be "a_field" for a fair round-trip test against
        // Sample's shape is unnecessary here — this only exercises
        // verify_canonical's structural check, not typed decode.
        assert_eq!(verify_canonical(&bytes), Err(CborError::NonCanonical));
    }

    #[test]
    fn red_indefinite_length_array_rejected() {
        // 0x9f = indefinite-length array start, 0x01 = uint 1, 0xff = break.
        let bytes = vec![0x9f, 0x01, 0xff];
        assert_eq!(verify_canonical(&bytes), Err(CborError::NonCanonical));
    }

    #[test]
    fn red_duplicate_key_rejected_both_directions() {
        let bytes = raw_bytes(Value::Map(vec![
            (Value::Text("a_field".into()), Value::Integer(1.into())),
            (Value::Text("a_field".into()), Value::Integer(2.into())),
        ]));
        assert_eq!(verify_canonical(&bytes), Err(CborError::DuplicateKey));
        assert!(from_canonical_bytes::<Sample>(&bytes).is_err());
    }

    #[test]
    fn red_null_rejected_both_directions() {
        let bytes = raw_bytes(Value::Map(vec![(
            Value::Text("a_field".into()),
            Value::Null,
        )]));
        assert_eq!(verify_canonical(&bytes), Err(CborError::NullNotAllowed));
        assert!(from_canonical_bytes::<Sample>(&bytes).is_err());
    }

    #[test]
    fn red_null_nested_inside_array_rejected() {
        let bytes = raw_bytes(Value::Map(vec![(
            Value::Text("a_field".into()),
            Value::Array(vec![Value::Null]),
        )]));
        assert_eq!(verify_canonical(&bytes), Err(CborError::NullNotAllowed));
    }

    #[test]
    fn red_trailing_bytes_rejected() {
        let s = Sample {
            b_field: 2,
            a_field: 1,
            c_field: "x".into(),
        };
        let mut bytes = to_canonical_vec(&s).unwrap();
        bytes.push(0xff);
        assert_eq!(verify_canonical(&bytes), Err(CborError::TrailingBytes));
    }

    #[test]
    fn red_non_map_top_level_rejected() {
        let bytes = raw_bytes(Value::Array(vec![Value::Integer(1.into())]));
        assert!(from_canonical_bytes::<Sample>(&bytes).is_err());
    }

    #[test]
    fn red_unknown_field_rejected_by_typed_decode() {
        let bytes = raw_bytes(Value::Map(vec![
            (Value::Text("a_field".into()), Value::Integer(1.into())),
            (Value::Text("b_field".into()), Value::Integer(2.into())),
            (Value::Text("c_field".into()), Value::Text("x".into())),
            (Value::Text("d_extra".into()), Value::Bool(true)),
        ]));
        // Canonical at the structural level...
        verify_canonical(&bytes).unwrap();
        // ...but deny_unknown_fields still rejects it against Sample.
        assert!(from_canonical_bytes::<Sample>(&bytes).is_err());
    }

    #[test]
    fn red_non_text_key_rejected_at_top_level() {
        let bytes = raw_bytes(Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Integer(1.into()),
        )]));
        assert_eq!(verify_canonical(&bytes), Err(CborError::NonTextKey));
    }

    #[test]
    fn red_non_text_key_rejected_when_nested() {
        let bytes = raw_bytes(Value::Map(vec![(
            Value::Text("outer".into()),
            Value::Map(vec![(Value::Integer(1.into()), Value::Bool(true))]),
        )]));
        assert_eq!(verify_canonical(&bytes), Err(CborError::NonTextKey));
    }

    #[test]
    fn red_tag_rejected_at_top_level_and_nested() {
        let top = raw_bytes(Value::Tag(0, Box::new(Value::Text("2026-08-04".into()))));
        assert_eq!(verify_canonical(&top), Err(CborError::TagNotAllowed));

        let nested = raw_bytes(Value::Map(vec![(
            Value::Text("a_field".into()),
            Value::Tag(0, Box::new(Value::Text("2026-08-04".into()))),
        )]));
        assert_eq!(verify_canonical(&nested), Err(CborError::TagNotAllowed));
    }

    #[test]
    fn red_float_rejected_at_top_level_and_nested() {
        let top = raw_bytes(Value::Float(1.5));
        assert_eq!(verify_canonical(&top), Err(CborError::FloatNotAllowed));

        let nested = raw_bytes(Value::Map(vec![(
            Value::Text("a_field".into()),
            Value::Float(1.5),
        )]));
        assert_eq!(verify_canonical(&nested), Err(CborError::FloatNotAllowed));
    }

    #[test]
    fn encoder_never_emits_what_the_decoder_would_reject() {
        // Regression for the audit finding: to_canonical_vec used to skip
        // reject_disallowed, so it could in principle emit a null/
        // duplicate that verify_canonical on the same bytes would then
        // refuse. There's no safe way to construct a null/duplicate via a
        // well-formed #[derive(Serialize)] struct in this crate's own
        // schemas, so this test asserts the INVARIANT directly: whatever
        // to_canonical_vec emits for a real struct, verify_canonical on
        // those exact bytes always agrees.
        let s = Sample {
            b_field: 2,
            a_field: 1,
            c_field: "x".into(),
        };
        let bytes = to_canonical_vec(&s).unwrap();
        verify_canonical(&bytes).unwrap();
    }

    #[test]
    fn type_key_detection() {
        let bytes = raw_bytes(Value::Map(vec![(
            Value::Text("type".into()),
            Value::Integer(1.into()),
        )]));
        assert!(map_has_top_level_key(&bytes, "type").unwrap());
    }

    #[test]
    fn unsigned_preimage_body_strips_exactly_one_sig() {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct WithSig {
            a: u32,
            sig: u32,
        }
        let bytes = unsigned_preimage_body(&WithSig { a: 1, sig: 2 }).unwrap();
        assert!(!map_has_top_level_key(&bytes, "sig").unwrap());
        assert!(map_has_top_level_key(&bytes, "a").unwrap());
    }

    #[test]
    fn red_unsigned_preimage_body_rejects_missing_sig() {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct NoSig {
            a: u32,
        }
        assert_eq!(
            unsigned_preimage_body(&NoSig { a: 1 }),
            Err(CborError::MissingOrDuplicateSigField)
        );
    }

    #[test]
    fn without_sig_field_accepts_a_map_with_exactly_one_sig() {
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct OnlySig {
            sig: u32,
        }
        let full = to_canonical_vec(&OnlySig { sig: 1 }).unwrap();
        assert!(without_sig_field(&full).is_ok());
    }

    // A "two sig entries" case is not separately testable as a distinct
    // code path: for a text key, two occurrences of "sig" always encode
    // identically, so verify_canonical's own duplicate-key rejection
    // (red_duplicate_key_rejected_both_directions, above) always fires
    // first — without_sig_field's `sig_count != 1` check can only ever
    // observe `0` in practice, never `>= 2`, on input that passed
    // verify_canonical. The check stays as a defense-in-depth backstop,
    // not a reachable branch worth a dedicated (and necessarily vacuous)
    // test.
}
