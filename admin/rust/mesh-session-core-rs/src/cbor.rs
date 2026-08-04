//! Canonical (RFC 8949 deterministic) CBOR encode/decode.
//!
//! B-SESSAO v6 §3 requires: sorted map keys, shortest form, definite length,
//! and closed decoding that rejects unknown/duplicate/null/trailing/
//! non-canonical input. `ciborium` already emits shortest-form scalars and
//! definite-length collections when serializing a `Value`, so canonicality
//! reduces to: sort every map's entries by the byte-wise order of their own
//! canonical encoding, then require the re-serialized bytes to match the
//! input exactly. Duplicate keys and embedded nulls are not caught by that
//! round-trip (a sorted list can still contain adjacent duplicates, and
//! `Value::Null` re-serializes to itself), so both are checked explicitly.

use ciborium::Value;
use serde::{Serialize, de::DeserializeOwned};
use std::io::Cursor;

use crate::error::CborError;

/// Serialize `value` as canonical CBOR bytes.
///
/// The type's own `Serialize` impl controls field order, which need not be
/// sorted — this function re-encodes through a `Value` tree and sorts every
/// map before emitting bytes, so the output is canonical regardless of the
/// order `#[derive(Serialize)]` would otherwise use.
pub fn to_canonical_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut raw = Vec::new();
    ciborium::ser::into_writer(value, &mut raw).map_err(|_| CborError::Encode)?;
    let parsed: Value =
        ciborium::de::from_reader(Cursor::new(&raw)).map_err(|_| CborError::Encode)?;
    let canonical = canonicalize(parsed);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&canonical, &mut out).map_err(|_| CborError::Encode)?;
    Ok(out)
}

/// Decode `bytes` as `T`, rejecting anything that is not exactly the closed,
/// canonical encoding of `T` (`#[serde(deny_unknown_fields)]` on `T` supplies
/// the "unknown field" half; this function supplies canonical/duplicate/
/// null/trailing rejection).
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
    reject_null_and_duplicates(&parsed)?;
    let canonical = canonicalize(parsed);
    let mut re_encoded = Vec::new();
    ciborium::ser::into_writer(&canonical, &mut re_encoded).map_err(|_| CborError::Encode)?;
    if re_encoded != bytes {
        return Err(CborError::NonCanonical);
    }
    Ok(())
}

/// Canonical byte encoding of a single `Value`, used only as a sort/compare
/// key — never emitted directly (map recursion is not canonicalized here).
fn encode_key(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    // A key is a scalar or nested structure in general CBOR, but every
    // B-SESSAO schema uses text keys; encoding whatever is actually present
    // keeps this correct for any legal CBOR map, not just the common case.
    ciborium::ser::into_writer(v, &mut out).expect("Value serialization is infallible");
    out
}

fn canonicalize(v: Value) -> Value {
    match v {
        Value::Map(entries) => {
            let mut sorted: Vec<(Value, Value)> = entries
                .into_iter()
                .map(|(k, val)| (k, canonicalize(val)))
                .collect();
            sorted.sort_by(|(k1, _), (k2, _)| encode_key(k1).cmp(&encode_key(k2)));
            Value::Map(sorted)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        other => other,
    }
}

fn reject_null_and_duplicates(v: &Value) -> Result<(), CborError> {
    match v {
        Value::Null => Err(CborError::NullNotAllowed),
        Value::Map(entries) => {
            let mut seen: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                let encoded = encode_key(k);
                if seen.contains(&encoded) {
                    return Err(CborError::DuplicateKey);
                }
                seen.push(encoded);
                reject_null_and_duplicates(val)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                reject_null_and_duplicates(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Return `bytes` (a canonical CBOR map) with its top-level `key` entry
/// removed, re-serialized canonically. Used to derive a signature preimage
/// from a schema that embeds its own `sig` field (removing one entry from
/// an already-sorted map preserves sortedness, so the result is canonical
/// without needing to re-sort).
pub fn without_top_level_key(bytes: &[u8], key: &str) -> Result<Vec<u8>, CborError> {
    let parsed: Value =
        ciborium::de::from_reader(Cursor::new(bytes)).map_err(|_| CborError::Decode)?;
    let Value::Map(entries) = parsed else {
        return Err(CborError::Decode);
    };
    let filtered: Vec<(Value, Value)> = entries
        .into_iter()
        .filter(|(k, _)| k.as_text() != Some(key))
        .collect();
    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(filtered), &mut out).map_err(|_| CborError::Encode)?;
    Ok(out)
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
    fn non_sorted_keys_are_rejected() {
        // Hand-build a map with keys in DECLARATION order (b before a),
        // which is not canonical order.
        let raw = Value::Map(vec![
            (Value::Text("b_field".into()), Value::Integer(2.into())),
            (Value::Text("a_field".into()), Value::Integer(1.into())),
            (Value::Text("c_field".into()), Value::Text("x".into())),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&raw, &mut bytes).unwrap();
        assert_eq!(verify_canonical(&bytes), Err(CborError::NonCanonical));
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let raw = Value::Map(vec![
            (Value::Text("a_field".into()), Value::Integer(1.into())),
            (Value::Text("a_field".into()), Value::Integer(2.into())),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&raw, &mut bytes).unwrap();
        assert_eq!(verify_canonical(&bytes), Err(CborError::DuplicateKey));
    }

    #[test]
    fn null_is_rejected() {
        let raw = Value::Map(vec![(Value::Text("a_field".into()), Value::Null)]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&raw, &mut bytes).unwrap();
        assert_eq!(verify_canonical(&bytes), Err(CborError::NullNotAllowed));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
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
    fn unknown_field_rejected_by_typed_decode() {
        let raw = Value::Map(vec![
            (Value::Text("a_field".into()), Value::Integer(1.into())),
            (Value::Text("b_field".into()), Value::Integer(2.into())),
            (Value::Text("c_field".into()), Value::Text("x".into())),
            (Value::Text("d_extra".into()), Value::Bool(true)),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&raw, &mut bytes).unwrap();
        // Canonical at the structural level...
        verify_canonical(&bytes).unwrap();
        // ...but deny_unknown_fields still rejects it against Sample.
        assert!(from_canonical_bytes::<Sample>(&bytes).is_err());
    }

    #[test]
    fn type_key_detection() {
        let raw = Value::Map(vec![(Value::Text("type".into()), Value::Integer(1.into()))]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&raw, &mut bytes).unwrap();
        assert!(map_has_top_level_key(&bytes, "type").unwrap());
    }
}
