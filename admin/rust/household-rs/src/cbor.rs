//! Deterministic CBOR encode/decode helpers (RFC 8949 §4.2.1).
//!
//! `serde` emits struct/map fields in declaration/insertion order, while RFC
//! 8949 canonical CBOR requires map keys sorted by their encoded byte form.
//! This module serializes through `ciborium::value::Value`, recursively sorts
//! every map by the bytewise lexicographic order of each key's canonical CBOR
//! encoding, then writes the sorted value.

use serde::{Serialize, de::DeserializeOwned};

use crate::error::HouseholdError;

/// Encode a value as canonical CBOR bytes.
pub fn to_canonical_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, HouseholdError> {
    let mut initial = Vec::with_capacity(256);
    ciborium::ser::into_writer(value, &mut initial)
        .map_err(|e| HouseholdError::Cbor(format!("encode: {e}")))?;
    let mut value: ciborium::value::Value = ciborium::de::from_reader(initial.as_slice())
        .map_err(|e| HouseholdError::Cbor(format!("canonical value decode: {e}")))?;
    canonicalize_value(&mut value)?;

    let mut buf = Vec::with_capacity(initial.len());
    ciborium::ser::into_writer(&value, &mut buf)
        .map_err(|e| HouseholdError::Cbor(format!("canonical value encode: {e}")))?;

    // Debug-mode invariant: decode → re-encode → byte-compare must be a fixed
    // point after recursive map sorting.
    #[cfg(debug_assertions)]
    {
        let value: ciborium::value::Value = ciborium::de::from_reader(buf.as_slice())
            .map_err(|e| HouseholdError::Cbor(format!("debug round-trip decode: {e}")))?;
        let mut value = value;
        canonicalize_value(&mut value)?;
        let mut re_encoded = Vec::with_capacity(buf.len());
        ciborium::ser::into_writer(&value, &mut re_encoded)
            .map_err(|e| HouseholdError::Cbor(format!("debug round-trip re-encode: {e}")))?;
        if re_encoded != buf {
            return Err(HouseholdError::Cbor(format!(
                "debug round-trip mismatch: {} vs {} bytes — encoder is non-canonical",
                buf.len(),
                re_encoded.len(),
            )));
        }
    }

    Ok(buf)
}

fn canonicalize_value(value: &mut ciborium::value::Value) -> Result<(), HouseholdError> {
    use ciborium::value::Value;
    match value {
        Value::Array(items) => {
            for item in items {
                canonicalize_value(item)?;
            }
        }
        Value::Map(entries) => {
            let mut sorted = Vec::with_capacity(entries.len());
            for (mut key, mut value) in std::mem::take(entries) {
                canonicalize_value(&mut key)?;
                canonicalize_value(&mut value)?;
                let key_bytes = canonical_key_bytes(&key)?;
                sorted.push((key_bytes, key, value));
            }
            sorted.sort_by(|(left, _, _), (right, _, _)| left.cmp(right));
            *entries = sorted
                .into_iter()
                .map(|(_, key, value)| (key, value))
                .collect();
        }
        Value::Tag(_, inner) => canonicalize_value(inner)?,
        _ => {}
    }
    Ok(())
}

fn canonical_key_bytes(value: &ciborium::value::Value) -> Result<Vec<u8>, HouseholdError> {
    let mut bytes = Vec::with_capacity(32);
    ciborium::ser::into_writer(value, &mut bytes)
        .map_err(|e| HouseholdError::Cbor(format!("canonical map key encode: {e}")))?;
    Ok(bytes)
}

/// Decode canonical CBOR bytes into a typed value.
pub fn from_canonical_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, HouseholdError> {
    ciborium::de::from_reader(bytes).map_err(|e| HouseholdError::Cbor(format!("decode: {e}")))
}
