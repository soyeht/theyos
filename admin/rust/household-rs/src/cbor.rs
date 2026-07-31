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
///
/// This is the LENIENT decoder and it does not verify what its name suggests:
/// it accepts any well-formed CBOR that deserializes, including maps whose
/// keys are not in canonical order, keys the target type does not model, and
/// trailing bytes after the item (`ciborium` stops at the end of the first
/// item and never checks for EOF). That tolerance is load-bearing for the
/// callers that read durable at-rest state, so it stays. Callers decoding
/// UNTRUSTED bytes whose exact form is part of the contract should use
/// [`from_canonical_slice_strict`].
pub fn from_canonical_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, HouseholdError> {
    ciborium::de::from_reader(bytes).map_err(|e| HouseholdError::Cbor(format!("decode: {e}")))
}

/// Decode canonical CBOR bytes into a typed value, admitting ONLY the exact
/// byte string this crate's encoder would have produced for that value.
///
/// Decode, re-encode the TYPED value canonically, and require byte equality
/// against the whole input. One comparison closes three distinct holes,
/// because the typed value is a lossy projection of the input:
///
/// - non-canonical map key order → re-encoding sorts it, so the bytes differ;
/// - a key the type does not model → it does not survive into `T`, so the
///   re-encoded map is shorter;
/// - trailing bytes → the re-encoded item ends where the item ends.
///
/// The `Serialize` bound is what makes that true and is not incidental:
/// round-tripping through `ciborium::value::Value` instead would PRESERVE an
/// unmodelled key and silently admit it.
///
/// Reserved for untrusted input where the encoding is part of the contract.
/// It is deliberately NOT the default: applying it to durable at-rest state
/// would turn any already-persisted non-canonical byte into an unreadable
/// file, which is a migration decision, not a hardening one.
pub fn from_canonical_slice_strict<T: Serialize + DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, HouseholdError> {
    let value: T = from_canonical_slice(bytes)?;
    let re_encoded = to_canonical_vec(&value)?;
    if re_encoded != bytes {
        return Err(HouseholdError::Cbor(format!(
            "non-canonical encoding: {} input bytes vs {} canonical bytes",
            bytes.len(),
            re_encoded.len(),
        )));
    }
    Ok(value)
}
