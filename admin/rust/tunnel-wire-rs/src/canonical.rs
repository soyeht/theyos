//! Deterministic CBOR encode/decode (RFC 8949 §4.2.1), and the sealed 0x17
//! body's only doors.
//!
//! # Why this module exists here rather than in the product crate
//!
//! The 0x17 body is sealed: [`NetworkSettingsBody`]'s field is private and its
//! byte accessors are `pub(crate)`, so "strictness cannot escape
//! `TunnelFrame::decode`". While the body and the product's strict decoder
//! shared a crate, `pub(crate)` was exactly the right visibility.
//!
//! Moving the wire mechanics to their own crate breaks that: `pub(crate)` now
//! means *within `tunnel-wire-rs`*, and Rust has no way to say "only
//! `household-rs` may call this". The three options were to make the accessors
//! `pub` (which deletes the seal — any consumer could then read or fabricate
//! settings bytes without the strict check), to duplicate the canonical codec
//! (two implementations of one check, which is how a validator bug hides), or to
//! bring the codec to the sealed type. This module is the third.
//!
//! The doors below are **method generics**, not type parameters on a wire type,
//! so the closed-wire-type rule is untouched: `TunnelFrame` stays concrete and
//! this crate never names the product's settings type.
//!
//! # What the seal does and does NOT guarantee (corrected)
//!
//! An earlier revision of this module claimed "the bytes never leave". **That
//! was wrong, and the error is worth recording because it is the same class the
//! design of these doors explicitly rejected.** A caller-supplied *identity
//! closure* (`read_with(|b| b.to_vec())`) was ruled out as a door; a
//! caller-supplied *identity type* is isomorphic to it. `ciborium::value::Value`
//! satisfies `Serialize + DeserializeOwned`, so `decode_strict::<Value>()`
//! type-checks and returns the whole structure — and byte recovery is then
//! guaranteed by the strict check's *own success criterion*, since it admits
//! input only when `to_canonical_vec(&value) == bytes`.
//!
//! Rust has no negative trait bound, and a sealed bound would also exclude the
//! product's own settings type, so this is restated rather than patched:
//!
//! * **Holds.** Non-canonical key order and trailing bytes are rejected for any
//!   `T`: canonicalization sorts, and the re-encoded item ends where the item
//!   ends. `TunnelFrame::decode` cannot yield settings that skipped that check.
//! * **Holds.** This crate still cannot *interpret* a body: it never names the
//!   product's type and cannot see the identity fields inside one.
//! * **Does NOT hold.** "Only the product's strict decoder can read a body." A
//!   consumer may pass a structurally universal `T` and read one — including a
//!   body carrying an unmodelled key, which survives into `Value` so the
//!   re-encode matches and the body is admitted. Unknown-key rejection is a
//!   property of the product's concrete type, not of these doors.
//! * **Does NOT hold.** "Only the product can construct a body."
//!   `encode_canonical::<Value>` builds an arbitrary canonical one.
//!
//! **Scope of the regression, measured rather than assumed:** byte recovery for
//! *valid* bodies and `session_id` disclosure were already reachable at the base
//! via decode-then-public-re-encode. Genuinely new here are (i) reading a body
//! the product's strict decoder would reject, and (ii) fabricating arbitrary
//! canonical bodies — which `pub(crate) from_bytes` previously prevented.
//!
//! `tunnel_wire.rs` is deliberately NOT edited to add these — it moved
//! byte-identically, and an inherent `impl` may live in any module of the
//! defining crate.
//!
//! `household-rs`'s `cbor` module delegates to the three free functions here, so
//! there is exactly one canonical implementation in the workspace and its 431
//! call sites keep their signatures.

use serde::{Serialize, de::DeserializeOwned};

use crate::tunnel_wire::{NetworkSettingsBody, WireError};

fn cbor_err(context: &str, error: impl core::fmt::Display) -> WireError {
    WireError::Cbor(format!("{context}: {error}"))
}

/// Encode a value as canonical CBOR bytes.
pub fn to_canonical_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, WireError> {
    let mut initial = Vec::with_capacity(256);
    ciborium::ser::into_writer(value, &mut initial).map_err(|e| cbor_err("encode", e))?;
    let mut value: ciborium::value::Value = ciborium::de::from_reader(initial.as_slice())
        .map_err(|e| cbor_err("canonical value decode", e))?;
    canonicalize_value(&mut value)?;

    let mut buf = Vec::with_capacity(initial.len());
    ciborium::ser::into_writer(&value, &mut buf)
        .map_err(|e| cbor_err("canonical value encode", e))?;

    // Debug-mode invariant: decode → re-encode → byte-compare must be a fixed
    // point after recursive map sorting.
    #[cfg(debug_assertions)]
    {
        let value: ciborium::value::Value = ciborium::de::from_reader(buf.as_slice())
            .map_err(|e| cbor_err("debug round-trip decode", e))?;
        let mut value = value;
        canonicalize_value(&mut value)?;
        let mut re_encoded = Vec::with_capacity(buf.len());
        ciborium::ser::into_writer(&value, &mut re_encoded)
            .map_err(|e| cbor_err("debug round-trip re-encode", e))?;
        if re_encoded != buf {
            return Err(WireError::Cbor(format!(
                "debug round-trip mismatch: {} vs {} bytes — encoder is non-canonical",
                buf.len(),
                re_encoded.len(),
            )));
        }
    }

    Ok(buf)
}

fn canonicalize_value(value: &mut ciborium::value::Value) -> Result<(), WireError> {
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

fn canonical_key_bytes(value: &ciborium::value::Value) -> Result<Vec<u8>, WireError> {
    let mut bytes = Vec::with_capacity(32);
    ciborium::ser::into_writer(value, &mut bytes)
        .map_err(|e| cbor_err("canonical map key encode", e))?;
    Ok(bytes)
}

/// Decode canonical CBOR bytes into a typed value.
///
/// This is the LENIENT decoder and it does not verify what its name suggests:
/// it accepts any well-formed CBOR that deserializes, including maps whose keys
/// are not in canonical order, keys the target type does not model, and trailing
/// bytes after the item (`ciborium` stops at the end of the first item and never
/// checks for EOF). That tolerance is load-bearing for the callers that read
/// durable at-rest state, so it stays. Callers decoding UNTRUSTED bytes whose
/// exact form is part of the contract should use [`from_canonical_slice_strict`].
pub fn from_canonical_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    ciborium::de::from_reader(bytes).map_err(|e| cbor_err("decode", e))
}

/// Decode canonical CBOR bytes into a typed value, admitting ONLY the exact byte
/// string this crate's encoder would have produced for that value.
///
/// Decode, re-encode the TYPED value canonically, and require byte equality
/// against the whole input. One comparison closes three distinct holes, because
/// the typed value is a lossy projection of the input:
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
/// **That last sentence binds the IMPLEMENTATION's internal choice, not the
/// caller's `T`** — and `Value` satisfies the very bound credited with excluding
/// it. So the unmodelled-key rejection is a property of passing a concrete
/// modelled type, which the product does; it is not a property this function
/// enforces against an arbitrary caller. Recorded because the original wording
/// reads as the stronger claim.
///
/// Reserved for untrusted input where the encoding is part of the contract. It
/// is deliberately NOT the default: applying it to durable at-rest state would
/// turn any already-persisted non-canonical byte into an unreadable file, which
/// is a migration decision, not a hardening one.
pub fn from_canonical_slice_strict<T: Serialize + DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, WireError> {
    let value: T = from_canonical_slice(bytes)?;
    let re_encoded = to_canonical_vec(&value)?;
    if re_encoded != bytes {
        return Err(WireError::Cbor(format!(
            "non-canonical encoding: {} input bytes vs {} canonical bytes",
            bytes.len(),
            re_encoded.len(),
        )));
    }
    Ok(value)
}

// ─── The sealed body's only doors ───────────────────────────────────────────

impl NetworkSettingsBody {
    /// Produce a body from an already-canonical encoding of `value`.
    ///
    /// The owning product supplies its own settings type; this crate never names
    /// it and cannot see the identity fields inside.
    pub fn encode_canonical<T: Serialize>(value: &T) -> Result<Self, WireError> {
        to_canonical_vec(value).map(Self::from_bytes)
    }

    /// [`Self::encode_canonical`], falling back to an EMPTY body on encode
    /// failure.
    ///
    /// Exists to preserve the pre-extraction product expression
    /// `NetworkSettingsBody::from_bytes(to_canonical_vec(..).unwrap_or_default())`
    /// byte-for-byte: `unwrap_or_default()` on `Result<Vec<u8>, _>` yields the
    /// EMPTY vector, not an encoding of anything. Rebuilding that from outside
    /// would need an arbitrary-bytes constructor, which is the seal. The empty
    /// body is safe to offer because no strict decode accepts it, and the caller
    /// still cannot choose the bytes.
    #[must_use]
    pub fn encode_canonical_or_empty<T: Serialize>(value: &T) -> Self {
        Self::from_bytes(to_canonical_vec(value).unwrap_or_default())
    }

    /// Strictly interpret the body as `T`.
    ///
    /// Guarantees canonicity — non-canonical key order and trailing bytes are
    /// rejected for every `T`. It does **not** confine reading to the product:
    /// the caller chooses `T`, and a structurally universal one recovers the
    /// content. See the module docs; the invariant is stated there rather than
    /// patched here, because Rust has no negative bound and a sealed one would
    /// exclude the product's own type too.
    pub fn decode_strict<T: Serialize + DeserializeOwned>(&self) -> Result<T, WireError> {
        from_canonical_slice_strict(self.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
    struct Sample {
        b: u8,
        a: u8,
    }

    /// The seal, as a mechanism: a body round-trips only through the doors, and
    /// the strict door rejects a non-canonical encoding. Positive control first
    /// so the negative cannot pass by rejecting everything.
    #[test]
    fn sealed_body_round_trips_and_rejects_non_canonical_bytes() {
        let sample = Sample { b: 2, a: 1 };
        let body = NetworkSettingsBody::encode_canonical(&sample).expect("encode");
        assert_eq!(body.decode_strict::<Sample>().expect("decode"), sample);

        // Declaration order is b,a; canonical order is a,b. Feeding serde's
        // unsorted encoding through the strict door must FAIL.
        let mut unsorted = Vec::new();
        ciborium::ser::into_writer(&sample, &mut unsorted).expect("serde encode");
        let canonical = to_canonical_vec(&sample).expect("canonical encode");
        assert_ne!(
            unsorted, canonical,
            "fixture is vacuous unless the two encodings actually differ"
        );
        assert!(from_canonical_slice_strict::<Sample>(&unsorted).is_err());
        assert!(from_canonical_slice_strict::<Sample>(&canonical).is_ok());
    }
}
