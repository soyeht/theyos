//! Deterministic CBOR encode/decode helpers (RFC 8949 §4.2.1).
//!
//! `serde` emits struct/map fields in declaration/insertion order, while RFC
//! 8949 canonical CBOR requires map keys sorted by their encoded byte form. The
//! implementation serializes through `ciborium::value::Value`, recursively sorts
//! every map by the bytewise lexicographic order of each key's canonical CBOR
//! encoding, then writes the sorted value.
//!
//! **S0: the implementation moved to `tunnel_wire_rs::canonical`** so it sits
//! beside the sealed 0x17 body, whose `pub(crate)` byte accessors stopped
//! reaching this crate once the wire mechanics became their own crate. Canonical
//! CBOR is bytes on the wire and decides nothing, so it is mechanics by the S0
//! test. This module stays as the household-facing façade: the signatures and
//! the `HouseholdError` type are unchanged, and there is exactly ONE canonical
//! implementation in the workspace — a second one is how a validator bug hides.
//!
//! That no other caller moved is checkable rather than counted:
//!
//! ```text
//! git diff <base> -- household-rs/src/ | grep -E '^[-+].*cbor::(to_canonical_vec|from_canonical_slice)'
//! ```
//!
//! yields TWO removed lines and ZERO added, both in the 0x17 path that was
//! deliberately rewritten. An earlier revision of this comment cited a call-site
//! count instead; it was not reproducible, and the diff proves the same claim
//! without needing one. A cited count is a claim that needs its own instrument.

use serde::{Serialize, de::DeserializeOwned};
use tunnel_wire_rs::canonical;
use tunnel_wire_rs::tunnel_wire::WireError;

use crate::error::HouseholdError;

fn widen(error: WireError) -> HouseholdError {
    match error {
        WireError::Cbor(detail) => HouseholdError::Cbor(detail),
        other => HouseholdError::Cbor(other.to_string()),
    }
}

/// Encode a value as canonical CBOR bytes.
pub fn to_canonical_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, HouseholdError> {
    canonical::to_canonical_vec(value).map_err(widen)
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
    canonical::from_canonical_slice(bytes).map_err(widen)
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
    canonical::from_canonical_slice_strict(bytes).map_err(widen)
}
