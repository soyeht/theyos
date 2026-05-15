//! Household and Machine identifier derivation.
//!
//! ```text
//! hash_bytes  = BLAKE3-256(public_key_bytes)        ; 32 bytes
//! b32         = base32_lower_no_pad(hash_bytes)     ; 52 chars
//! hh_id       = "hh_" || b32                        ; 55 chars
//! m_id        = "m_"  || b32                        ; 54 chars
//! ```
//!
//! With the `hash-sha256-fallback` Cargo feature SHA-256 replaces BLAKE3.
//!
//! See `contracts/cbor-schemas.md` § "Hash convention".

use std::fmt;
use std::sync::OnceLock;

use data_encoding::Encoding;
use serde::{Deserialize, Serialize};

use crate::error::HouseholdError;
use crate::keys::P256PublicKey;

/// RFC 4648 base32 alphabet, lowercase, no padding. Constructed once and reused.
fn base32_lower_nopad() -> &'static Encoding {
    static ENC: OnceLock<Encoding> = OnceLock::new();
    ENC.get_or_init(|| {
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
        spec.encoding().expect("hardcoded base32 alphabet")
    })
}

/// Encode 32 bytes as 52-char lowercase base32 (no padding).
#[must_use]
pub fn base32_lower_nopad_encode(bytes: &[u8]) -> String {
    base32_lower_nopad().encode(bytes)
}

/// Decode 52-char lowercase base32 back into 32 bytes.
pub fn base32_lower_nopad_decode(s: &str) -> Result<Vec<u8>, HouseholdError> {
    base32_lower_nopad()
        .decode(s.as_bytes())
        .map_err(|e| HouseholdError::Base32(format!("{e}")))
}

/// Hash a public key per the household hash convention.
///
/// Uses BLAKE3-256 per Constitution Engineering Standards. The `hash-sha256-fallback`
/// feature flag was removed in PR #51 R7-A (Constitution Principle IV — no architectural
/// fence-sitting; SHA-256 fallback was dead code since BLAKE3 is universally available).
#[must_use]
pub fn hash_public_key(public_key_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(public_key_bytes).as_bytes()
}

/// Short, non-authoritative machine public-key hint for Bonjour TXT records.
///
/// This is `base32-lower-no-pad(BLAKE3-256(m_pub)[0..12])`, yielding 20
/// lowercase chars. It is only a discovery hint; the fetched `JoinRequest`
/// remains the authenticated source of truth.
#[must_use]
pub fn m_pub_short(m_pub: &[u8; 33]) -> String {
    let hash = hash_public_key(m_pub);
    base32_lower_nopad_encode(&hash[..12])
}

/// Identifier of a Household. Stable, public, `hh_` + 52-char base32.
///
/// Deserialization validates the prefix shape so that, when this type is
/// embedded in an `untagged` enum (see `SubjectId` in `machine_cert.rs`),
/// only well-formed `hh_…` strings select the [`SubjectId::Household`]
/// variant. Malformed strings cause variant search to fall through to the
/// next candidate instead of silently mismatching.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Debug)]
#[serde(transparent)]
pub struct HouseholdId(pub String);

impl<'de> Deserialize<'de> for HouseholdId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: String = String::deserialize(d)?;
        Self::parse(s).map_err(serde::de::Error::custom)
    }
}

impl HouseholdId {
    pub const PREFIX: &'static str = "hh_";

    /// Returns `true` if the string conforms to `^hh_[a-z2-7]{52}$`.
    #[must_use]
    pub fn is_well_formed(s: &str) -> bool {
        is_well_formed_id(s, Self::PREFIX)
    }

    /// Parse a string as a [`HouseholdId`], validating shape.
    pub fn parse(s: impl Into<String>) -> Result<Self, HouseholdError> {
        let s = s.into();
        if !Self::is_well_formed(&s) {
            return Err(HouseholdError::Identifier(format!(
                "expected hh_<52-char base32>, got {s:?}"
            )));
        }
        Ok(Self(s))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HouseholdId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identifier of a Machine. Stable, public, `m_` + 52-char base32.
///
/// See the rationale on [`HouseholdId`] for why deserialization validates
/// the prefix.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Debug)]
#[serde(transparent)]
pub struct MachineId(pub String);

impl<'de> Deserialize<'de> for MachineId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: String = String::deserialize(d)?;
        Self::parse(s).map_err(serde::de::Error::custom)
    }
}

impl MachineId {
    pub const PREFIX: &'static str = "m_";

    #[must_use]
    pub fn is_well_formed(s: &str) -> bool {
        is_well_formed_id(s, Self::PREFIX)
    }

    pub fn parse(s: impl Into<String>) -> Result<Self, HouseholdError> {
        let s = s.into();
        if !Self::is_well_formed(&s) {
            return Err(HouseholdError::Identifier(format!(
                "expected m_<52-char base32>, got {s:?}"
            )));
        }
        Ok(Self(s))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MachineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validation: prefix matches and the suffix is exactly 52 base32 lowercase
/// characters from the alphabet `abcdefghijklmnopqrstuvwxyz234567`.
fn is_well_formed_id(s: &str, prefix: &str) -> bool {
    let Some(rest) = s.strip_prefix(prefix) else {
        return false;
    };
    if rest.len() != 52 {
        return false;
    }
    rest.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

/// Derive a [`HouseholdId`] from a 33-byte SEC1 compressed P-256 public key.
#[must_use]
pub fn derive_household_id(hh_pub: &P256PublicKey) -> HouseholdId {
    let h = hash_public_key(hh_pub.as_bytes());
    HouseholdId(format!("hh_{}", base32_lower_nopad_encode(&h)))
}

/// Derive a [`MachineId`] from a 33-byte SEC1 compressed P-256 public key.
#[must_use]
pub fn derive_machine_id(m_pub: &P256PublicKey) -> MachineId {
    let h = hash_public_key(m_pub.as_bytes());
    MachineId(format!("m_{}", base32_lower_nopad_encode(&h)))
}

#[cfg(test)]
mod tests {
    use super::m_pub_short;

    #[test]
    fn m_pub_short_is_stable_20_char_base32_hint() {
        let mut m_pub = [0u8; 33];
        m_pub[0] = 0x02;
        let first = m_pub_short(&m_pub);
        let second = m_pub_short(&m_pub);
        assert_eq!(first, second);
        assert_eq!(first.len(), 20);
        assert!(
            first
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
        );

        let mut other = m_pub;
        other[32] = 1;
        assert_ne!(first, m_pub_short(&other));
    }
}
