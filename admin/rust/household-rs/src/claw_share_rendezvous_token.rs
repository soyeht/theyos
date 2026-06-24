//! Shared rendezvous routing token for Product A `relay_stream`.
//!
//! C7c-2a moved this leaf type here so both the engine (server-rs) and the guest
//! (friend-cli) can use it. The relay splicer/table and the hello shape stay in
//! server-rs (`claw_share_rendezvous_stream_relay`) and re-export this type, so
//! their behavior is unchanged.
//!
//! The token is opaque metadata for pairing two relay connections, not an access
//! credential; its Debug/Display are intentionally redacted. Its serde form is
//! byte-for-byte identical to the previous server-rs definition (it serializes
//! as raw bytes via `serde_bytes`).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

pub const MIN_RENDEZVOUS_TOKEN_LEN: usize = 16;
pub const MAX_RENDEZVOUS_TOKEN_LEN: usize = 128;

/// Opaque rendezvous routing token.
///
/// The token is metadata for pairing two relay connections; it is not an access
/// credential. Its debug/display output is intentionally redacted.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RendezvousToken(Vec<u8>);

impl RendezvousToken {
    pub fn try_new(bytes: impl AsRef<[u8]>) -> Result<Self, RendezvousTokenError> {
        let bytes = bytes.as_ref();
        if bytes.is_empty() {
            return Err(RendezvousTokenError::Empty);
        }
        if bytes.len() < MIN_RENDEZVOUS_TOKEN_LEN {
            return Err(RendezvousTokenError::TooSmall {
                actual: bytes.len(),
                min: MIN_RENDEZVOUS_TOKEN_LEN,
            });
        }
        if bytes.len() > MAX_RENDEZVOUS_TOKEN_LEN {
            return Err(RendezvousTokenError::TooLarge {
                actual: bytes.len(),
                max: MAX_RENDEZVOUS_TOKEN_LEN,
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn redacted_label(&self) -> String {
        format!("rendezvous-token(len={}, redacted)", self.len())
    }
}

impl fmt::Debug for RendezvousToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted_label())
    }
}

impl fmt::Display for RendezvousToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted_label())
    }
}

impl Serialize for RendezvousToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(self.as_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RendezvousToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Self::try_new(bytes.as_slice()).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendezvousTokenError {
    Empty,
    TooSmall { actual: usize, min: usize },
    TooLarge { actual: usize, max: usize },
}

impl fmt::Display for RendezvousTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("rendezvous token is empty"),
            Self::TooSmall { actual, min } => {
                write!(f, "rendezvous token too small: {actual} < {min}")
            }
            Self::TooLarge { actual, max } => {
                write!(f, "rendezvous token too large: {actual} > {max}")
            }
        }
    }
}

impl std::error::Error for RendezvousTokenError {}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::cbor;

    #[test]
    fn rejects_out_of_bounds_lengths() {
        assert!(matches!(
            RendezvousToken::try_new([]),
            Err(RendezvousTokenError::Empty)
        ));
        assert!(matches!(
            RendezvousToken::try_new(vec![0x11; MIN_RENDEZVOUS_TOKEN_LEN - 1]),
            Err(RendezvousTokenError::TooSmall { .. })
        ));
        assert!(matches!(
            RendezvousToken::try_new(vec![0x11; MAX_RENDEZVOUS_TOKEN_LEN + 1]),
            Err(RendezvousTokenError::TooLarge { .. })
        ));
        assert!(RendezvousToken::try_new(vec![0x11; MIN_RENDEZVOUS_TOKEN_LEN]).is_ok());
    }

    #[test]
    fn serde_round_trips_as_raw_bytes() {
        let token = RendezvousToken::try_new(vec![0x42; 16]).unwrap();
        let bytes = cbor::to_canonical_vec(&token).unwrap();
        let decoded: RendezvousToken = cbor::from_canonical_slice(&bytes).unwrap();
        assert_eq!(decoded, token);
        assert_eq!(decoded.as_bytes(), token.as_bytes());
    }

    #[test]
    fn debug_and_display_redact_bytes() {
        let token = RendezvousToken::try_new(b"0123456789abcdef").unwrap();
        let debug = format!("{token:?}");
        let display = format!("{token}");
        assert!(debug.contains("redacted"));
        assert!(display.contains("redacted"));
        assert!(!debug.contains("0123456789abcdef"));
        assert!(!display.contains("0123456789abcdef"));
    }
}
