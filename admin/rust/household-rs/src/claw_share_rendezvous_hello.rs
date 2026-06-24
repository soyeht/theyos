//! Relay-visible rendezvous hello shape for Product A `relay_stream`.
//!
//! C7c-2c-2a moved this codec here, alongside the rendezvous token
//! ([`crate::claw_share_rendezvous_token`]), so the guest (friend-cli) can
//! encode the hello it sends to the relay without depending on the engine
//! crate. The relay-side splicer/table and the listener stay in server-rs and
//! re-export these types, so their behavior is unchanged. Only the leaf codec
//! moved.
//!
//! This is an internal testable shape, not a committed external wire protocol.

use std::fmt;

use crate::claw_share_rendezvous_token::{RendezvousToken, RendezvousTokenError};

pub const RENDEZVOUS_HELLO_VERSION: u8 = 1;

/// Relay-visible role for one side of a rendezvous stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RendezvousRole {
    Guest,
    Claw,
}

impl RendezvousRole {
    fn wire_value(self) -> u8 {
        match self {
            Self::Guest => 1,
            Self::Claw => 2,
        }
    }

    fn from_wire(value: u8) -> Result<Self, RendezvousHelloError> {
        match value {
            1 => Ok(Self::Guest),
            2 => Ok(Self::Claw),
            other => Err(RendezvousHelloError::InvalidRole(other)),
        }
    }
}

/// Minimal relay-visible hello. This is an internal testable shape, not a
/// committed external wire protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RendezvousHello {
    pub version: u8,
    pub role: RendezvousRole,
    pub token: RendezvousToken,
}

impl RendezvousHello {
    #[must_use]
    pub fn new(role: RendezvousRole, token: RendezvousToken) -> Self {
        Self {
            version: RENDEZVOUS_HELLO_VERSION,
            role,
            token,
        }
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.token.len());
        out.push(self.version);
        out.push(self.role.wire_value());
        let token_len = u16::try_from(self.token.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&token_len.to_be_bytes());
        out.extend_from_slice(self.token.as_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RendezvousHelloError> {
        if bytes.len() < 4 {
            return Err(RendezvousHelloError::Malformed("header-too-short"));
        }
        let version = bytes[0];
        if version != RENDEZVOUS_HELLO_VERSION {
            return Err(RendezvousHelloError::UnsupportedVersion(version));
        }
        let role = RendezvousRole::from_wire(bytes[1])?;
        let token_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let token_end = 4usize.saturating_add(token_len);
        if bytes.len() != token_end {
            return Err(RendezvousHelloError::Malformed("token-length-mismatch"));
        }
        let token = RendezvousToken::try_new(&bytes[4..token_end])
            .map_err(RendezvousHelloError::InvalidToken)?;
        Ok(Self {
            version,
            role,
            token,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendezvousHelloError {
    UnsupportedVersion(u8),
    InvalidRole(u8),
    InvalidToken(RendezvousTokenError),
    Malformed(&'static str),
}

impl fmt::Display for RendezvousHelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported rendezvous hello version: {version}")
            }
            Self::InvalidRole(role) => write!(f, "invalid rendezvous role: {role}"),
            Self::InvalidToken(error) => write!(f, "invalid rendezvous token: {error}"),
            Self::Malformed(reason) => write!(f, "malformed rendezvous hello: {reason}"),
        }
    }
}

impl std::error::Error for RendezvousHelloError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(label: u8) -> RendezvousToken {
        RendezvousToken::try_new(vec![label; 16]).unwrap()
    }

    #[test]
    fn rendezvous_stream_hello_round_trips_without_token_leak() {
        let token = token(0x42);
        let hello = RendezvousHello::new(RendezvousRole::Guest, token.clone());

        let decoded = RendezvousHello::decode(&hello.encode()).unwrap();

        assert_eq!(decoded.version, RENDEZVOUS_HELLO_VERSION);
        assert_eq!(decoded.role, RendezvousRole::Guest);
        assert_eq!(decoded.token, token);
        assert!(!format!("{decoded:?}").contains("4242424242424242"));
    }
}
