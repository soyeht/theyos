//! Shared error types for the mesh-session-core-rs crate.

use thiserror::Error;

/// Errors from the length-prefixed wire framing layer (item 1).
#[derive(Debug, Error)]
pub enum WireError {
    #[error("declared frame length {declared} exceeds the maximum {max}")]
    OversizeFrame { declared: u32, max: u32 },
    #[error("underlying I/O error reading a frame")]
    Io(#[from] std::io::Error),
    #[error("frame body is not a well-formed CBOR map")]
    Cbor(#[from] CborError),
    #[error("post-handshake frame body must not contain a \"type\" key")]
    TypeKeyInBody,
    #[error("unknown post-handshake type byte {0:#04x}")]
    UnknownTypeByte(u8),
}

/// Errors from the canonical-CBOR layer (item 1 support).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CborError {
    #[error("CBOR encode failed")]
    Encode,
    #[error("CBOR decode failed")]
    Decode,
    #[error("CBOR value is not the RFC 8949 canonical (deterministic) encoding")]
    NonCanonical,
    #[error("CBOR map contains a duplicate key")]
    DuplicateKey,
    #[error("CBOR value contains a null, which no B-SESSAO schema permits")]
    NullNotAllowed,
    #[error("trailing bytes after the first CBOR item")]
    TrailingBytes,
    #[error("CBOR map contains an unknown field for this schema")]
    UnknownField,
}

/// Errors from `MeshSessionDelegation` schema/policy handling (item 3a).
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum DelegationError {
    #[error("delegation is not canonical CBOR")]
    NonCanonical,
    #[error("delegation window is invalid: not_after must be strictly greater than not_before")]
    InvalidTtlWindow,
    #[error("delegation TTL {ttl} exceeds policy max_ttl {max_ttl}")]
    TtlExceedsPolicy { ttl: u64, max_ttl: u64 },
    #[error("delegation signature does not verify")]
    BadSignature,
    #[error("proof.hh_id does not match local.hh_id or delegation.hh_id")]
    HouseholdBindingMismatch,
    #[error("proof.self_m_id does not match delegation.delegator_m_id")]
    DelegatorBindingMismatch,
}

/// Errors from the rekey state machine (item 4).
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum RekeyError {
    #[error("rekey threshold must be nonzero")]
    InvalidRekeyPolicy,
    #[error("expected a rekey marker at this policy_count but got a non-marker record")]
    ExpectedRekeyMarker,
    #[error("received a rekey marker before the threshold was reached")]
    PrematureRekeyMarker,
    #[error(
        "rekey marker generation {got} does not follow the current generation (expected {expected})"
    )]
    WrongGeneration { expected: u64, got: u64 },
    #[error("generation counter exhausted")]
    GenerationExhausted,
}

/// Errors from Noise session-static setup (item 2).
#[derive(Debug, Error)]
pub enum NoiseSetupError {
    #[error("snow builder/handshake error")]
    Snow(#[from] snow::Error),
    #[error("handshake did not reach the finished state after 3 flights")]
    HandshakeNotFinished,
    #[error(transparent)]
    Wire(#[from] WireError),
}
