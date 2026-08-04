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
    #[error("CBOR tag major type is not used by any B-SESSAO schema")]
    TagNotAllowed,
    #[error("CBOR float major type is not used by any B-SESSAO schema")]
    FloatNotAllowed,
    #[error("CBOR map key is not a text string")]
    NonTextKey,
    #[error("CBOR value uses a shape no B-SESSAO schema recognizes")]
    DisallowedShape,
    #[error("expected exactly one top-level \"sig\" entry, found a different count")]
    MissingOrDuplicateSigField,
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
    #[error("delegation.version is not the frozen literal 1")]
    VersionMismatch,
    #[error("delegation.kind is not the frozen literal")]
    KindMismatch,
    #[error("delegation.domain is not the frozen literal")]
    DomainMismatch,
    #[error("delegation.profile is not the frozen literal")]
    ProfileMismatch,
    #[error("delegation.channel is not \"dev\" or \"release\"")]
    ChannelInvalid,
    #[error("delegation.delegated_pub is not a valid SEC1-compressed P-256 point")]
    InvalidDelegatedPubPoint,
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
    #[error(
        "permit was issued by a different DirectionalRekeyState, or its generation/policy_count snapshot no longer matches current state"
    )]
    StalePermit,
}

/// Errors from the 5 auth frame schemas / K_mesh signing (Fila 1 follow-on,
/// D9 Point2).
#[derive(Debug, Error)]
pub enum AuthFrameError {
    #[error(transparent)]
    Cbor(#[from] CborError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("field does not match its fixed wire shape")]
    ShapeMismatch,
    #[error("signature does not verify")]
    BadSignature,
    #[error("signature is not low-S canonical")]
    HighSRejected,
    #[error("frame's protocol_version/domain does not match the frozen literal")]
    VersionOrDomainMismatch,
    #[error("frame's role/kind does not match what this step of the handshake expects")]
    RoleOrKindMismatch,
    #[error("h_final does not match this session's own handshake hash")]
    HFinalMismatch,
    #[error("peer identity does not match ExpectedResponder")]
    ExpectedPeerMismatch,
    #[error("checkpoint_hash does not match the local live snapshot")]
    CheckpointMismatch,
    #[error(transparent)]
    Delegation(#[from] DelegationError),
    #[error(
        "delegation policy/signature/binding check failed before the frame signature was even checked"
    )]
    DelegationGate,
    #[error("frame_digest cross-reference does not match")]
    DigestMismatch,
    #[error(transparent)]
    Noise(#[from] NoiseSetupError),
    #[error("write of the final frame did not complete — no state transition occurred")]
    ActivateAckWriteFailed,
    #[error(
        "K_mesh signer failed (revoked/stale/expired/backend unavailable) — no signature produced"
    )]
    SignerFailed,
    #[error("signer returned a byte string that does not parse as a valid P-256 signature")]
    InvalidSignatureScalar,
}

/// Errors from Noise session-static setup (item 2).
#[derive(Debug, Error)]
pub enum NoiseSetupError {
    #[error("snow builder/handshake error")]
    Snow(#[from] snow::Error),
    #[error("handshake did not reach the finished state after 3 flights")]
    HandshakeNotFinished,
    #[error(
        "handshake flight carried a non-empty payload ({0} bytes) — v6 §1 requires payload empty"
    )]
    NonEmptyHandshakePayload(usize),
    #[error(transparent)]
    Wire(#[from] WireError),
}
