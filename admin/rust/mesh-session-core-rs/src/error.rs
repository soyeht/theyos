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
    #[error("ceremony deadline exceeded before this I/O call could even be attempted")]
    DeadlineExceeded,
    #[error("failed to arm the per-call I/O deadline (e.g. setsockopt failure) — failing closed")]
    DeadlineArmingFailed,
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
    #[error(
        "ceremony deadline exceeded before/while verifying the delegation signature — a real verifier must respect the same deadline, never block past it"
    )]
    DeadlineExceeded,
    #[error(
        "delegation signature verifier unavailable (backend/roster I/O failed) — failing closed"
    )]
    VerifierUnavailable,
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
    #[error("OS RNG failed while minting a RekeyStateId")]
    RngFailure,
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
        "the ActivateAck exchange failed (cause: {source}); D1 pending-admission cancel outcome: {cancel_outcome:?} — the cause is why this attempt failed, the outcome is what happened to the reserved D1 permit as a result, never silently discarded"
    )]
    AckExchangeFailedWithCancelOutcome {
        #[source]
        source: Box<AuthFrameError>,
        cancel_outcome: crate::intent::D1CancelOutcome,
    },
    #[error(
        "K_mesh signer failed (revoked/stale/expired/backend unavailable) — no signature produced"
    )]
    SignerFailed,
    #[error("signer returned a byte string that does not parse as a valid P-256 signature")]
    InvalidSignatureScalar,
    #[error(
        "signer produced a signature that does not verify against its own preimage and public key"
    )]
    SignerProducedInvalidSignature,
    #[error("signer's own public key does not match local.delegation.delegated_pub")]
    SignerKeyMismatchDelegation,
    #[error(transparent)]
    Rekey(#[from] RekeyError),
    #[error(
        "delegation.roles does not exactly equal the roles this ceremony requires (no extras, duplicates, or omissions)"
    )]
    DelegationRolesMismatch,
    #[error(
        "delegation.transcript_kinds does not exactly equal the kinds this ceremony requires (no extras, duplicates, or omissions)"
    )]
    DelegationTranscriptKindsMismatch,
    #[error("delegation.channel does not match the channel this ceremony expects")]
    DelegationChannelMismatch,
    #[error(transparent)]
    Intent(#[from] IntentError),
}

/// Errors from `SignedMeshConnectionIntent` (0x06 carrier, D9 addendum
/// `kiana-d9-intent-carrier-b-addendum.c203463c…`). Deliberately separate
/// from `AuthFrameError`'s frame-shaped errors: `IntentRecord` is not an
/// `AuthFrameBody` and never goes through `sign_frame`/`verify_frame`.
#[derive(Debug, Error)]
pub enum IntentError {
    #[error(transparent)]
    Cbor(#[from] CborError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("intent's protocol_version/domain does not match the frozen literal")]
    VersionOrDomainMismatch,
    #[error("intent field does not match its fixed wire shape")]
    ShapeMismatch,
    #[error("intent record's type byte is not 0x06")]
    UnexpectedTypeByte(u8),
    #[error("intent signature does not verify")]
    BadSignature,
    #[error("intent signature is not low-S canonical")]
    HighSRejected,
    #[error("signer returned a byte string that does not parse as a valid P-256 signature")]
    InvalidSignatureScalar,
    #[error("K_mesh signer failed — no intent signature produced")]
    SignerFailed,
    #[error(
        "signer produced an intent signature that does not verify against its own preimage and public key"
    )]
    SignerProducedInvalidSignature,
    #[error("intent.delegated_key_id does not match Proof-I.delegation.delegated_key_id")]
    KeyIdMismatch,
    #[error("intent and Proof-I signatures do not resolve to the same delegated public key")]
    DelegatedKeyMismatch,
    #[error("Proof-I.connection_intent_digest does not match the received intent record")]
    DigestMismatch,
    #[error(
        "intent's household/initiator/target identity or fingerprint does not match Proof-I/local"
    )]
    IdentityMismatch,
    #[error(
        "intent.not_after is not within now..=delegation.not_after (expired, not yet valid, or exceeds the delegation's own window)"
    )]
    TtlInvalid,
    #[error("this intent's nonce has already been consumed")]
    NonceAlreadyConsumed,
    #[error(
        "nonce ledger commit outcome is ambiguous (may have taken effect) — treated as consumed, never as committed"
    )]
    NonceCommitAmbiguous,
    #[error("nonce ledger unavailable")]
    NonceLedgerUnavailable,
    #[error("no nonce ledger configured — fails closed until a real one is injected")]
    NoLedgerConfigured,
    #[error("intent's channel does not match the channel this ceremony expects")]
    ChannelMismatch,
    #[error("no D1 admission hook configured — fails closed until a real one is injected")]
    NoD1AdmissionConfigured,
    #[error(
        "no D4 retained-generation resolver configured — fails closed until a real one is injected"
    )]
    NoRetainedGenerationResolverConfigured,
    #[error(
        "D4-resolved generation's not_after does not match the delegation's own not_after — the resolver's record has drifted from what this delegation claims"
    )]
    ResolvedGenerationNotAfterMismatch,
    #[error("trusted clock unavailable — failing closed rather than assuming freshness")]
    ClockUnavailable,
    #[error("ceremony's absolute deadline has passed")]
    DeadlineExceeded,
    #[error(
        "D1 admission binding at activate time does not match the exact binding reserved (session_id/fingerprint/revision/channel) — a fresh read by m_id alone is not enough"
    )]
    D1BindingMismatch,
    #[error("signer's own public key does not match the key PendingIntent was built to bind")]
    SignerKeyMismatchPendingIntent,
    #[error(
        "PendingIntent's captured delegation binding (key bytes/serial/window) does not match the local delegation now in use"
    )]
    PendingIntentDelegationMismatch,
    #[error(
        "PendingIntent's own (signed) checkpoint_hash does not match the checkpoint this ceremony is about to present"
    )]
    PendingIntentCheckpointMismatch,
    #[error("intent record carries an empty hh_id/initiator_m_id/target_m_id/delegated_key_id")]
    EmptyIdentifier,
    /// 2026-08-05, @daisy, runtime-facade `D1Admission` adapter
    /// (`RegistryD1Admission`, `mesh-session-runtime-rs`): a real
    /// `reserve_pending` needs a current `RosterSnapshotView` to project a
    /// `D1MembershipKey` into a `SealedBinding` before it can even ask the
    /// registry to admit anything. Deliberately its OWN variant, never
    /// folded into [`Self::D1MembershipRejected`] (@zain, explicit): "the
    /// snapshot could not be acquired" and "the roster, once acquired,
    /// rejected this binding" are different failures with different
    /// remediation — the first is a local/IO condition the caller might
    /// retry, the second is a genuine admission decision.
    #[error("could not acquire a current roster snapshot for D1 admission")]
    RosterSnapshotUnavailable,
    /// 2026-08-05, @daisy, same adapter: the roster — whether checked by
    /// this adapter's own pre-check (`SealedBinding::from_membership_key`)
    /// or by the registry's own internal recheck against a possibly-more-
    /// advanced revision inside `try_preauthorize_before` — rejected this
    /// exact binding. One flat class covering every sub-reason (household
    /// mismatch, revision mismatch, revoked, not active, or a stale
    /// `D1MembershipKey` field), matching `MembershipKeyRejected`'s own
    /// "no variant, no field" discipline: this is the seam boundary, not a
    /// place to re-leak household-rs's internal refusal taxonomy across
    /// crates.
    #[error("D1 registry roster check rejected this membership binding")]
    D1MembershipRejected,
    /// 2026-08-05, @daisy, same adapter: the D1 registry itself is
    /// unavailable (its lock poisoned, or the tracked household's mode is
    /// no longer `Live`) — distinct from [`Self::D1MembershipRejected`]:
    /// this is an infrastructure failure with no binding-specific cause to
    /// report, matching [`Self::NonceLedgerUnavailable`]'s own shape one
    /// seam over.
    #[error("D1 registry unavailable")]
    D1RegistryUnavailable,
}

/// Errors from post-Active records (DATA/REVOKE_NOTICE/CLOSE/REKEY),
/// frozen by `kiana-bsessao-post-active-wire-addendum.b14fcf9520222ad3ab3ac3443ae4b0e7ba219411f41e3389751c92a402b64d8a.md`
/// (+ provenance-only erratum1 `4be4cd3d0963cbc145b4aeb1f5450e5753e84f1b65e94e84af9ecd29832bf203.md`),
/// both self-hash verified 2026-08-04. Deliberately separate from
/// [`AuthFrameError`]/[`IntentError`] — these records are neither
/// `AuthFrameBody` nor the 0x06 intent carrier, and never pass through
/// `sign_frame`/`verify_frame`/`sign_intent_record`.
#[derive(Debug, Error)]
pub enum PostActiveError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Cbor(#[from] CborError),
    #[error("post-Active plaintext is empty — no type byte present")]
    EmptyRecord,
    #[error("body length {declared} exceeds the maximum {max}")]
    OversizeBody { declared: u32, max: u32 },
    #[error("CLOSE/REVOKE_NOTICE body must be exactly empty (addendum §3.2/§3.3)")]
    NonEmptyControlBody,
    #[error("auth frame type byte {0:#04x} is not valid after Active")]
    UnexpectedAuthFrame(u8),
    #[error("0x06 intent record is not valid after Active")]
    UnexpectedIntentRecord,
    #[error("0x07 is reserved and unreachable")]
    ReservedTypeByte,
    #[error("unknown post-Active type byte {0:#04x}")]
    UnknownTypeByte(u8),
    #[error("session is already closed")]
    Closed,
    #[error("D1 forwarding authorization was not granted for this operation")]
    NotAuthorized,
    #[error("session has expired (now >= expires_at)")]
    Expired,
    #[error(transparent)]
    Rekey(#[from] RekeyError),
    #[error(transparent)]
    Noise(#[from] NoiseSetupError),
    #[error(
        "caller-provided receive buffer ({buffer_len}) is smaller than the delivered DATA payload ({payload_len})"
    )]
    ReceiveBufferTooSmall {
        buffer_len: usize,
        payload_len: usize,
    },
    #[error("peer sent CLOSE")]
    PeerClosed,
    #[error("peer sent REVOKE_NOTICE")]
    PeerRevoked,
    #[error(
        "REKEY may only be emitted by this crate to immediately precede CLOSE while in the terminal Closing substate"
    )]
    RekeyOnlyAllowedBeforeClose,
    /// 2026-08-04, @khai audit `d7e45e10…`: `send_data`/`receive_data` take
    /// a `Clock` and re-sample it fresh after the guard is acquired,
    /// exactly like the handshake's own `clock.now()` call sites — a
    /// clock failure is treated identically to an expired lease (fail
    /// closed, never assume freshness), but kept as its own variant so a
    /// caller can distinguish "no reliable time source" from "time is up".
    #[error(transparent)]
    Intent(#[from] IntentError),
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
