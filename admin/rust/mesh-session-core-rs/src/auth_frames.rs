//! The 5 auth frame schemas, B-SESSAO v6 §4, plus the D9 Point2 extension
//! (`zain-signed-mesh-connection-intent-v2.d013ac29…` §1, `connection_intent_digest`
//! added to Proof-I). Wire framing itself (length-prefix, type-byte/CBOR
//! split) is item 1 (`wire.rs`); this module owns the 5 concrete schemas,
//! the `signed_preimage`/`frame_digest` formulas v6 §3 freezes for them,
//! and K_mesh signing/verification.
//!
//! **Scope boundary:** only the frame *schemas* and their own signature/
//! digest mechanics. The full v6 §8 binding validator (which needs a live
//! roster, D-1) is not implemented — see `delegation.rs`'s module doc for
//! the same boundary applied here: verifying a frame's signature against
//! its *own embedded* `delegated_pub` proves internal self-consistency
//! ("whoever holds this key produced this frame"), never that the key is
//! legitimately authorized (that needs D-1's roster) — self-consistency
//! does not authorize; `auth_state_machine` gates the delegation (policy +
//! injected signature verifier + partial binding) before this key is ever
//! trusted for anything. D9 Point 1 (`SignedMeshConnectionIntent`/
//! `Capability`, `ExpectedResponder` construction *from* an intent, the
//! nonce ledger, capability revocation) is explicitly out of scope —
//! `connection_intent_digest` is carried here as an opaque, typed 32-byte
//! field, never computed or checked against anything.
//!
//! **Hardened 2026-08-04, @kiana, pre-freeze review of this same
//! generation:**
//! - Each frame type now has a private-field public struct + a
//!   `pub(crate)` wire shadow + `TryFrom`-validated construction, exactly
//!   the `delegation.rs` pattern: `protocol_version`/`domain`/`role`/`kind`
//!   literals and every fixed-size `bstr` field are checked on *every*
//!   construction path (including embedded-field deserialization), not
//!   just by whichever caller happens to remember to check them.
//! - Signing/verification no longer take a raw `&[u8]` preimage or an
//!   externally-suppliable `type_byte`. [`MeshSessionFramePreimage`] is an
//!   opaque token buildable only by this crate (`pub(crate)` constructor),
//!   only from one of the 5 real, already-validated frame types (via the
//!   sealed [`AuthFrameBody`] trait, which fixes `TYPE_BYTE` to the type
//!   itself — a caller cannot pick an arbitrary type byte for an arbitrary
//!   struct). A `MeshSessionFrameSigner` can therefore never be asked to
//!   sign attacker-chosen bytes; it can only sign a preimage this crate
//!   itself derived from a real frame.
//!
//! Several items here (`sign_frame`/`verify_frame`/`frame_digest`/the
//! `new`/`with_sig` constructors) are `pub(crate)`, called only by
//! `auth_state_machine` — which is itself `pub(crate)` pending a real
//! D-1/D-9 admission authority. A plain (non-test) build therefore has no
//! production caller for them yet; `#![allow(dead_code)]` reflects that as
//! the expected, intentional current state. `cargo test` exercises all of
//! it via `auth_state_machine`'s test suite and this module's own.
#![allow(dead_code)]

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cbor;
use crate::delegation::MeshSessionDelegation;
use crate::error::AuthFrameError;
use crate::ingress::CeremonyDeadline;

pub const TYPE_PROOF_R: u8 = 0x01;
pub const TYPE_PROOF_I: u8 = 0x02;
pub const TYPE_FINAL_CONFIRM: u8 = 0x03;
pub const TYPE_ACTIVATE: u8 = 0x04;
pub const TYPE_ACTIVATE_ACK: u8 = 0x05;

pub const PROTOCOL_VERSION: u64 = 1;
pub const DOMAIN: &str = "soyeht/mesh-session/v1";
pub const ROLE_RESPONDER: &str = "responder";
pub const ROLE_INITIATOR: &str = "initiator";
pub const KIND_FINAL_CONFIRM: &str = "final-confirm";
pub const KIND_ACTIVATE: &str = "activate";
pub const KIND_ACTIVATE_ACK: &str = "activate-ack";

fn check_header(protocol_version: u64, domain: &str) -> Result<(), AuthFrameError> {
    if protocol_version != PROTOCOL_VERSION || domain != DOMAIN {
        return Err(AuthFrameError::VersionOrDomainMismatch);
    }
    Ok(())
}

fn check_len(bytes: &[u8], expected: usize) -> Result<(), AuthFrameError> {
    if bytes.len() != expected {
        return Err(AuthFrameError::ShapeMismatch);
    }
    Ok(())
}

/// Constructed by the initiator, before the first Noise byte, from an
/// authenticated source (v6 §1 — D-9, not this crate's concern how). Not a
/// wire type; never serialized.
///
/// **`pub(crate)` on purpose (2026-08-04, @kiana):** D-1/D-9 will define
/// the real, sealed `ExpectedResponder`-equivalent authority once a live
/// roster is available. This shape exists only so `auth_state_machine`'s
/// own tests can exercise the initiator path with real crypto — shipping
/// it as a public, freely-constructible struct would risk it becoming a
/// second, competing "ExpectedResponder" that a future integration might
/// reach for instead of the real, roster-backed one. When that
/// integration lands, it converts *into* whatever shape the state machine
/// actually needs (which may not even be this one) — this type is not the
/// production authority and must not be exported as though it were.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedResponder {
    pub(crate) hh_id: String,
    pub(crate) m_id: String,
    pub(crate) cert_fingerprint: [u8; 32],
}

/// D9 Point2 (`zain…d013ac29` §1): the digest of a `SignedMeshConnectionIntent`
/// (Point 1, now implemented in [`crate::intent`] — D9 carrier-B addendum).
/// Carried here as an opaque, fixed-size, *typed* field — never a bare
/// `[u8; 32]` that could be confused with `h_final` or a cert fingerprint.
///
/// **`from_bytes` is `pub(crate)` (2026-08-04, @kiana, integration
/// addendum):** a raw, freely-constructible `ConnectionIntentDigest` must
/// never be able to substitute for one genuinely derived from a validated,
/// signed intent — "raw digest/bare ids não iniciam handshake". The only
/// production path to a value of this type is `intent::intent_digest`
/// (via `run_initiator_handshake`, which derives it internally from the
/// same `PendingIntent` it sends as the 0x06 record) or the combined
/// check reading one back off the wire; `from_bytes` remains only for
/// this crate's own tests to build fixtures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionIntentDigest([u8; 32]);

impl ConnectionIntentDigest {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for ConnectionIntentDigest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(&self.0).serialize(s)
    }
}

impl<'de> Deserialize<'de> for ConnectionIntentDigest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let buf = serde_bytes::ByteBuf::deserialize(d)?;
        let arr: [u8; 32] = buf.into_vec().try_into().map_err(|_| {
            serde::de::Error::custom("connection_intent_digest must be exactly 32 bytes")
        })?;
        Ok(Self(arr))
    }
}

/// Sealed — only this module may implement it, only for the 5 real frame
/// types, each fixing its own `TYPE_BYTE`. This is what makes
/// [`MeshSessionFramePreimage::for_frame`] safe to be the *only* way to
/// build a signable preimage: a caller can never pair an arbitrary type
/// byte with an arbitrary struct.
mod sealed {
    pub trait Sealed {}
}

pub trait AuthFrameBody: sealed::Sealed + Serialize {
    const TYPE_BYTE: u8;
}

/// An opaque, unforgeable signing/verification preimage. The only
/// constructor is `pub(crate)` and only accepts a value of one of the 5
/// sealed [`AuthFrameBody`] types — a caller holding a
/// `MeshSessionFrameSigner` cannot ask it to sign attacker-chosen bytes or
/// an arbitrary (type_byte, struct) pairing; it can only ever be handed a
/// preimage this crate itself derived from a real, already-validated
/// frame.
pub struct MeshSessionFramePreimage(Vec<u8>);

impl MeshSessionFramePreimage {
    /// v6 §3: `signed_preimage = type_byte || canonical_cbor(unsigned_body)`.
    pub(crate) fn for_frame<F: AuthFrameBody>(frame: &F) -> Result<Self, AuthFrameError> {
        let unsigned = cbor::unsigned_preimage_body(frame)?;
        let mut out = Vec::with_capacity(1 + unsigned.len());
        out.push(F::TYPE_BYTE);
        out.extend(unsigned);
        Ok(Self(out))
    }

    /// Public read access to the bytes to sign/verify — needed by a real
    /// (external, future) `MeshSessionFrameSigner`/`Verifier`
    /// implementation, which must exist outside this crate to reach real
    /// key custody. Construction stays `pub(crate)`; reading an
    /// already-legitimately-constructed token does not weaken that.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn digest_for_frame<F: AuthFrameBody>(frame: &F) -> Result<[u8; 32], AuthFrameError> {
    use sha2::{Digest, Sha256};
    let full = cbor::to_canonical_vec(frame)?;
    let mut hasher = Sha256::new();
    hasher.update([F::TYPE_BYTE]);
    hasher.update(&full);
    Ok(hasher.finalize().into())
}

/// v6 §4.1, type byte `0x01`, R→I.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProofRWire {
    pub(crate) protocol_version: u64,
    pub(crate) domain: String,
    pub(crate) role: String,
    #[serde(with = "serde_bytes")]
    pub(crate) h_final: Vec<u8>,
    pub(crate) hh_id: String,
    pub(crate) self_m_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) self_cert_fingerprint: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) checkpoint_hash: Vec<u8>,
    pub(crate) checkpoint_sequence: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) checkpoint_event_head: Vec<u8>,
    pub(crate) checkpoint_not_after: u64,
    pub(crate) delegation: MeshSessionDelegation,
    #[serde(with = "serde_bytes")]
    pub(crate) sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ProofRWire", into = "ProofRWire")]
pub struct ProofR {
    protocol_version: u64,
    domain: String,
    role: String,
    h_final: Vec<u8>,
    hh_id: String,
    self_m_id: String,
    self_cert_fingerprint: Vec<u8>,
    checkpoint_hash: Vec<u8>,
    checkpoint_sequence: u64,
    checkpoint_event_head: Vec<u8>,
    checkpoint_not_after: u64,
    delegation: MeshSessionDelegation,
    sig: Vec<u8>,
}

impl sealed::Sealed for ProofR {}
impl AuthFrameBody for ProofR {
    const TYPE_BYTE: u8 = TYPE_PROOF_R;
}

impl TryFrom<ProofRWire> for ProofR {
    type Error = AuthFrameError;
    fn try_from(w: ProofRWire) -> Result<Self, AuthFrameError> {
        check_header(w.protocol_version, &w.domain)?;
        if w.role != ROLE_RESPONDER {
            return Err(AuthFrameError::RoleOrKindMismatch);
        }
        check_len(&w.h_final, 32)?;
        check_len(&w.self_cert_fingerprint, 32)?;
        check_len(&w.checkpoint_hash, 32)?;
        check_len(&w.checkpoint_event_head, 32)?;
        check_len(&w.sig, 64)?;
        Ok(Self {
            protocol_version: w.protocol_version,
            domain: w.domain,
            role: w.role,
            h_final: w.h_final,
            hh_id: w.hh_id,
            self_m_id: w.self_m_id,
            self_cert_fingerprint: w.self_cert_fingerprint,
            checkpoint_hash: w.checkpoint_hash,
            checkpoint_sequence: w.checkpoint_sequence,
            checkpoint_event_head: w.checkpoint_event_head,
            checkpoint_not_after: w.checkpoint_not_after,
            delegation: w.delegation,
            sig: w.sig,
        })
    }
}
impl From<ProofR> for ProofRWire {
    fn from(f: ProofR) -> Self {
        ProofRWire {
            protocol_version: f.protocol_version,
            domain: f.domain,
            role: f.role,
            h_final: f.h_final,
            hh_id: f.hh_id,
            self_m_id: f.self_m_id,
            self_cert_fingerprint: f.self_cert_fingerprint,
            checkpoint_hash: f.checkpoint_hash,
            checkpoint_sequence: f.checkpoint_sequence,
            checkpoint_event_head: f.checkpoint_event_head,
            checkpoint_not_after: f.checkpoint_not_after,
            delegation: f.delegation,
            sig: f.sig,
        }
    }
}

impl ProofR {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        h_final: Vec<u8>,
        hh_id: String,
        self_m_id: String,
        self_cert_fingerprint: Vec<u8>,
        checkpoint_hash: Vec<u8>,
        checkpoint_sequence: u64,
        checkpoint_event_head: Vec<u8>,
        checkpoint_not_after: u64,
        delegation: MeshSessionDelegation,
        sig: Vec<u8>,
    ) -> Result<Self, AuthFrameError> {
        ProofRWire {
            protocol_version: PROTOCOL_VERSION,
            domain: DOMAIN.to_string(),
            role: ROLE_RESPONDER.to_string(),
            h_final,
            hh_id,
            self_m_id,
            self_cert_fingerprint,
            checkpoint_hash,
            checkpoint_sequence,
            checkpoint_event_head,
            checkpoint_not_after,
            delegation,
            sig,
        }
        .try_into()
    }
    pub fn h_final(&self) -> &[u8] {
        &self.h_final
    }
    pub fn hh_id(&self) -> &str {
        &self.hh_id
    }
    pub fn self_m_id(&self) -> &str {
        &self.self_m_id
    }
    pub fn self_cert_fingerprint(&self) -> &[u8] {
        &self.self_cert_fingerprint
    }
    pub fn checkpoint_hash(&self) -> &[u8] {
        &self.checkpoint_hash
    }
    pub fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }
    pub fn checkpoint_event_head(&self) -> &[u8] {
        &self.checkpoint_event_head
    }
    pub fn checkpoint_not_after(&self) -> u64 {
        self.checkpoint_not_after
    }
    pub fn delegation(&self) -> &MeshSessionDelegation {
        &self.delegation
    }
    pub fn sig(&self) -> &[u8] {
        &self.sig
    }
    pub(crate) fn with_sig(mut self, sig: Vec<u8>) -> Self {
        self.sig = sig;
        self
    }
}

/// v6 §4.2, type byte `0x02`, I→R. `connection_intent_digest` is the D9
/// Point2 extension (`zain…d013ac29` §1) — mandatory, typed, opaque here.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProofIWire {
    pub(crate) protocol_version: u64,
    pub(crate) domain: String,
    pub(crate) role: String,
    #[serde(with = "serde_bytes")]
    pub(crate) h_final: Vec<u8>,
    pub(crate) hh_id: String,
    pub(crate) self_m_id: String,
    pub(crate) expected_peer_m_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) self_cert_fingerprint: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) expected_peer_cert_fingerprint: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) checkpoint_hash: Vec<u8>,
    pub(crate) checkpoint_sequence: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) checkpoint_event_head: Vec<u8>,
    pub(crate) checkpoint_not_after: u64,
    pub(crate) delegation: MeshSessionDelegation,
    pub(crate) connection_intent_digest: ConnectionIntentDigest,
    #[serde(with = "serde_bytes")]
    pub(crate) sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ProofIWire", into = "ProofIWire")]
pub struct ProofI {
    protocol_version: u64,
    domain: String,
    role: String,
    h_final: Vec<u8>,
    hh_id: String,
    self_m_id: String,
    expected_peer_m_id: String,
    self_cert_fingerprint: Vec<u8>,
    expected_peer_cert_fingerprint: Vec<u8>,
    checkpoint_hash: Vec<u8>,
    checkpoint_sequence: u64,
    checkpoint_event_head: Vec<u8>,
    checkpoint_not_after: u64,
    delegation: MeshSessionDelegation,
    connection_intent_digest: ConnectionIntentDigest,
    sig: Vec<u8>,
}

impl sealed::Sealed for ProofI {}
impl AuthFrameBody for ProofI {
    const TYPE_BYTE: u8 = TYPE_PROOF_I;
}

impl TryFrom<ProofIWire> for ProofI {
    type Error = AuthFrameError;
    fn try_from(w: ProofIWire) -> Result<Self, AuthFrameError> {
        check_header(w.protocol_version, &w.domain)?;
        if w.role != ROLE_INITIATOR {
            return Err(AuthFrameError::RoleOrKindMismatch);
        }
        check_len(&w.h_final, 32)?;
        check_len(&w.self_cert_fingerprint, 32)?;
        check_len(&w.expected_peer_cert_fingerprint, 32)?;
        check_len(&w.checkpoint_hash, 32)?;
        check_len(&w.checkpoint_event_head, 32)?;
        check_len(&w.sig, 64)?;
        Ok(Self {
            protocol_version: w.protocol_version,
            domain: w.domain,
            role: w.role,
            h_final: w.h_final,
            hh_id: w.hh_id,
            self_m_id: w.self_m_id,
            expected_peer_m_id: w.expected_peer_m_id,
            self_cert_fingerprint: w.self_cert_fingerprint,
            expected_peer_cert_fingerprint: w.expected_peer_cert_fingerprint,
            checkpoint_hash: w.checkpoint_hash,
            checkpoint_sequence: w.checkpoint_sequence,
            checkpoint_event_head: w.checkpoint_event_head,
            checkpoint_not_after: w.checkpoint_not_after,
            delegation: w.delegation,
            connection_intent_digest: w.connection_intent_digest,
            sig: w.sig,
        })
    }
}
impl From<ProofI> for ProofIWire {
    fn from(f: ProofI) -> Self {
        ProofIWire {
            protocol_version: f.protocol_version,
            domain: f.domain,
            role: f.role,
            h_final: f.h_final,
            hh_id: f.hh_id,
            self_m_id: f.self_m_id,
            expected_peer_m_id: f.expected_peer_m_id,
            self_cert_fingerprint: f.self_cert_fingerprint,
            expected_peer_cert_fingerprint: f.expected_peer_cert_fingerprint,
            checkpoint_hash: f.checkpoint_hash,
            checkpoint_sequence: f.checkpoint_sequence,
            checkpoint_event_head: f.checkpoint_event_head,
            checkpoint_not_after: f.checkpoint_not_after,
            delegation: f.delegation,
            connection_intent_digest: f.connection_intent_digest,
            sig: f.sig,
        }
    }
}

impl ProofI {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        h_final: Vec<u8>,
        hh_id: String,
        self_m_id: String,
        expected_peer_m_id: String,
        self_cert_fingerprint: Vec<u8>,
        expected_peer_cert_fingerprint: Vec<u8>,
        checkpoint_hash: Vec<u8>,
        checkpoint_sequence: u64,
        checkpoint_event_head: Vec<u8>,
        checkpoint_not_after: u64,
        delegation: MeshSessionDelegation,
        connection_intent_digest: ConnectionIntentDigest,
        sig: Vec<u8>,
    ) -> Result<Self, AuthFrameError> {
        ProofIWire {
            protocol_version: PROTOCOL_VERSION,
            domain: DOMAIN.to_string(),
            role: ROLE_INITIATOR.to_string(),
            h_final,
            hh_id,
            self_m_id,
            expected_peer_m_id,
            self_cert_fingerprint,
            expected_peer_cert_fingerprint,
            checkpoint_hash,
            checkpoint_sequence,
            checkpoint_event_head,
            checkpoint_not_after,
            delegation,
            connection_intent_digest,
            sig,
        }
        .try_into()
    }
    pub fn h_final(&self) -> &[u8] {
        &self.h_final
    }
    pub fn hh_id(&self) -> &str {
        &self.hh_id
    }
    pub fn self_m_id(&self) -> &str {
        &self.self_m_id
    }
    pub fn self_cert_fingerprint(&self) -> &[u8] {
        &self.self_cert_fingerprint
    }
    /// Who the initiator itself intended to reach — 2026-08-04, @kiana:
    /// the responder must compare this (and
    /// [`Self::expected_peer_cert_fingerprint`]) against its own identity
    /// before accepting this frame. Without that check, a validly-signed
    /// Proof-I addressed to a *different* machine (R2) would be silently
    /// accepted by whichever machine (R1) it actually arrived at.
    pub fn expected_peer_m_id(&self) -> &str {
        &self.expected_peer_m_id
    }
    pub fn expected_peer_cert_fingerprint(&self) -> &[u8] {
        &self.expected_peer_cert_fingerprint
    }
    pub fn checkpoint_hash(&self) -> &[u8] {
        &self.checkpoint_hash
    }
    pub fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }
    pub fn checkpoint_event_head(&self) -> &[u8] {
        &self.checkpoint_event_head
    }
    pub fn checkpoint_not_after(&self) -> u64 {
        self.checkpoint_not_after
    }
    pub fn delegation(&self) -> &MeshSessionDelegation {
        &self.delegation
    }
    /// D9 Point2/carrier-B: the responder's combined intent check compares
    /// this against `intent::intent_digest` of the received 0x06 record
    /// (addendum §4 item 5) — before this accessor existed, the field was
    /// carried but never read back out anywhere.
    pub fn connection_intent_digest(&self) -> &ConnectionIntentDigest {
        &self.connection_intent_digest
    }
    pub fn sig(&self) -> &[u8] {
        &self.sig
    }
    pub(crate) fn with_sig(mut self, sig: Vec<u8>) -> Self {
        self.sig = sig;
        self
    }
}

/// v6 §4.3, type byte `0x03`, R→I.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalConfirmWire {
    pub(crate) protocol_version: u64,
    pub(crate) domain: String,
    pub(crate) kind: String,
    #[serde(with = "serde_bytes")]
    pub(crate) h_final: Vec<u8>,
    pub(crate) initiator_m_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) initiator_cert_fingerprint: Vec<u8>,
    pub(crate) responder_m_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "FinalConfirmWire", into = "FinalConfirmWire")]
pub struct FinalConfirm {
    protocol_version: u64,
    domain: String,
    kind: String,
    h_final: Vec<u8>,
    initiator_m_id: String,
    initiator_cert_fingerprint: Vec<u8>,
    responder_m_id: String,
    sig: Vec<u8>,
}

impl sealed::Sealed for FinalConfirm {}
impl AuthFrameBody for FinalConfirm {
    const TYPE_BYTE: u8 = TYPE_FINAL_CONFIRM;
}

impl TryFrom<FinalConfirmWire> for FinalConfirm {
    type Error = AuthFrameError;
    fn try_from(w: FinalConfirmWire) -> Result<Self, AuthFrameError> {
        check_header(w.protocol_version, &w.domain)?;
        if w.kind != KIND_FINAL_CONFIRM {
            return Err(AuthFrameError::RoleOrKindMismatch);
        }
        check_len(&w.h_final, 32)?;
        check_len(&w.initiator_cert_fingerprint, 32)?;
        check_len(&w.sig, 64)?;
        Ok(Self {
            protocol_version: w.protocol_version,
            domain: w.domain,
            kind: w.kind,
            h_final: w.h_final,
            initiator_m_id: w.initiator_m_id,
            initiator_cert_fingerprint: w.initiator_cert_fingerprint,
            responder_m_id: w.responder_m_id,
            sig: w.sig,
        })
    }
}
impl From<FinalConfirm> for FinalConfirmWire {
    fn from(f: FinalConfirm) -> Self {
        FinalConfirmWire {
            protocol_version: f.protocol_version,
            domain: f.domain,
            kind: f.kind,
            h_final: f.h_final,
            initiator_m_id: f.initiator_m_id,
            initiator_cert_fingerprint: f.initiator_cert_fingerprint,
            responder_m_id: f.responder_m_id,
            sig: f.sig,
        }
    }
}

impl FinalConfirm {
    pub(crate) fn new(
        h_final: Vec<u8>,
        initiator_m_id: String,
        initiator_cert_fingerprint: Vec<u8>,
        responder_m_id: String,
        sig: Vec<u8>,
    ) -> Result<Self, AuthFrameError> {
        FinalConfirmWire {
            protocol_version: PROTOCOL_VERSION,
            domain: DOMAIN.to_string(),
            kind: KIND_FINAL_CONFIRM.to_string(),
            h_final,
            initiator_m_id,
            initiator_cert_fingerprint,
            responder_m_id,
            sig,
        }
        .try_into()
    }
    pub fn h_final(&self) -> &[u8] {
        &self.h_final
    }
    pub fn initiator_m_id(&self) -> &str {
        &self.initiator_m_id
    }
    pub fn initiator_cert_fingerprint(&self) -> &[u8] {
        &self.initiator_cert_fingerprint
    }
    pub fn responder_m_id(&self) -> &str {
        &self.responder_m_id
    }
    pub fn sig(&self) -> &[u8] {
        &self.sig
    }
    pub(crate) fn with_sig(mut self, sig: Vec<u8>) -> Self {
        self.sig = sig;
        self
    }
}

/// v6 §4.4, type byte `0x04`, I→R. `final_confirm_digest` =
/// `frame_digest(0x03, FinalConfirm full including sig)`.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivateWire {
    pub(crate) protocol_version: u64,
    pub(crate) domain: String,
    pub(crate) kind: String,
    #[serde(with = "serde_bytes")]
    pub(crate) h_final: Vec<u8>,
    pub(crate) responder_m_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) final_confirm_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ActivateWire", into = "ActivateWire")]
pub struct Activate {
    protocol_version: u64,
    domain: String,
    kind: String,
    h_final: Vec<u8>,
    responder_m_id: String,
    final_confirm_digest: Vec<u8>,
    sig: Vec<u8>,
}

impl sealed::Sealed for Activate {}
impl AuthFrameBody for Activate {
    const TYPE_BYTE: u8 = TYPE_ACTIVATE;
}

impl TryFrom<ActivateWire> for Activate {
    type Error = AuthFrameError;
    fn try_from(w: ActivateWire) -> Result<Self, AuthFrameError> {
        check_header(w.protocol_version, &w.domain)?;
        if w.kind != KIND_ACTIVATE {
            return Err(AuthFrameError::RoleOrKindMismatch);
        }
        check_len(&w.h_final, 32)?;
        check_len(&w.final_confirm_digest, 32)?;
        check_len(&w.sig, 64)?;
        Ok(Self {
            protocol_version: w.protocol_version,
            domain: w.domain,
            kind: w.kind,
            h_final: w.h_final,
            responder_m_id: w.responder_m_id,
            final_confirm_digest: w.final_confirm_digest,
            sig: w.sig,
        })
    }
}
impl From<Activate> for ActivateWire {
    fn from(f: Activate) -> Self {
        ActivateWire {
            protocol_version: f.protocol_version,
            domain: f.domain,
            kind: f.kind,
            h_final: f.h_final,
            responder_m_id: f.responder_m_id,
            final_confirm_digest: f.final_confirm_digest,
            sig: f.sig,
        }
    }
}

impl Activate {
    pub(crate) fn new(
        h_final: Vec<u8>,
        responder_m_id: String,
        final_confirm_digest: Vec<u8>,
        sig: Vec<u8>,
    ) -> Result<Self, AuthFrameError> {
        ActivateWire {
            protocol_version: PROTOCOL_VERSION,
            domain: DOMAIN.to_string(),
            kind: KIND_ACTIVATE.to_string(),
            h_final,
            responder_m_id,
            final_confirm_digest,
            sig,
        }
        .try_into()
    }
    pub fn h_final(&self) -> &[u8] {
        &self.h_final
    }
    pub fn responder_m_id(&self) -> &str {
        &self.responder_m_id
    }
    pub fn final_confirm_digest(&self) -> &[u8] {
        &self.final_confirm_digest
    }
    pub fn sig(&self) -> &[u8] {
        &self.sig
    }
    pub(crate) fn with_sig(mut self, sig: Vec<u8>) -> Self {
        self.sig = sig;
        self
    }
}

/// v6 §4.5, type byte `0x05`, R→I. `activate_digest` =
/// `frame_digest(0x04, Activate full including sig)`.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivateAckWire {
    pub(crate) protocol_version: u64,
    pub(crate) domain: String,
    pub(crate) kind: String,
    #[serde(with = "serde_bytes")]
    pub(crate) h_final: Vec<u8>,
    pub(crate) responder_m_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) activate_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ActivateAckWire", into = "ActivateAckWire")]
pub struct ActivateAck {
    protocol_version: u64,
    domain: String,
    kind: String,
    h_final: Vec<u8>,
    responder_m_id: String,
    activate_digest: Vec<u8>,
    sig: Vec<u8>,
}

impl sealed::Sealed for ActivateAck {}
impl AuthFrameBody for ActivateAck {
    const TYPE_BYTE: u8 = TYPE_ACTIVATE_ACK;
}

impl TryFrom<ActivateAckWire> for ActivateAck {
    type Error = AuthFrameError;
    fn try_from(w: ActivateAckWire) -> Result<Self, AuthFrameError> {
        check_header(w.protocol_version, &w.domain)?;
        if w.kind != KIND_ACTIVATE_ACK {
            return Err(AuthFrameError::RoleOrKindMismatch);
        }
        check_len(&w.h_final, 32)?;
        check_len(&w.activate_digest, 32)?;
        check_len(&w.sig, 64)?;
        Ok(Self {
            protocol_version: w.protocol_version,
            domain: w.domain,
            kind: w.kind,
            h_final: w.h_final,
            responder_m_id: w.responder_m_id,
            activate_digest: w.activate_digest,
            sig: w.sig,
        })
    }
}
impl From<ActivateAck> for ActivateAckWire {
    fn from(f: ActivateAck) -> Self {
        ActivateAckWire {
            protocol_version: f.protocol_version,
            domain: f.domain,
            kind: f.kind,
            h_final: f.h_final,
            responder_m_id: f.responder_m_id,
            activate_digest: f.activate_digest,
            sig: f.sig,
        }
    }
}

impl ActivateAck {
    pub(crate) fn new(
        h_final: Vec<u8>,
        responder_m_id: String,
        activate_digest: Vec<u8>,
        sig: Vec<u8>,
    ) -> Result<Self, AuthFrameError> {
        ActivateAckWire {
            protocol_version: PROTOCOL_VERSION,
            domain: DOMAIN.to_string(),
            kind: KIND_ACTIVATE_ACK.to_string(),
            h_final,
            responder_m_id,
            activate_digest,
            sig,
        }
        .try_into()
    }
    pub fn h_final(&self) -> &[u8] {
        &self.h_final
    }
    pub fn responder_m_id(&self) -> &str {
        &self.responder_m_id
    }
    pub fn activate_digest(&self) -> &[u8] {
        &self.activate_digest
    }
    pub fn sig(&self) -> &[u8] {
        &self.sig
    }
    pub(crate) fn with_sig(mut self, sig: Vec<u8>) -> Self {
        self.sig = sig;
        self
    }
}

/// Closed over exactly the 5 known type bytes — the public decode surface
/// (`decode_auth_frame`) returns this, never a raw `(type_byte, body)`
/// tuple a caller could mishandle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthFrame {
    ProofR(ProofR),
    ProofI(ProofI),
    FinalConfirm(FinalConfirm),
    Activate(Activate),
    ActivateAck(ActivateAck),
}

pub fn encode_auth_frame(frame: &AuthFrame) -> Result<Vec<u8>, AuthFrameError> {
    let (type_byte, body_cbor) = match frame {
        AuthFrame::ProofR(f) => (TYPE_PROOF_R, cbor::to_canonical_vec(f)?),
        AuthFrame::ProofI(f) => (TYPE_PROOF_I, cbor::to_canonical_vec(f)?),
        AuthFrame::FinalConfirm(f) => (TYPE_FINAL_CONFIRM, cbor::to_canonical_vec(f)?),
        AuthFrame::Activate(f) => (TYPE_ACTIVATE, cbor::to_canonical_vec(f)?),
        AuthFrame::ActivateAck(f) => (TYPE_ACTIVATE_ACK, cbor::to_canonical_vec(f)?),
    };
    Ok(crate::wire::encode_typed_frame(type_byte, &body_cbor)?)
}

pub fn decode_auth_frame(plaintext: &[u8]) -> Result<AuthFrame, AuthFrameError> {
    let (type_byte, body) = crate::wire::decode_typed_frame(plaintext)?;
    match type_byte {
        TYPE_PROOF_R => Ok(AuthFrame::ProofR(cbor::from_canonical_bytes(body)?)),
        TYPE_PROOF_I => Ok(AuthFrame::ProofI(cbor::from_canonical_bytes(body)?)),
        TYPE_FINAL_CONFIRM => Ok(AuthFrame::FinalConfirm(cbor::from_canonical_bytes(body)?)),
        TYPE_ACTIVATE => Ok(AuthFrame::Activate(cbor::from_canonical_bytes(body)?)),
        TYPE_ACTIVATE_ACK => Ok(AuthFrame::ActivateAck(cbor::from_canonical_bytes(body)?)),
        other => Err(AuthFrameError::Wire(
            crate::error::WireError::UnknownTypeByte(other),
        )),
    }
}

/// K_mesh signing, purpose-bound to mesh-session auth frames specifically
/// (distinct name from any hypothetical roster-sync equivalent, matching
/// v6 §9's typestate/purpose discipline). No implementation ships in this
/// crate — K_mesh's actual key custody is D-4/household-rs territory.
/// Takes an opaque [`MeshSessionFramePreimage`], never raw bytes — see the
/// module hardening note. A caller holding a `MeshSessionFrameSigner`
/// cannot ask it to sign attacker-chosen bytes: there is no
/// `sign_mesh_session_frame(&[u8])` overload, only one taking the opaque,
/// unforgeable preimage type:
///
/// ```compile_fail
/// use mesh_session_core_rs::auth_frames::{MeshSessionFrameSigner, MeshSessionFramePreimage};
/// use mesh_session_core_rs::error::AuthFrameError;
/// use p256::ecdsa::SigningKey;
/// use p256::ecdsa::signature::Signer;
/// use rand_core::OsRng;
///
/// struct AnySigner(SigningKey);
/// impl MeshSessionFrameSigner for AnySigner {
///     fn sign_mesh_session_frame(&self, preimage: &[u8]) -> Result<[u8; 64], AuthFrameError> {
///         // wrong parameter type — the trait requires
///         // &MeshSessionFramePreimage, not a raw byte slice.
///         Ok(self.0.sign(preimage).to_bytes().into())
///     }
/// }
/// ```
///
/// **Fallible (hardened 2026-08-04, @kiana, round 2):** a real K_mesh
/// signer (D-4's `sign_checked`) can legitimately fail — revoked, stale
/// epoch, expired delegation, backend unavailable. An earlier, infallible
/// version of this trait left an implementor no honest way to report that
/// except panicking or fabricating a signature; both are worse than an
/// `Err`. `sign_frame` propagates the error as-is and never invents a
/// signature on failure.
///
/// **`public_key` (hardened 2026-08-04, @kiana, round 3):** exposes only
/// the signer's *public* key — never anything secret — so two things
/// downstream can both be checked mathematically rather than assumed: (1)
/// `sign_frame` verifies its own output against this exact key before
/// ever writing it to a frame (a signer bug could otherwise return a
/// syntactically-valid low-S signature that verifies against some *other*
/// message or key, and it would go straight to the wire); (2)
/// `auth_state_machine` compares this key against
/// `local.delegation.delegated_pub()` before the first frame is sent, so
/// a signer that does not actually hold the delegated key is caught
/// before producing anything a peer would reject anyway. Self-consistency
/// (a frame verifying against its own embedded key) still never
/// substitutes for delegation authority — see the module scope note; this
/// only proves the *local* signer and the *local* delegation agree.
pub trait MeshSessionFrameSigner {
    /// Returns the P-256 fixed-size `r || s` encoding (64 bytes),
    /// **low-S canonical** — implementors must normalize before returning.
    /// `sign_frame` re-parses and re-checks this itself before the
    /// signature ever reaches the wire (2026-08-04, @kiana: do not trust
    /// only the implementor's doc comment or the peer's inbound verifier
    /// to catch a non-canonical signature this side produced).
    /// `deadline` (2026-08-04, @kiana, WIP audit, E3 seam): the real D4
    /// signer (guard/revalidation/backend.sign) may block. The SAME
    /// absolute `CeremonyDeadline` already threaded through the rest of
    /// the ceremony is passed here too — never a fresh, independently-
    /// resettable timeout. A real implementation must return
    /// `SignerFailed`/an equivalent unavailable outcome before any
    /// terminal effect if it cannot produce a signature within budget,
    /// never block past it.
    fn sign_mesh_session_frame(
        &self,
        preimage: &MeshSessionFramePreimage,
        deadline: &CeremonyDeadline,
    ) -> Result<[u8; 64], AuthFrameError>;

    /// This signer's own P-256 public key. Never secret material — used
    /// only to mathematically self-check `sign_mesh_session_frame`'s
    /// output and to bind the signer to `local.delegation.delegated_pub`.
    ///
    /// **Contractually non-blocking (2026-08-04, @kiana, runtime-facade
    /// audit `3cbbfb37…` P1-1):** called from multiple pre-I/O preflight
    /// checks (`check_signer_matches_delegation`,
    /// `PendingIntent::build_and_sign`/`verify_binds_to`) before this
    /// crate's own `CeremonyDeadline` has necessarily been checked again.
    /// No `&CeremonyDeadline` parameter is threaded through here — instead
    /// a real implementation MUST return in bounded, effectively-constant
    /// time (an in-memory P-256 scalar read, never network/disk I/O or a
    /// lock that can be held by an unrelated slow operation). A signer
    /// backend whose key material genuinely requires I/O to read must
    /// cache the public half at construction time, not read it fresh on
    /// every call.
    fn public_key(&self) -> VerifyingKey;

    /// Sign a `SignedMeshConnectionIntent` (0x06 carrier). Deliberately a
    /// separate method, not a reuse of `sign_mesh_session_frame` (2026-08-04,
    /// D9 carrier-B addendum): the intent is never an `AuthFrameBody` and
    /// never passes through `sign_frame`. Reusing the SAME signer object
    /// (and therefore the SAME physical key) for both this and
    /// `sign_mesh_session_frame` structurally guarantees "the same K_mesh
    /// signs both the intent and Proof-I" — addendum §4 item 3 — rather
    /// than requiring a caller to prove it separately. Same low-S-canonical
    /// contract as `sign_mesh_session_frame`; `intent::sign_intent_record`
    /// re-parses and mathematically self-verifies this output too.
    /// **No `deadline` parameter (2026-08-04, @kiana, WIP audit, E3 seam
    /// — conditional: "se 0x06 for assinado on-path"):** unlike
    /// `sign_mesh_session_frame`, signing the 0x06 intent is NOT on-path
    /// within the timed ceremony in this crate's design — `PendingIntent::
    /// build_and_sign` (the only caller of this method) is built by the
    /// initiator's own caller before dialing, outside any
    /// `CeremonyDeadline`'s scope (see the intent module's own "what this
    /// module does not do" note: this crate does not decide how an
    /// initiator obtains/mints its own intent before dialing). If a real
    /// integration ever signs 0x06 on-path instead, that call site would
    /// need its own deadline threading at that point — not assumed here.
    fn sign_intent(
        &self,
        preimage: &crate::intent::IntentSigningPreimage,
    ) -> Result<[u8; 64], AuthFrameError>;
}

pub trait MeshSessionFrameVerifier {
    fn verify_mesh_session_frame(
        &self,
        preimage: &MeshSessionFramePreimage,
        signature: &[u8; 64],
    ) -> Result<(), AuthFrameError>;

    /// Verify a `SignedMeshConnectionIntent` signature — same rationale as
    /// `MeshSessionFrameSigner::sign_intent`: a separate method so the
    /// intent never needs to pretend to be an `AuthFrameBody` to be
    /// verified. Returns `IntentError`, not `AuthFrameError` — this trait
    /// method is intent-specific even though the trait itself is shared.
    fn verify_intent(
        &self,
        preimage: &crate::intent::IntentSigningPreimage,
        signature: &[u8; 64],
    ) -> Result<(), crate::error::IntentError>;
}

/// Verifies a mesh-session frame signature against a specific, already-in-
/// hand P-256 public key — typically the peer's own `delegation.delegated_pub`,
/// which the frame carries itself (self-consistency only, never authority;
/// see the module scope-boundary note). Concrete and always available:
/// unlike signing, this needs no key custody, only the public key the
/// caller already has.
///
/// **Low-S canonical required (2026-08-04, @kiana instruction — not a v6
/// literal, ECDSA signature-malleability hygiene):** a signature that
/// `normalize_s()` reports as non-normalized (i.e. high-S) is rejected
/// outright, not silently accepted-after-normalizing.
pub struct RawP256FrameVerifier(pub VerifyingKey);

/// Parse `signature` as a P-256 ECDSA signature and require it to already
/// be low-S canonical, rejecting high-S outright rather than normalizing
/// and accepting. Shared by inbound verification
/// ([`RawP256FrameVerifier`]) and outbound signing ([`sign_frame`]) — the
/// same check runs on bytes this crate is about to trust *and* on bytes
/// it is about to put on the wire, so a non-canonical signature can never
/// pass in either direction.
pub(crate) fn parse_low_s_signature(signature: &[u8; 64]) -> Result<Signature, AuthFrameError> {
    let sig =
        Signature::from_slice(signature).map_err(|_| AuthFrameError::InvalidSignatureScalar)?;
    if sig.normalize_s().is_some() {
        return Err(AuthFrameError::HighSRejected);
    }
    Ok(sig)
}

impl MeshSessionFrameVerifier for RawP256FrameVerifier {
    fn verify_mesh_session_frame(
        &self,
        preimage: &MeshSessionFramePreimage,
        signature: &[u8; 64],
    ) -> Result<(), AuthFrameError> {
        let sig = parse_low_s_signature(signature)?;
        self.0
            .verify(preimage.as_bytes(), &sig)
            .map_err(|_| AuthFrameError::BadSignature)
    }

    fn verify_intent(
        &self,
        preimage: &crate::intent::IntentSigningPreimage,
        signature: &[u8; 64],
    ) -> Result<(), crate::error::IntentError> {
        let sig = parse_low_s_signature(signature).map_err(|e| match e {
            AuthFrameError::HighSRejected => crate::error::IntentError::HighSRejected,
            _ => crate::error::IntentError::InvalidSignatureScalar,
        })?;
        self.0
            .verify(preimage.as_bytes(), &sig)
            .map_err(|_| crate::error::IntentError::BadSignature)
    }
}

/// Parse a `delegated_pub` (SEC1-compressed P-256 point, 33 bytes) into a
/// verifier for that specific key. Pure math — no custody, no claim the
/// key is authorized. `delegation.rs`'s own `validate_shape` already
/// parses this same field at construction time, so this should not fail
/// for any `delegated_pub` obtained from a real `MeshSessionDelegation` —
/// it re-parses rather than trusting that invariant blindly.
pub(crate) fn verifier_from_delegated_pub(
    delegated_pub: &[u8],
) -> Result<RawP256FrameVerifier, AuthFrameError> {
    let vk =
        VerifyingKey::from_sec1_bytes(delegated_pub).map_err(|_| AuthFrameError::BadSignature)?;
    Ok(RawP256FrameVerifier(vk))
}

/// Sign a frame with K_mesh and return the same frame with `sig` filled
/// in. `pub(crate)`: only `auth_state_machine` orchestrates signing.
///
/// Propagates a fallible signer's error as-is (2026-08-04, @kiana: a real
/// K_mesh signer can fail — revoked/stale/expired/backend — and must never
/// be forced into fabricating a signature to satisfy an infallible
/// return type). Before returning, re-parses whatever the signer produced
/// and requires it to be a valid, low-S canonical P-256 signature — this
/// crate does not trust only the implementor's doc comment, or the
/// receiving peer's own inbound check, to catch a malformed signature
/// this side is about to put on the wire.
///
/// **Mathematically self-verified (hardened 2026-08-04, @kiana, round 3):**
/// shape-and-low-S parsing alone does not prove the returned bytes are a
/// signature *over this preimage* — a buggy signer could return a
/// perfectly well-formed low-S signature that happens to verify against a
/// completely different message (or nothing at all it was asked to sign),
/// and it would previously have gone straight to the wire, condemned only
/// once the peer eventually checked it. `sign_frame` now verifies the
/// signature against the exact `preimage` and the signer's own
/// [`MeshSessionFrameSigner::public_key`] before ever returning it —
/// wrong-message and wrong-key both fail closed locally,
/// `SignerProducedInvalidSignature`, before any write.
pub(crate) fn sign_frame<F, Sig>(
    frame: F,
    k_mesh: &Sig,
    deadline: &CeremonyDeadline,
) -> Result<F, AuthFrameError>
where
    F: AuthFrameBody + FrameWithSig,
    Sig: MeshSessionFrameSigner,
{
    let preimage = MeshSessionFramePreimage::for_frame(&frame)?;
    let sig_bytes = k_mesh.sign_mesh_session_frame(&preimage, deadline)?;
    let sig = parse_low_s_signature(&sig_bytes)?;
    k_mesh
        .public_key()
        .verify(preimage.as_bytes(), &sig)
        .map_err(|_| AuthFrameError::SignerProducedInvalidSignature)?;
    Ok(frame.with_sig_bytes(sig_bytes.to_vec()))
}

/// Verify a frame's own `sig` against `verifier`. `pub(crate)`: only
/// `auth_state_machine` orchestrates verification, always after the
/// delegation gate (policy + injected signature verifier + partial
/// binding) has already passed — self-consistency does not authorize.
pub(crate) fn verify_frame<F, Ver>(
    frame: &F,
    sig: &[u8; 64],
    verifier: &Ver,
) -> Result<(), AuthFrameError>
where
    F: AuthFrameBody,
    Ver: MeshSessionFrameVerifier,
{
    let preimage = MeshSessionFramePreimage::for_frame(frame)?;
    verifier.verify_mesh_session_frame(&preimage, sig)
}

/// Internal helper trait so `sign_frame` can be generic over which frame
/// type it's filling `sig` into, without exposing a public "set sig on
/// anything" API.
pub(crate) trait FrameWithSig {
    fn with_sig_bytes(self, sig: Vec<u8>) -> Self;
}
impl FrameWithSig for ProofR {
    fn with_sig_bytes(self, sig: Vec<u8>) -> Self {
        self.with_sig(sig)
    }
}
impl FrameWithSig for ProofI {
    fn with_sig_bytes(self, sig: Vec<u8>) -> Self {
        self.with_sig(sig)
    }
}
impl FrameWithSig for FinalConfirm {
    fn with_sig_bytes(self, sig: Vec<u8>) -> Self {
        self.with_sig(sig)
    }
}
impl FrameWithSig for Activate {
    fn with_sig_bytes(self, sig: Vec<u8>) -> Self {
        self.with_sig(sig)
    }
}
impl FrameWithSig for ActivateAck {
    fn with_sig_bytes(self, sig: Vec<u8>) -> Self {
        self.with_sig(sig)
    }
}

/// `frame_digest(type, body) = SHA-256(type_byte || canonical_cbor(full
/// body INCLUDING sig))` — distinct from the signing preimage (which
/// excludes `sig`). Used for `final_confirm_digest`/`activate_digest`
/// cross-references. `pub(crate)`: same "no arbitrary type/struct pairing"
/// reasoning as signing — the sealed `AuthFrameBody` fixes the type byte.
pub(crate) fn frame_digest<F: AuthFrameBody>(frame: &F) -> Result<[u8; 32], AuthFrameError> {
    digest_for_frame(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::test_support::sample_delegation;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use rand_core::OsRng;
    use std::time::{Duration, Instant};

    fn far_future_deadline() -> CeremonyDeadline {
        CeremonyDeadline::for_test(Instant::now(), Duration::from_secs(3600))
    }

    struct TestKMesh(SigningKey);
    impl MeshSessionFrameSigner for TestKMesh {
        fn sign_mesh_session_frame(
            &self,
            preimage: &MeshSessionFramePreimage,
            _deadline: &CeremonyDeadline,
        ) -> Result<[u8; 64], AuthFrameError> {
            let sig: Signature = self.0.sign(preimage.as_bytes());
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().into())
        }
        fn public_key(&self) -> VerifyingKey {
            *self.0.verifying_key()
        }
        fn sign_intent(
            &self,
            preimage: &crate::intent::IntentSigningPreimage,
        ) -> Result<[u8; 64], AuthFrameError> {
            let sig: Signature = self.0.sign(preimage.as_bytes());
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().into())
        }
    }

    /// Stands in for a buggy/malicious K_mesh that signs a DIFFERENT
    /// message than the one it was asked for, but otherwise correctly
    /// (low-S, matching its own key) — proves `sign_frame`'s new
    /// mathematical self-check catches a wrong-preimage signature that
    /// shape-and-low-S parsing alone would have let straight onto the
    /// wire.
    struct WrongMessageKMesh(SigningKey);
    impl MeshSessionFrameSigner for WrongMessageKMesh {
        fn sign_mesh_session_frame(
            &self,
            _preimage: &MeshSessionFramePreimage,
            _deadline: &CeremonyDeadline,
        ) -> Result<[u8; 64], AuthFrameError> {
            let sig: Signature = self.0.sign(b"not the preimage sign_frame asked for");
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().into())
        }
        fn public_key(&self) -> VerifyingKey {
            *self.0.verifying_key()
        }
        fn sign_intent(
            &self,
            _preimage: &crate::intent::IntentSigningPreimage,
        ) -> Result<[u8; 64], AuthFrameError> {
            let sig: Signature = self
                .0
                .sign(b"not the preimage sign_intent_record asked for");
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().into())
        }
    }

    /// Stands in for a K_mesh that signs correctly but whose reported
    /// `public_key()` does not match the key it actually signed with —
    /// used to prove `sign_frame`'s self-check (and, separately,
    /// `auth_state_machine`'s delegation binding check) catch a
    /// key/signature mismatch rather than trusting either side alone.
    struct MismatchedPublicKeyKMesh {
        signs_with: SigningKey,
        claims_to_be: SigningKey,
    }
    impl MeshSessionFrameSigner for MismatchedPublicKeyKMesh {
        fn sign_mesh_session_frame(
            &self,
            preimage: &MeshSessionFramePreimage,
            _deadline: &CeremonyDeadline,
        ) -> Result<[u8; 64], AuthFrameError> {
            let sig: Signature = self.signs_with.sign(preimage.as_bytes());
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().into())
        }
        fn public_key(&self) -> VerifyingKey {
            *self.claims_to_be.verifying_key()
        }
        fn sign_intent(
            &self,
            preimage: &crate::intent::IntentSigningPreimage,
        ) -> Result<[u8; 64], AuthFrameError> {
            let sig: Signature = self.signs_with.sign(preimage.as_bytes());
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().into())
        }
    }

    /// Stands in for a real K_mesh whose backend refuses to sign — e.g.
    /// revoked, stale epoch, expired delegation. `sign_frame` must
    /// propagate this, never fabricate a signature.
    struct AlwaysFailingKMesh(SigningKey);
    impl MeshSessionFrameSigner for AlwaysFailingKMesh {
        fn sign_mesh_session_frame(
            &self,
            _preimage: &MeshSessionFramePreimage,
            _deadline: &CeremonyDeadline,
        ) -> Result<[u8; 64], AuthFrameError> {
            Err(AuthFrameError::SignerFailed)
        }
        fn public_key(&self) -> VerifyingKey {
            *self.0.verifying_key()
        }
        fn sign_intent(
            &self,
            _preimage: &crate::intent::IntentSigningPreimage,
        ) -> Result<[u8; 64], AuthFrameError> {
            Err(AuthFrameError::SignerFailed)
        }
    }

    /// Stands in for a buggy/non-compliant K_mesh that returns a high-S
    /// signature — `sign_frame` must catch this itself, not rely on the
    /// receiving peer's inbound check. RFC6979 signing is deterministic
    /// per (key, message), so probe a small salt range for a message that
    /// happens to sign high-S (roughly half do) rather than trying to
    /// construct one directly — the `ecdsa` crate exposes no public
    /// "denormalize" operation.
    struct AlwaysHighSKMesh(SigningKey);
    impl MeshSessionFrameSigner for AlwaysHighSKMesh {
        fn sign_mesh_session_frame(
            &self,
            preimage: &MeshSessionFramePreimage,
            _deadline: &CeremonyDeadline,
        ) -> Result<[u8; 64], AuthFrameError> {
            for salt in 0u8..255 {
                let mut salted = preimage.as_bytes().to_vec();
                salted.push(salt);
                let sig: Signature = self.0.sign(&salted);
                if sig.normalize_s().is_some() {
                    return Ok(sig.to_bytes().into());
                }
            }
            panic!("expected at least one high-S signature among 255 probes");
        }
        fn public_key(&self) -> VerifyingKey {
            *self.0.verifying_key()
        }
        fn sign_intent(
            &self,
            preimage: &crate::intent::IntentSigningPreimage,
        ) -> Result<[u8; 64], AuthFrameError> {
            for salt in 0u8..255 {
                let mut salted = preimage.as_bytes().to_vec();
                salted.push(salt);
                let sig: Signature = self.0.sign(&salted);
                if sig.normalize_s().is_some() {
                    return Ok(sig.to_bytes().into());
                }
            }
            panic!("expected at least one high-S signature among 255 probes");
        }
    }

    fn sample_proof_r() -> ProofR {
        ProofR::new(
            vec![0u8; 32],
            "hh-1".to_string(),
            "responder-1".to_string(),
            vec![0xCC; 32],
            vec![0xDD; 32],
            1,
            vec![0xEE; 32],
            1_000_000,
            sample_delegation(100, 200),
            vec![0u8; 64],
        )
        .unwrap()
    }

    #[test]
    fn auth_frame_round_trip_through_wire_encode_decode() {
        let frame = AuthFrame::ProofR(sample_proof_r());
        let bytes = encode_auth_frame(&frame).unwrap();
        assert_eq!(bytes[0], TYPE_PROOF_R);
        let decoded = decode_auth_frame(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn red_unknown_type_byte_rejected() {
        let mut bytes = encode_auth_frame(&AuthFrame::ProofR(sample_proof_r())).unwrap();
        bytes[0] = 0x99;
        assert!(matches!(
            decode_auth_frame(&bytes),
            Err(AuthFrameError::Wire(
                crate::error::WireError::UnknownTypeByte(0x99)
            ))
        ));
    }

    #[test]
    fn red_wrong_role_for_proof_r_rejected_at_construction() {
        let bad = ProofRWire {
            protocol_version: PROTOCOL_VERSION,
            domain: DOMAIN.to_string(),
            role: ROLE_INITIATOR.to_string(), // wrong — ProofR must be "responder"
            h_final: vec![0u8; 32],
            hh_id: "hh-1".to_string(),
            self_m_id: "x".to_string(),
            self_cert_fingerprint: vec![0xCC; 32],
            checkpoint_hash: vec![0xDD; 32],
            checkpoint_sequence: 1,
            checkpoint_event_head: vec![0xEE; 32],
            checkpoint_not_after: 1,
            delegation: sample_delegation(100, 200),
            sig: vec![0u8; 64],
        };
        assert!(matches!(
            ProofR::try_from(bad),
            Err(AuthFrameError::RoleOrKindMismatch)
        ));
    }

    #[test]
    fn red_wrong_h_final_length_rejected_at_construction() {
        let bad = ProofRWire {
            protocol_version: PROTOCOL_VERSION,
            domain: DOMAIN.to_string(),
            role: ROLE_RESPONDER.to_string(),
            h_final: vec![0u8; 31], // one byte short
            hh_id: "hh-1".to_string(),
            self_m_id: "x".to_string(),
            self_cert_fingerprint: vec![0xCC; 32],
            checkpoint_hash: vec![0xDD; 32],
            checkpoint_sequence: 1,
            checkpoint_event_head: vec![0xEE; 32],
            checkpoint_not_after: 1,
            delegation: sample_delegation(100, 200),
            sig: vec![0u8; 64],
        };
        assert!(matches!(
            ProofR::try_from(bad),
            Err(AuthFrameError::ShapeMismatch)
        ));
    }

    #[test]
    fn red_wrong_domain_literal_rejected_at_construction() {
        let bad = ProofRWire {
            protocol_version: PROTOCOL_VERSION,
            domain: "soyeht/mesh-connection-intent/v1".to_string(),
            role: ROLE_RESPONDER.to_string(),
            h_final: vec![0u8; 32],
            hh_id: "hh-1".to_string(),
            self_m_id: "x".to_string(),
            self_cert_fingerprint: vec![0xCC; 32],
            checkpoint_hash: vec![0xDD; 32],
            checkpoint_sequence: 1,
            checkpoint_event_head: vec![0xEE; 32],
            checkpoint_not_after: 1,
            delegation: sample_delegation(100, 200),
            sig: vec![0u8; 64],
        };
        assert!(matches!(
            ProofR::try_from(bad),
            Err(AuthFrameError::VersionOrDomainMismatch)
        ));
    }

    #[test]
    fn embedding_still_validates_after_decode_not_just_at_construction() {
        // Regression for the audit finding: fields used to be pub with no
        // post-decode validation. Hand-build wire bytes with a bad role
        // (bypassing ProofR::new's own validation entirely) and confirm
        // the closed decode entrypoint still rejects them.
        let w = ProofRWire {
            protocol_version: PROTOCOL_VERSION,
            domain: DOMAIN.to_string(),
            role: "not-a-real-role".to_string(),
            h_final: vec![0u8; 32],
            hh_id: "hh-1".to_string(),
            self_m_id: "x".to_string(),
            self_cert_fingerprint: vec![0xCC; 32],
            checkpoint_hash: vec![0xDD; 32],
            checkpoint_sequence: 1,
            checkpoint_event_head: vec![0xEE; 32],
            checkpoint_not_after: 1,
            delegation: sample_delegation(100, 200),
            sig: vec![0u8; 64],
        };
        let body_cbor = cbor::to_canonical_vec(&w).unwrap();
        let frame_bytes = crate::wire::encode_typed_frame(TYPE_PROOF_R, &body_cbor).unwrap();
        assert!(decode_auth_frame(&frame_bytes).is_err());
    }

    #[test]
    fn red_wrong_frame_type_for_the_type_byte_rejected() {
        // A ProofI-shaped body framed under ProofR's type byte — the field
        // sets differ (ProofI has expected_peer_m_id etc.), so
        // deny_unknown_fields on ProofR must reject it.
        let proof_i = ProofI::new(
            vec![0u8; 32],
            "hh-1".to_string(),
            "initiator-1".to_string(),
            "responder-1".to_string(),
            vec![0xAA; 32],
            vec![0xCC; 32],
            vec![0xDD; 32],
            1,
            vec![0xEE; 32],
            1_000_000,
            sample_delegation(100, 200),
            ConnectionIntentDigest::from_bytes([0x11; 32]),
            vec![0u8; 64],
        )
        .unwrap();
        let body_cbor = cbor::to_canonical_vec(&proof_i).unwrap();
        let frame_bytes = crate::wire::encode_typed_frame(TYPE_PROOF_R, &body_cbor).unwrap();
        assert!(decode_auth_frame(&frame_bytes).is_err());
    }

    #[test]
    fn connection_intent_digest_round_trips_and_rejects_wrong_length() {
        let digest = ConnectionIntentDigest::from_bytes([0x42; 32]);
        let bytes = cbor::to_canonical_vec(&digest).unwrap();
        let back: ConnectionIntentDigest = cbor::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(digest, back);

        let short = serde_bytes::ByteBuf::from(vec![0u8; 31]);
        let short_bytes = cbor::to_canonical_vec(&short).unwrap();
        assert!(cbor::from_canonical_bytes::<ConnectionIntentDigest>(&short_bytes).is_err());
    }

    #[test]
    fn red_missing_connection_intent_digest_rejected_by_deny_unknown_fields_shape() {
        use ciborium::Value;
        let raw = Value::Map(vec![
            (
                Value::Text("protocol_version".into()),
                Value::Integer(1.into()),
            ),
            (Value::Text("domain".into()), Value::Text(DOMAIN.into())),
            (
                Value::Text("role".into()),
                Value::Text(ROLE_INITIATOR.into()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&raw, &mut bytes).unwrap();
        assert!(cbor::from_canonical_bytes::<ProofI>(&bytes).is_err());
    }

    #[test]
    fn signed_preimage_excludes_sig_frame_digest_includes_it() {
        let frame = sample_proof_r();
        let preimage = MeshSessionFramePreimage::for_frame(&frame).unwrap();
        assert_eq!(preimage.as_bytes()[0], TYPE_PROOF_R);
        assert!(!crate::cbor::map_has_top_level_key(&preimage.as_bytes()[1..], "sig").unwrap());

        let digest_a = frame_digest(&frame).unwrap();
        let tampered = frame.clone().with_sig(vec![0xFFu8; 64]);
        let digest_b = frame_digest(&tampered).unwrap();
        assert_ne!(
            digest_a, digest_b,
            "frame_digest must include sig — two different sigs must digest differently"
        );
    }

    #[test]
    fn sign_then_verify_round_trip_with_a_real_p256_pair() {
        let signing_key = SigningKey::random(&mut OsRng);
        let k_mesh = TestKMesh(signing_key.clone());
        let verifier = RawP256FrameVerifier(VerifyingKey::from(&signing_key));

        let frame = sample_proof_r();
        let signed = sign_frame(frame, &k_mesh, &far_future_deadline()).unwrap();
        let sig: [u8; 64] = signed.sig().to_vec().try_into().unwrap();
        verify_frame(&signed, &sig, &verifier).unwrap();
    }

    /// Reads `deadline` itself and fails if already expired — proves the
    /// SAME token `sign_frame` receives genuinely reaches a real signer's
    /// own check (2026-08-04, @kiana, WIP audit, E3 seam: "todo hook
    /// potencialmente I/O deve receber o mesmo token"), the signing-side
    /// counterpart of `DeadlineAwareVerifier` in
    /// `auth_state_machine::tests`.
    struct DeadlineAwareSigner(SigningKey);
    impl MeshSessionFrameSigner for DeadlineAwareSigner {
        fn sign_mesh_session_frame(
            &self,
            preimage: &MeshSessionFramePreimage,
            deadline: &CeremonyDeadline,
        ) -> Result<[u8; 64], AuthFrameError> {
            if deadline.is_expired() {
                return Err(AuthFrameError::SignerFailed);
            }
            let sig: Signature = self.0.sign(preimage.as_bytes());
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().into())
        }
        fn public_key(&self) -> VerifyingKey {
            *self.0.verifying_key()
        }
        fn sign_intent(
            &self,
            preimage: &crate::intent::IntentSigningPreimage,
        ) -> Result<[u8; 64], AuthFrameError> {
            let sig: Signature = self.0.sign(preimage.as_bytes());
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().into())
        }
    }

    #[test]
    fn red_sign_frame_propagates_the_official_ceremony_deadline_to_the_signer() {
        let k_mesh = DeadlineAwareSigner(SigningKey::random(&mut OsRng));
        let expired = CeremonyDeadline::already_expired_for_test();
        let err = sign_frame(sample_proof_r(), &k_mesh, &expired).unwrap_err();
        assert!(matches!(err, AuthFrameError::SignerFailed));
    }

    #[test]
    fn red_signer_failure_propagates_never_fabricates_a_signature() {
        let k_mesh = AlwaysFailingKMesh(SigningKey::random(&mut OsRng));
        let err = sign_frame(sample_proof_r(), &k_mesh, &far_future_deadline()).unwrap_err();
        assert!(matches!(err, AuthFrameError::SignerFailed));
    }

    #[test]
    fn red_signer_returning_high_s_is_caught_before_the_wire() {
        let signing_key = SigningKey::random(&mut OsRng);
        let k_mesh = AlwaysHighSKMesh(signing_key);
        let err = sign_frame(sample_proof_r(), &k_mesh, &far_future_deadline()).unwrap_err();
        assert!(matches!(err, AuthFrameError::HighSRejected));
    }

    #[test]
    fn red_signer_returning_a_valid_low_s_signature_for_a_different_message_is_rejected() {
        // The core finding this closes: shape-and-low-S parsing alone
        // does not prove the signature is OVER THIS PREIMAGE. A signer
        // that returns a perfectly well-formed, low-S, key-consistent
        // signature — just over the wrong message — must still be caught
        // locally, before the frame is ever written.
        let k_mesh = WrongMessageKMesh(SigningKey::random(&mut OsRng));
        let err = sign_frame(sample_proof_r(), &k_mesh, &far_future_deadline()).unwrap_err();
        assert!(matches!(
            err,
            AuthFrameError::SignerProducedInvalidSignature
        ));
    }

    #[test]
    fn red_signer_public_key_not_matching_its_own_signing_key_is_rejected() {
        // A signer whose sign_mesh_session_frame and public_key report
        // two DIFFERENT keys — the signature is real and over the right
        // preimage, but does not verify against what the signer itself
        // claims to be. Must fail the same way as a wrong-message
        // signature: locally, before any write.
        let k_mesh = MismatchedPublicKeyKMesh {
            signs_with: SigningKey::random(&mut OsRng),
            claims_to_be: SigningKey::random(&mut OsRng),
        };
        let err = sign_frame(sample_proof_r(), &k_mesh, &far_future_deadline()).unwrap_err();
        assert!(matches!(
            err,
            AuthFrameError::SignerProducedInvalidSignature
        ));
    }

    #[test]
    fn tampered_frame_fails_verification() {
        let signing_key = SigningKey::random(&mut OsRng);
        let k_mesh = TestKMesh(signing_key.clone());
        let verifier = RawP256FrameVerifier(VerifyingKey::from(&signing_key));

        let frame = sample_proof_r();
        let signed = sign_frame(frame, &k_mesh, &far_future_deadline()).unwrap();
        let sig: [u8; 64] = signed.sig().to_vec().try_into().unwrap();

        let tampered = ProofR::new(
            signed.h_final().to_vec(),
            signed.hh_id().to_string(),
            "attacker".to_string(),
            signed.self_cert_fingerprint().to_vec(),
            signed.checkpoint_hash().to_vec(),
            1,
            vec![0xEE; 32],
            1_000_000,
            sample_delegation(100, 200),
            signed.sig().to_vec(),
        )
        .unwrap();
        assert!(verify_frame(&tampered, &sig, &verifier).is_err());
    }

    #[test]
    fn red_high_s_signature_rejected_low_s_accepted() {
        // RFC6979 signing is deterministic per (key, message), so a fixed
        // preimage always yields the same s. Vary the frame across a
        // small probe set to find at least one naturally-high-S signature
        // (P-256 ECDSA signatures land high-S roughly half the time before
        // normalization) — this is deterministic given a fixed key and a
        // fixed sequence of probe frames, not flaky.
        let signing_key = SigningKey::random(&mut OsRng);
        let verifier = RawP256FrameVerifier(VerifyingKey::from(&signing_key));

        let mut found_high_s = false;
        let mut found_low_s = false;
        for i in 0u64..64 {
            let probe = ProofR::new(
                vec![0u8; 32],
                "hh-1".to_string(),
                "responder-1".to_string(),
                vec![0xCC; 32],
                vec![0xDD; 32],
                i,
                vec![0xEE; 32],
                1_000_000,
                sample_delegation(100, 200),
                vec![0u8; 64],
            )
            .unwrap();
            let preimage = MeshSessionFramePreimage::for_frame(&probe).unwrap();
            let sig: Signature = signing_key.sign(preimage.as_bytes());
            let sig_bytes: [u8; 64] = sig.to_bytes().into();
            if sig.normalize_s().is_some() {
                assert!(matches!(
                    verifier.verify_mesh_session_frame(&preimage, &sig_bytes),
                    Err(AuthFrameError::HighSRejected)
                ));
                found_high_s = true;
            } else {
                verifier
                    .verify_mesh_session_frame(&preimage, &sig_bytes)
                    .unwrap();
                found_low_s = true;
            }
            if found_high_s && found_low_s {
                break;
            }
        }
        assert!(
            found_high_s,
            "expected at least one high-S signature among 64 probes"
        );
        assert!(
            found_low_s,
            "expected at least one low-S signature among 64 probes"
        );
    }
}
