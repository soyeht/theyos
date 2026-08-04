//! `SignedMeshConnectionIntent` (0x06) — D9 carrier B.
//!
//! Normative sources (self-hash verified against
//! `/tmp/soyeht-triage/*` before implementation, 2026-08-04):
//! - `kiana-d9-device-intent-wire-freeze.62dbf788…` (wire schema, §1-2)
//! - `zain-signed-mesh-connection-intent-v2.d013ac29…` + erratum1
//!   `b7fd28d3…` + erratum2 `15283ea2…` (binding, digest domain
//!   separation, nonce ledger durability, capability/intent type split)
//! - `kiana-d9-intent-carrier-b-addendum.c203463c…` (carrier decision,
//!   states/sequencing, combined check, nonce ledger key/atomicity,
//!   timeout, REDs)
//!
//! **Deliberately NOT part of `AuthFrame`/`AuthFrameBody`** (addendum §1):
//! `SignedMeshConnectionIntent` is a separate wire record, sent exactly
//! once between a verified Proof-R and Proof-I, under the same Noise
//! transport encryption but through its own dedicated encode/decode
//! functions — never through `auth_frames::sign_frame`/`verify_frame`,
//! never a variant of the closed `AuthFrame` enum. `0x07`
//! (`SignedMeshConnectionCapability`) stays reserved and unreachable —
//! nothing in this module can construct, decode, or sign one.
//!
//! **Carrier A (pre-Noise out-of-band staging + ack) is rejected**
//! (addendum §1): it exposes identifying fields to a passive observer
//! with zero Noise required, creates attacker-reachable durable state
//! before any handshake cap applies, is not bound to `h_final`, and has
//! no frozen wire mechanism to authenticate an ack. Carrier B reuses the
//! existing Noise transport, existing `MAX_CBOR_BODY_LEN`/
//! `HANDSHAKE_TIMEOUT` discipline, and the existing "self-consistency
//! does not authorize" doctrine end to end.
//!
//! **What this module does not do** (addendum §8, unchanged): it does not
//! decide how an initiator obtains/mints its own intent before dialing;
//! it does not implement D-4's real signer or the delegation's own M_priv
//! preimage; it does not implement a real durable nonce ledger or D-1
//! admission — both are caller-injected traits with fail-closed defaults
//! shipped ([`NoIntentLedgerConfigured`], [`NoD1AdmissionConfigured`]).
#![allow(dead_code)]

use p256::ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};

use crate::auth_frames::{MeshSessionFrameSigner, MeshSessionFrameVerifier, parse_low_s_signature};
use crate::auth_state_machine::{ExpectedChannel, LocalIdentity};
use crate::cbor;
use crate::delegation::MeshSessionDelegation;
use crate::error::{AuthFrameError, IntentError};
use crate::ingress::CeremonyDeadline;

/// `parse_low_s_signature` is shared plumbing typed around
/// `AuthFrameError` (its original, `AuthFrame`-scoped caller) — this
/// module re-maps its two possible failures to the equivalent
/// `IntentError` variants rather than collapsing them into one, so a
/// caller can still tell "not a valid signature at all" apart from
/// "valid but high-S".
fn map_low_s_error(e: AuthFrameError) -> IntentError {
    match e {
        AuthFrameError::HighSRejected => IntentError::HighSRejected,
        _ => IntentError::InvalidSignatureScalar,
    }
}

/// Registered in the same external namespace as `0x01..0x05` (D9 wire
/// freeze §1) but outside the closed `AuthFrame` Rust enum/sealed
/// `AuthFrameBody` trait.
pub const INTENT_TYPE_BYTE: u8 = 0x06;
/// Reserved, never admitted — `SignedMeshConnectionCapability` is not
/// implemented anywhere in this crate. Kept only so a decoder can name
/// the collision explicitly instead of falling through to a generic
/// "unknown type byte".
pub const CAPABILITY_TYPE_BYTE_RESERVED: u8 = 0x07;

pub const INTENT_DOMAIN: &str = "soyeht/mesh-connection-intent/v1";
pub const INTENT_VERSION: u64 = 1;

fn check_intent_header(version: u64, domain: &str) -> Result<(), IntentError> {
    if version != INTENT_VERSION || domain != INTENT_DOMAIN {
        return Err(IntentError::VersionOrDomainMismatch);
    }
    Ok(())
}

fn check_len(bytes: &[u8], expected: usize) -> Result<(), IntentError> {
    if bytes.len() != expected {
        return Err(IntentError::ShapeMismatch);
    }
    Ok(())
}

/// **Added 2026-08-04, @kiana, WIP audit item 4:** `hh_id`/`initiator_m_id`/
/// `target_m_id`/`delegated_key_id` previously had no validation at all
/// beyond being *some* string — an empty string satisfied every other
/// check in [`TryFrom<SignedMeshConnectionIntentWire>`] and would reach as
/// far as the combined check before failing (if it failed at all; an
/// empty `delegated_key_id` could coincidentally match an equally-empty
/// field elsewhere). Rejected here, at shape-validation time, before the
/// value is ever held as a `SignedMeshConnectionIntent` at all.
fn check_nonempty(s: &str) -> Result<(), IntentError> {
    if s.is_empty() {
        return Err(IntentError::EmptyIdentifier);
    }
    Ok(())
}

/// Plain wire-shape shadow, `pub(crate)` — used only as the serde
/// `try_from`/`into` intermediate so construction always runs through
/// `TryFrom`'s validation, and by this module's own tests to build
/// fixtures without a full sign round trip. Field order here is
/// declaration order only; canonical wire order is RFC 8949
/// (length-then-lexicographic key sort), applied generically by
/// `cbor::to_canonical_vec` — matches the D9 freeze §2 key order exactly
/// (verified by inspection: v, sig, hh_id, nonce, domain, not_after,
/// target_m_id, initiator_m_id, checkpoint_hash, delegated_key_id,
/// target_cert_fingerprint, initiator_cert_fingerprint, sorted by
/// (byte-length, lexicographic)).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedMeshConnectionIntentWire {
    #[serde(rename = "v")]
    pub(crate) version: u64,
    pub(crate) domain: String,
    pub(crate) hh_id: String,
    pub(crate) initiator_m_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) initiator_cert_fingerprint: Vec<u8>,
    pub(crate) target_m_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) target_cert_fingerprint: Vec<u8>,
    /// Audit only — D9 freeze §6, v2 CFX-2, addendum §4 item 9: never
    /// compared against anything for authorization.
    #[serde(with = "serde_bytes")]
    pub(crate) checkpoint_hash: Vec<u8>,
    pub(crate) delegated_key_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) nonce: Vec<u8>,
    pub(crate) not_after: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) sig: Vec<u8>,
}

/// A `SignedMeshConnectionIntent`, shape-validated on every construction
/// path (including as an embedded field, via `#[serde(try_from, into)]`).
/// Fields are private; read access is via accessors. Signature
/// *mathematical* validity is a separate, explicit step
/// ([`verify_intent_record`]) — a `SignedMeshConnectionIntent` value only
/// proves the wire shape is well-formed, never that the signature is
/// real or that the signer was authorized (same "self-consistency does
/// not authorize" doctrine as `auth_frames`/`delegation`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "SignedMeshConnectionIntentWire",
    into = "SignedMeshConnectionIntentWire"
)]
pub struct SignedMeshConnectionIntent {
    version: u64,
    domain: String,
    hh_id: String,
    initiator_m_id: String,
    initiator_cert_fingerprint: Vec<u8>,
    target_m_id: String,
    target_cert_fingerprint: Vec<u8>,
    checkpoint_hash: Vec<u8>,
    delegated_key_id: String,
    nonce: Vec<u8>,
    not_after: u64,
    sig: Vec<u8>,
}

impl TryFrom<SignedMeshConnectionIntentWire> for SignedMeshConnectionIntent {
    type Error = IntentError;
    fn try_from(w: SignedMeshConnectionIntentWire) -> Result<Self, IntentError> {
        check_intent_header(w.version, &w.domain)?;
        check_nonempty(&w.hh_id)?;
        check_nonempty(&w.initiator_m_id)?;
        check_nonempty(&w.target_m_id)?;
        check_nonempty(&w.delegated_key_id)?;
        check_len(&w.initiator_cert_fingerprint, 32)?;
        check_len(&w.target_cert_fingerprint, 32)?;
        check_len(&w.checkpoint_hash, 32)?;
        check_len(&w.nonce, 32)?;
        check_len(&w.sig, 64)?;
        Ok(Self {
            version: w.version,
            domain: w.domain,
            hh_id: w.hh_id,
            initiator_m_id: w.initiator_m_id,
            initiator_cert_fingerprint: w.initiator_cert_fingerprint,
            target_m_id: w.target_m_id,
            target_cert_fingerprint: w.target_cert_fingerprint,
            checkpoint_hash: w.checkpoint_hash,
            delegated_key_id: w.delegated_key_id,
            nonce: w.nonce,
            not_after: w.not_after,
            sig: w.sig,
        })
    }
}

impl From<SignedMeshConnectionIntent> for SignedMeshConnectionIntentWire {
    fn from(i: SignedMeshConnectionIntent) -> Self {
        SignedMeshConnectionIntentWire {
            version: i.version,
            domain: i.domain,
            hh_id: i.hh_id,
            initiator_m_id: i.initiator_m_id,
            initiator_cert_fingerprint: i.initiator_cert_fingerprint,
            target_m_id: i.target_m_id,
            target_cert_fingerprint: i.target_cert_fingerprint,
            checkpoint_hash: i.checkpoint_hash,
            delegated_key_id: i.delegated_key_id,
            nonce: i.nonce,
            not_after: i.not_after,
            sig: i.sig,
        }
    }
}

impl SignedMeshConnectionIntent {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        hh_id: String,
        initiator_m_id: String,
        initiator_cert_fingerprint: Vec<u8>,
        target_m_id: String,
        target_cert_fingerprint: Vec<u8>,
        checkpoint_hash: Vec<u8>,
        delegated_key_id: String,
        nonce: Vec<u8>,
        not_after: u64,
        sig: Vec<u8>,
    ) -> Result<Self, IntentError> {
        SignedMeshConnectionIntentWire {
            version: INTENT_VERSION,
            domain: INTENT_DOMAIN.to_string(),
            hh_id,
            initiator_m_id,
            initiator_cert_fingerprint,
            target_m_id,
            target_cert_fingerprint,
            checkpoint_hash,
            delegated_key_id,
            nonce,
            not_after,
            sig,
        }
        .try_into()
    }

    pub(crate) fn hh_id(&self) -> &str {
        &self.hh_id
    }
    pub(crate) fn initiator_m_id(&self) -> &str {
        &self.initiator_m_id
    }
    pub(crate) fn initiator_cert_fingerprint(&self) -> &[u8] {
        &self.initiator_cert_fingerprint
    }
    pub(crate) fn target_m_id(&self) -> &str {
        &self.target_m_id
    }
    pub(crate) fn target_cert_fingerprint(&self) -> &[u8] {
        &self.target_cert_fingerprint
    }
    /// Audit only — never compared for authorization (addendum §4 item 9).
    pub(crate) fn checkpoint_hash(&self) -> &[u8] {
        &self.checkpoint_hash
    }
    pub(crate) fn delegated_key_id(&self) -> &str {
        &self.delegated_key_id
    }
    pub(crate) fn nonce(&self) -> &[u8] {
        &self.nonce
    }
    pub(crate) fn not_after(&self) -> u64 {
        self.not_after
    }
    pub(crate) fn sig(&self) -> &[u8] {
        &self.sig
    }
    pub(crate) fn with_sig(mut self, sig: Vec<u8>) -> Self {
        self.sig = sig;
        self
    }
}

/// An opaque, unforgeable intent signing/verification preimage —
/// `I_preimage = 0x06 || I_unsigned` (D9 freeze §2). Only constructor is
/// `pub(crate)`; mirrors `auth_frames::MeshSessionFramePreimage` but is a
/// genuinely distinct type, so a `MeshSessionFrameSigner` still cannot be
/// handed an `AuthFrameBody` preimage where an intent preimage is
/// expected or vice versa — no cross-purpose reuse at the type level.
pub struct IntentSigningPreimage(Vec<u8>);

impl IntentSigningPreimage {
    fn for_intent(intent: &SignedMeshConnectionIntent) -> Result<Self, IntentError> {
        let unsigned = cbor::unsigned_preimage_body(intent)?;
        let mut out = Vec::with_capacity(1 + unsigned.len());
        out.push(INTENT_TYPE_BYTE);
        out.extend(unsigned);
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// `intent_digest = SHA256(ASCII(domain) || I_full)` (D9 freeze §2,
/// addendum §2) — **not** `frame_digest`'s formula: no type byte, and the
/// domain-separation tag is the ASCII domain string, not a leading byte.
/// Computed over `I_full` (canonical CBOR *including* `sig`), so two
/// intents differing only in signature digest differently, same as
/// `frame_digest` for auth frames.
pub(crate) fn intent_digest(intent: &SignedMeshConnectionIntent) -> Result<[u8; 32], IntentError> {
    use sha2::{Digest, Sha256};
    let full = cbor::to_canonical_vec(intent)?;
    let mut hasher = Sha256::new();
    hasher.update(INTENT_DOMAIN.as_bytes());
    hasher.update(&full);
    Ok(hasher.finalize().into())
}

/// Sign an unsigned (placeholder-`sig`) intent with K_mesh and return it
/// with `sig` filled in. Mirrors `auth_frames::sign_frame`'s discipline
/// exactly: propagates a fallible signer's error as-is, then
/// mathematically self-verifies the signer's output against the exact
/// preimage and the signer's own reported public key before ever
/// returning it — a signer bug that returns a syntactically valid,
/// low-S, but wrong-message or wrong-key signature is caught here, not
/// on the wire.
pub(crate) fn sign_intent_record<Sig: MeshSessionFrameSigner>(
    intent: SignedMeshConnectionIntent,
    k_mesh: &Sig,
) -> Result<SignedMeshConnectionIntent, IntentError> {
    let preimage = IntentSigningPreimage::for_intent(&intent)?;
    let sig_bytes = k_mesh
        .sign_intent(&preimage)
        .map_err(|_| IntentError::SignerFailed)?;
    let sig = parse_low_s_signature(&sig_bytes).map_err(map_low_s_error)?;
    k_mesh
        .public_key()
        .verify(preimage.as_bytes(), &sig)
        .map_err(|_| IntentError::SignerProducedInvalidSignature)?;
    Ok(intent.with_sig(sig_bytes.to_vec()))
}

/// Verify an intent's `sig` against `verifier` — pure math, no claim of
/// authority. `pub(crate)`: `auth_state_machine`'s combined check calls
/// this against the SAME verifier already resolved from
/// `Proof-I.delegation().delegated_pub()` (addendum §4 item 3) — never
/// against a key the intent names itself, which would be
/// self-consistency only.
pub(crate) fn verify_intent_record<Ver: MeshSessionFrameVerifier>(
    intent: &SignedMeshConnectionIntent,
    verifier: &Ver,
) -> Result<(), IntentError> {
    let preimage = IntentSigningPreimage::for_intent(intent)?;
    let sig_bytes: [u8; 64] = intent
        .sig()
        .to_vec()
        .try_into()
        .map_err(|_| IntentError::ShapeMismatch)?;
    verifier.verify_intent(&preimage, &sig_bytes)
}

/// `[0x06][canonical CBOR full]` — reuses `wire::encode_typed_frame`
/// (same `MAX_CBOR_BODY_LEN`/canonicality/no-`"type"`-key discipline
/// already applied to the 5 `AuthFrame` types), so no new DoS or
/// canonicality surface is introduced for this record.
pub(crate) fn encode_intent_record(
    intent: &SignedMeshConnectionIntent,
) -> Result<Vec<u8>, IntentError> {
    let body_cbor = cbor::to_canonical_vec(intent)?;
    Ok(crate::wire::encode_typed_frame(
        INTENT_TYPE_BYTE,
        &body_cbor,
    )?)
}

/// Decode `plaintext` as an intent record. Rejects any type byte other
/// than exactly `0x06` — including `0x07` (capability, reserved,
/// unreachable) and `0x01..0x05` (AuthFrame types) — *before* attempting
/// to parse the body as an intent at all (addendum RED #4: type swap
/// rejected).
///
/// Combined check item 1 in full (addendum §4: "domain/version/shape/
/// canonicalidade e low-S do intent"): domain/version/shape come from
/// `TryFrom`, canonicality from `wire::decode_typed_frame`/
/// `cbor::from_canonical_bytes`, and low-S canonicality of the raw
/// signature bytes is checked here too — *shape* only (does the
/// signature parse as a low-S P-256 signature at all), not yet verified
/// against any specific key. The full cryptographic verify against the
/// key resolved from Proof-I's delegation (item 3) is a separate, later
/// step in `run_combined_intent_check` — this function proves the record
/// is not obviously garbage before it is even held in memory tied to the
/// session, nothing more.
pub(crate) fn decode_intent_record(
    plaintext: &[u8],
) -> Result<SignedMeshConnectionIntent, IntentError> {
    let (type_byte, body) = crate::wire::decode_typed_frame(plaintext)?;
    if type_byte != INTENT_TYPE_BYTE {
        return Err(IntentError::UnexpectedTypeByte(type_byte));
    }
    let intent: SignedMeshConnectionIntent =
        cbor::from_canonical_bytes(body).map_err(IntentError::from)?;
    let sig_bytes: [u8; 64] = intent
        .sig()
        .to_vec()
        .try_into()
        .map_err(|_| IntentError::ShapeMismatch)?;
    parse_low_s_signature(&sig_bytes).map_err(map_low_s_error)?;
    Ok(intent)
}

/// Caller-supplied scalar fields for one outbound `SignedMeshConnectionIntent`
/// — already resolved live by the caller (D1 snapshot, D4 generation,
/// nonce mint) before calling in. This crate does not consult a roster,
/// mint nonces, or decide TTL policy itself (same posture as
/// `auth_state_machine::LocalCheckpoint`). `pub(crate)`: only this
/// crate's own tests construct one until a real facade exists.
///
/// **Narrowed 2026-08-04, @kiana, WIP audit item 3:** the initiator's own
/// `hh_id`/`initiator_m_id`/`initiator_cert_fingerprint`/`delegated_key_id`
/// used to be caller-supplied here too, independently of the `local`
/// identity ultimately passed to [`PendingIntent::build_and_sign`] —
/// nothing forced the two to agree at construction, only a set of
/// individually-comparable scalars a later check could verify (or fail to
/// verify identically for two different reasons). Those four fields are
/// now *derived* from `local`/`k_mesh` inside `build_and_sign` itself,
/// never caller-supplied here — there is no way to construct an
/// `IntentDetails` whose initiator-side fields disagree with `local` in
/// the first place.
/// **`checkpoint_hash` removed 2026-08-04, @kiana, WIP audit "exact
/// binding" precision:** derived from the `checkpoint` param
/// [`PendingIntent::build_and_sign`] now takes directly, for the same
/// reason the initiator-side identity fields were removed above — one
/// authoritative source, not a second caller-suppliable copy that could
/// disagree.
pub(crate) struct IntentDetails {
    pub(crate) target_m_id: String,
    pub(crate) target_cert_fingerprint: Vec<u8>,
    pub(crate) nonce: Vec<u8>,
    pub(crate) not_after: u64,
}

/// Opaque, session-bound, single-use token proving a
/// `SignedMeshConnectionIntent` was validly built and signed for THIS
/// specific outbound attempt (2026-08-04, @kiana, integration addendum:
/// raw `ConnectionIntentDigest`/bare ids must never be able to start a
/// handshake — only this token can). Deliberately **not** `Clone`: the
/// only ways to consume it are internal to `run_initiator_handshake`,
/// which takes it by value. No accessor exposes `intent_digest`/
/// `delegated_key_id`/fingerprints/channel directly — they stay private,
/// verified once at construction (shape only; signature math is
/// `sign_intent_record`'s job, already done by the time this token
/// exists), threaded internally.
pub(crate) struct PendingIntent {
    intent: SignedMeshConnectionIntent,
    channel: ExpectedChannel,
    /// SEC1-compressed public key of the signer that actually produced
    /// `intent.sig`, captured at build time (2026-08-04, @kiana, C.5) —
    /// re-checked by [`Self::verify_binds_to`] against the signer/local
    /// identity a handshake is *actually* about to run with, before any
    /// I/O. Without this, nothing prevented a token built against signer
    /// A / identity A from being handed to a handshake call driven by a
    /// different signer B / identity B — `IntentDetails` alone carries no
    /// authority, only a token bound to the exact signer/identity it was
    /// built against does.
    signer_pub: Vec<u8>,
    /// SHA256 of `local.delegation.to_canonical_bytes()`, captured at
    /// build time (2026-08-04, @kiana, WIP audit "exact binding"
    /// precision — supersedes the earlier serial/window-only capture,
    /// which left `roles`/`transcript_kinds`/`profile`/`sig`/
    /// `delegated_pub` etc. uncompared: a substitution that preserved
    /// serial/window/key-id while swapping any of THOSE fields would have
    /// passed). One digest over the FULL canonical encoding stands in for
    /// every field at once — a real implementation cannot satisfy this by
    /// matching some subset of scalars while differing elsewhere.
    delegation_digest: [u8; 32],
    /// The 3 `LocalCheckpoint` scalars not already carried inside the
    /// signed intent itself (only `checkpoint_hash` is signed/audit
    /// there — see [`SignedMeshConnectionIntentWire::checkpoint_hash`]).
    /// Captured so [`Self::verify_binds_to`] can recompare the FULL
    /// 4-scalar checkpoint, not just `hash` (2026-08-04, @kiana, WIP audit
    /// "exact binding" precision).
    checkpoint_sequence: u64,
    checkpoint_event_head: Vec<u8>,
    checkpoint_not_after: u64,
}

fn delegation_digest(delegation: &MeshSessionDelegation) -> Result<[u8; 32], IntentError> {
    use sha2::{Digest, Sha256};
    let canonical = delegation
        .to_canonical_bytes()
        .map_err(|_| IntentError::ShapeMismatch)?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(hasher.finalize().into())
}

impl PendingIntent {
    /// The only constructor. Derives the intent's own initiator-side
    /// fields from `local`, and `checkpoint_hash` from `checkpoint`
    /// (never independently caller-supplied — see [`IntentDetails`]'s
    /// doc), signs it with `k_mesh` (the SAME signer that will also sign
    /// Proof-I — structurally guarantees "same physical key signs both",
    /// addendum §4 item 3), and captures the signer's public key, the
    /// local delegation's full canonical digest, and the checkpoint's
    /// remaining 3 scalars as this token's binding.
    pub(crate) fn build_and_sign<Sig: MeshSessionFrameSigner>(
        details: IntentDetails,
        channel: ExpectedChannel,
        local: &LocalIdentity,
        checkpoint: &crate::auth_state_machine::LocalCheckpoint,
        k_mesh: &Sig,
    ) -> Result<Self, IntentError> {
        let signer_pub = k_mesh
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let delegation_digest_now = delegation_digest(&local.delegation)?;
        let unsigned = SignedMeshConnectionIntent::new(
            local.hh_id.clone(),
            local.m_id.clone(),
            local.cert_fingerprint.clone(),
            details.target_m_id,
            details.target_cert_fingerprint,
            checkpoint.hash.clone(),
            local.delegation.delegated_key_id().to_string(),
            details.nonce,
            details.not_after,
            vec![0u8; 64],
        )?;
        let intent = sign_intent_record(unsigned, k_mesh)?;
        Ok(Self {
            intent,
            channel,
            signer_pub,
            delegation_digest: delegation_digest_now,
            checkpoint_sequence: checkpoint.sequence,
            checkpoint_event_head: checkpoint.event_head.clone(),
            checkpoint_not_after: checkpoint.not_after,
        })
    }

    pub(crate) fn channel(&self) -> ExpectedChannel {
        self.channel
    }

    /// Cross-checks this token's own binding — captured once at
    /// [`Self::build_and_sign`] time — against the signer/local identity/
    /// checkpoint a handshake is actually about to run with (2026-08-04,
    /// @kiana, C.5 + WIP audit "exact binding", widened to a full
    /// canonical delegation digest + all 4 checkpoint scalars). Must be
    /// called before any I/O. `IntentDetails`/a bare
    /// `SignedMeshConnectionIntent` are never accepted as authority on
    /// their own — only a `PendingIntent` whose FULL binding (signer key
    /// bytes, identity scalars, the exact byte-for-byte delegation, and
    /// the exact checkpoint it was built against) matches what the caller
    /// is using right now is allowed to start a handshake.
    pub(crate) fn verify_binds_to<Sig: MeshSessionFrameSigner>(
        &self,
        local: &LocalIdentity,
        checkpoint: &crate::auth_state_machine::LocalCheckpoint,
        k_mesh: &Sig,
        expected_channel: ExpectedChannel,
    ) -> Result<(), IntentError> {
        let signer_pub_now = k_mesh
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        if signer_pub_now != self.signer_pub {
            return Err(IntentError::SignerKeyMismatchPendingIntent);
        }
        if self.intent.hh_id() != local.hh_id
            || self.intent.initiator_m_id() != local.m_id
            || self.intent.initiator_cert_fingerprint() != local.cert_fingerprint.as_slice()
            || self.intent.delegated_key_id() != local.delegation.delegated_key_id()
            || self.channel != expected_channel
        {
            return Err(IntentError::IdentityMismatch);
        }
        // Full canonical delegation digest — one atomic check standing in
        // for every field (roles/transcript_kinds/profile/sig/
        // delegated_pub/serial/window/etc.), not a handful of
        // individually-comparable scalars a substitution could dodge by
        // differing only in a field this crate didn't happen to check.
        if delegation_digest(&local.delegation)? != self.delegation_digest {
            return Err(IntentError::PendingIntentDelegationMismatch);
        }
        if self.intent.not_after() > local.delegation.not_after() {
            return Err(IntentError::TtlInvalid);
        }
        // Checkpoint/authority token binding, all 4 scalars — this is a
        // CONSISTENCY check ("was this token built for the checkpoint we
        // are about to present"), not an authorization check;
        // checkpoint_hash stays audit-only for authorization purposes
        // everywhere else (addendum §4 item 9) — this is a narrower,
        // different use.
        if self.intent.checkpoint_hash() != checkpoint.hash.as_slice()
            || self.checkpoint_sequence != checkpoint.sequence
            || self.checkpoint_event_head != checkpoint.event_head
            || self.checkpoint_not_after != checkpoint.not_after
        {
            return Err(IntentError::PendingIntentCheckpointMismatch);
        }
        Ok(())
    }

    /// Derives `ExpectedResponder` from this token's own (already
    /// validated) target fields — addendum §3: "deriva ExpectedResponder
    /// dessa admissão". The initiator never constructs `ExpectedResponder`
    /// from a second, independently-suppliable source.
    pub(crate) fn expected_responder(&self) -> crate::auth_frames::ExpectedResponder {
        crate::auth_frames::ExpectedResponder {
            hh_id: self.intent.hh_id.clone(),
            m_id: self.intent.target_m_id.clone(),
            cert_fingerprint: self
                .intent
                .target_cert_fingerprint
                .clone()
                .try_into()
                .expect("target_cert_fingerprint is shape-checked to 32 bytes at construction"),
        }
    }

    pub(crate) fn intent(&self) -> &SignedMeshConnectionIntent {
        &self.intent
    }
}

/// Atomic, durable, caller-injected nonce ledger. `pub(crate)` — this
/// crate does not implement D1/D4 persistence itself (2026-08-04,
/// @kiana: "não inventar D1/D4 persistence dentro do core"); a real
/// implementation belongs to whichever crate owns durable state (same
/// precedent as `PairDeviceWindow::with_persistence`, per erratum1 §3).
/// The single call site is the LAST step of the responder's combined
/// intent check (addendum §5) — see `run_responder_handshake`.
/// The exhaustive outcome of one [`IntentNonceLedger::consume`] call
/// (2026-08-04, @kiana, C.2, definitive — replaces the earlier bare
/// `Result<(), IntentError>` shape, which could not distinguish "durably
/// consumed" from "maybe consumed" from "ledger unreachable" and so gave
/// a caller no way to apply different handling to each). Only
/// [`Self::Committed`] permits the ceremony to proceed to Active; the
/// other three all close the session — never a blind retry, and
/// [`Self::MayHaveTakenEffect`] specifically requires a real
/// implementation to reread/reconcile before it may ever be tried again,
/// never assume either outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonceConsumeOutcome {
    /// Consumed for the first time, durably. Exactly one caller ever
    /// observes this for a given key.
    Committed,
    /// A real prior consumption exists (including a concurrent race
    /// winner).
    AlreadyConsumed,
    /// The write itself may or may not have durably landed (e.g. crash
    /// mid-fsync). Never treated as committed — the session must close;
    /// a real implementation must reread/reconcile before this key may be
    /// attempted again, never retry blindly.
    MayHaveTakenEffect,
    /// The ledger itself could not be reached at all (I/O error, not a
    /// commit-outcome question).
    Unavailable,
}

pub(crate) trait IntentNonceLedger {
    /// Atomic check-and-set. `key` is the pure replay identity (erratum1
    /// E2 — never includes `channel`/digest). `not_after` and `digest`
    /// are passed *separately*, not folded into `key`'s own `Eq`/`Hash`
    /// (2026-08-04, @kiana: "not_after... digest como evidência, nunca
    /// como key") — a real implementation needs `not_after` to know how
    /// long to retain the record for eviction, and `digest` only as
    /// audit evidence of *which* intent consumed this nonce, never as
    /// part of what makes two attempts collide.
    ///
    /// `deadline` (2026-08-04, @kiana, C.1) bounds this call: a real
    /// implementation must not block indefinitely on `flock`/`fsync` —
    /// it must itself respect `deadline` and, on expiry/timeout/an
    /// ambiguous ack, return [`NonceConsumeOutcome::MayHaveTakenEffect`]
    /// or [`Self::consume`]-level `Err(DeadlineExceeded)` rather than
    /// hang or silently retry. The caller additionally checks `deadline`
    /// immediately before calling this (C.3): an already-expired deadline
    /// means zero nonce burn is attempted at all.
    ///
    /// Returns [`NonceConsumeOutcome`] on success (including the
    /// non-`Committed` cases — those are ordinary outcomes a caller
    /// matches on, not this method's failure mode); `Err` is reserved for
    /// this call itself failing to produce any outcome (e.g. the deadline
    /// was already exceeded).
    fn consume(
        &self,
        key: &IntentNonceKey,
        not_after: u64,
        digest: &[u8; 32],
        deadline: &CeremonyDeadline,
    ) -> Result<NonceConsumeOutcome, IntentError>;
}

/// **Corrected 2026-08-04, @kiana, addendum erratum1 E2:** the key is
/// `(ledger-domain-v1, hh_id, initiator_m_id, delegated_key_id,
/// intent_nonce)` — the ledger is single per target/household and
/// **shared across `dev`/`release`**, and `intent_digest` never enters
/// the key either. Neither `channel` nor `intent_digest` may appear here:
/// including `channel` would let the *same signed bytes* be replayed
/// once per channel (a channel-aliased double-spend); including the
/// digest would let a *different* intent under the *same* nonce/scope
/// dodge collision instead of failing closed against it — "um nonce
/// repetido com outro digest no mesmo escopo também colide e falha
/// fechado." `channel` stays validated (by the existing delegation gate,
/// on both local and received delegations) but never creates a second
/// nonce slot. `target` is deliberately not part of the key either — the
/// ledger is local to one target, and the combined check already
/// requires `intent.target_m_id == local.m_id` before this key is ever
/// built. A real implementation's persisted key should be prefixed with
/// the fixed literal `"ledger-domain-v1"` to separate this namespace
/// from any other ledger the same store might hold.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct IntentNonceKey {
    pub(crate) hh_id: String,
    pub(crate) initiator_m_id: String,
    pub(crate) delegated_key_id: String,
    pub(crate) nonce: [u8; 32],
}

pub(crate) const LEDGER_DOMAIN: &str = "ledger-domain-v1";

/// Ships no real ledger — always fails closed, so a caller cannot forget
/// to inject a real one and silently get replay "protection" that
/// doesn't exist. Same precedent as `delegation::NoVerifierConfigured`.
pub(crate) struct NoIntentLedgerConfigured;
impl IntentNonceLedger for NoIntentLedgerConfigured {
    fn consume(
        &self,
        _key: &IntentNonceKey,
        _not_after: u64,
        _digest: &[u8; 32],
        _deadline: &CeremonyDeadline,
    ) -> Result<NonceConsumeOutcome, IntentError> {
        Err(IntentError::NoLedgerConfigured)
    }
}

/// A fresh reading of current time — never cached by this crate, called
/// again at each deadline checkpoint (2026-08-04, @kiana, erratum1 E3: a
/// single scalar `now` captured once cannot bound a slow-loris that
/// trickles bytes across many blocking reads; only a clock consulted
/// again at each checkpoint can). This crate does not implement a real
/// clock/timer subsystem — same "não inventar... dentro do core" posture
/// as the nonce ledger and D1 admission.
pub(crate) trait Clock {
    fn now(&self) -> Result<u64, IntentError>;
}

/// Ships no real clock — fails closed. Same precedent as
/// `NoIntentLedgerConfigured`/`NoD1AdmissionConfigured`.
pub(crate) struct NoClockConfigured;
impl Clock for NoClockConfigured {
    fn now(&self) -> Result<u64, IntentError> {
        Err(IntentError::ClockUnavailable)
    }
}

/// Two-stage D1 admission hook (2026-08-04, @kiana, D1 seam erratum +
/// erratum1 E4): registering a session and opening forwarding must never
/// be tied to `ActivateAck`'s write succeeding in one step — a
/// concurrent revoke landing between "Ack write succeeded" and "session
/// marked Active" must still be able to close the session before
/// forwarding ever opens. This crate models the SEAM only; no real D1
/// persistence, locking, or revision tracking lives here.
///
/// Ordering enforced by `run_responder_handshake`, not by this trait's
/// signature alone (erratum1 E4):
///
/// - Step 1, [`Self::reserve_pending`]: a real implementation does the
///   exact final D1 revision/snapshot recheck here and inserts the
///   session as `Pending` (forwarding gate CLOSED), returning an opaque,
///   `!Clone` permit conceptually bound to `(session_id, peer_m_id,
///   exact_revision)` — this crate only sees `Self::Pending`, an
///   associated type, and never inspects its contents. Called BEFORE the
///   `ActivateAck` write; a real implementation must not hold any
///   registry mutex across that write, but a concurrent revoke must not
///   be able to *complete* while the permit is alive either (an
///   admission barrier, not a lock held across I/O).
/// - Step 2: `ActivateAck` `write_all`, executed exactly once.
/// - Step 3, write succeeds: [`Self::activate_if_authorized`] runs
///   IMMEDIATELY, with no other fallible or external operation between
///   the write's success and this call (`run_responder_handshake`
///   enforces this by construction, not this trait) — atomic; either
///   opens Active/forwarding under the registry's synchronized state, or
///   a concurrent revoke observed in the meantime closes it instead.
///   Either outcome is terminal and consumes the permit. Releasing the
///   barrier here lets any revoke that was waiting on it proceed
///   immediately afterward.
/// - Step 3, write fails/times out: [`Self::cancel_pending`] aborts and
///   removes the Pending entry, keeps the gate closed, and releases the
///   barrier — nothing ever becomes Active for this attempt.
///
/// No DATA is ever delivered against a `Pending` gate, and no session
/// exists without being tracked under one of these two terminal outcomes
/// — there is no third path.
///
/// **`ActiveGate`, embedded not tupled (2026-08-04, @kiana, definitive —
/// supersedes the earlier tuple-return formulation):** `activate_if_authorized`
/// returning bare `()` left nothing for the caller to retain — once
/// `run_responder_handshake` returned, there was no live handle a later
/// revoke could act on and nothing an eventual DATA path could check.
/// `activate_if_authorized` returns an opaque `Self::ActiveGate`, which
/// the handshake function moves *immediately* into a private field of the
/// `ActiveMeshSession` it constructs — never returned as a second tuple
/// element, never exposed via any accessor. Dropping the session runs
/// `G`'s own `Drop` (whatever unregister/revoke semantics the real D1
/// implementation gives its gate type), so a session can never be
/// separated from its gate while still claiming to be usable. `Pending`/
/// `ActiveGate` are not `Clone`-bound at the trait level (Rust has no
/// stable "not Clone" bound); this crate's own calling code never clones
/// either — each value is moved into exactly one of
/// `activate_if_authorized`/`cancel_pending`, enforced by the borrow
/// checker at each call site, not by convention.
///
/// **`deadline` on every method (2026-08-04, @kiana, C.1):** a real
/// implementation must not block indefinitely on `flock`/`fsync` or an
/// ambiguous concurrent-revoke race; it must respect `deadline` itself
/// and fail closed (never transition to Active) on expiry or an
/// indeterminate outcome.
pub(crate) trait D1Admission {
    type Pending;
    type ActiveGate;

    /// Step 1 — see the ordering note above. A real implementation
    /// re-verifies the *exact same* binding (`D1AdmissionKey`'s full
    /// session_id/authenticated-fingerprint/delegated-pub/checkpoint
    /// fields — not merely a fresh read keyed by `initiator_m_id` alone,
    /// which would let a stale or substituted fingerprint/revision slip
    /// through) both here and again before committing in
    /// [`Self::activate_if_authorized`] — the latter only ever receives
    /// the opaque `Self::Pending` this call returned, so a real
    /// implementation's own internal state must carry the binding
    /// forward rather than re-deriving a weaker one from scratch.
    fn reserve_pending(
        &self,
        key: &D1AdmissionKey,
        deadline: &CeremonyDeadline,
    ) -> Result<Self::Pending, IntentError>;
    fn activate_if_authorized(
        &self,
        pending: Self::Pending,
        deadline: &CeremonyDeadline,
    ) -> Result<Self::ActiveGate, IntentError>;
    /// **`Result`-returning (2026-08-04, @kiana, WIP audit item (b)) —
    /// cleanup here is not best-effort-silent.** An earlier `-> ()`
    /// signature gave a real implementation no way to signal "I could not
    /// confirm this cancellation actually landed" — most concretely, if
    /// `deadline` is already expired by the time this runs, a real
    /// implementation might not be able to reach its own registry/lock at
    /// all, yet `()` forced it to either block anyway (exactly what this
    /// trait exists to forbid) or silently return as if cleanup
    /// succeeded, potentially leaving a `Pending` entry stranded. `Err`
    /// here means "cancellation could not be confirmed" — a caller
    /// receiving it must still treat the attempt as closed/never-Active
    /// (the caller never had an `ActiveGate` to begin with; there is
    /// nothing to activate), but should surface/log the ambiguity rather
    /// than assume the registry is clean, since a real implementation may
    /// need out-of-band reconciliation for a `Pending` it could not
    /// positively confirm removing.
    ///
    /// **`Self::Pending` must itself be Drop-idempotent-safe (2026-08-04,
    /// @kiana, WIP audit item (b), required):** because `pending` is
    /// taken *by value*, an `Err` return here does NOT hand the token
    /// back — it is already moved into (and, ordinarily, consumed/dropped
    /// by) this call. A `Result` return alone would therefore let a
    /// cancel failure silently strand a registry entry with nothing left
    /// for any caller to act on. This crate cannot itself enforce a
    /// "must impl `Drop`" bound on an associated type (Rust has no such
    /// bound), so it is a documented requirement on every real
    /// `Self::Pending`: dropping a `Pending` value that never reached
    /// [`Self::activate_if_authorized`] — including via a partially- or
    /// fully-failed `cancel_pending` call — MUST itself trigger the same
    /// unregister/close effect, idempotently (safe whether or not
    /// `cancel_pending` also ran). `cancel_pending`'s own `Result` is a
    /// best-effort synchronous confirmation signal, never the sole
    /// cleanup mechanism; the type's own `Drop` is the structural safety
    /// net that guarantees nothing is ever truly lost.
    fn cancel_pending(
        &self,
        pending: Self::Pending,
        deadline: &CeremonyDeadline,
    ) -> Result<(), IntentError>;
}

/// The exact binding D1 admission is granted against (2026-08-04, @kiana,
/// C.4, definitive — replaces the earlier "scalar bag" shape that carried
/// only `hh_id`/`initiator_m_id`/`target_m_id`/`delegated_key_id`/
/// `channel`, none of it AUTHENTICATED beyond what a peer merely claimed
/// in its own frame). `session_id` is this ceremony's own `h_final` — the
/// Noise handshake hash, unique per completed handshake and bound to both
/// parties' keys and full transcript — so admission can never be
/// carried over to a different ceremony by coincidence of matching
/// `m_id`.
///
/// **`local_*`/`peer_*`, not `initiator_*`/`target_*` (2026-08-04, @kiana,
/// WIP audit — role-neutral, definitive):** the earlier `initiator_*`/
/// `target_*` naming was responder-shaped — on the responder side
/// `initiator_*` names the PEER and `target_*` names local, but on the
/// initiator side that flips (`initiator_*` names local, `target_*` names
/// the peer). Reusing those names unchanged on the initiator side meant
/// mechanically re-mapping which physical party each field held per call
/// site, exactly the kind of swap-prone shape a future edit could get
/// backwards. `local_*`/`peer_*` are unconditionally symmetric: `local_*`
/// is always this function's own `LocalIdentity`, `peer_*` is always the
/// other party, on both call sites, so both construction sites should
/// look structurally identical modulo which concrete values they read
/// from. `peer_cert_fingerprint` is the AUTHENTICATED fingerprint already
/// verified via `pass_delegation_gate`/`verify_frame`, not a bare claim.
///
/// **`delegated_key_id`/`delegated_pub` stay protocol-role-scoped, NOT
/// local/peer-scoped:** these always name *the initiator's* delegation —
/// the party that actually signed the 0x06 intent — regardless of
/// whether the initiator is `local` or the `peer` in this particular
/// call. Renaming these to `local_*`/`peer_*` would be actively wrong on
/// the responder side, where they name the peer's (not local's)
/// delegation. `delegated_pub` lets a real implementation bind to the
/// actual key bytes, not just the `delegated_key_id` label.
///
/// The checkpoint/`not_after` fields let `reserve_pending`/
/// `activate_if_authorized` recheck the identical revision/expiry, not a
/// fresh unrelated read. A real implementation must recheck this WHOLE
/// binding at both `reserve_pending` and `activate_if_authorized` time —
/// re-reading only `peer_m_id` and forgetting the rest (fingerprint,
/// revision, delegated key) is exactly the gap this richer key exists to
/// close.
///
/// **`checkpoint_hash`/`checkpoint_sequence` are the D1-registry-relevant
/// revision (2026-08-04, @kiana, WIP audit correction — supersedes an
/// earlier framing of this as a strict 4-scalar requirement):**
/// `checkpoint_event_head`/`checkpoint_not_after` are carried too, as
/// useful additional hardening (a real implementation gets to recheck the
/// FULL live `LocalCheckpoint`, not just the 2 fields D1 registry
/// admission strictly needs), but only `hash`/`sequence` are the actual
/// "revisão D1 vigente" this key must bind to — `event_head`/`not_after`
/// are already covered by this ceremony's own separate auth checks
/// (`check_checkpoint` against the peer's claimed values) before this key
/// is ever built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1AdmissionKey {
    pub(crate) session_id: Vec<u8>,
    pub(crate) hh_id: String,
    pub(crate) local_m_id: String,
    pub(crate) local_cert_fingerprint: Vec<u8>,
    pub(crate) peer_m_id: String,
    pub(crate) peer_cert_fingerprint: Vec<u8>,
    pub(crate) delegated_key_id: String,
    pub(crate) delegated_pub: Vec<u8>,
    pub(crate) checkpoint_hash: Vec<u8>,
    pub(crate) checkpoint_sequence: u64,
    pub(crate) checkpoint_event_head: Vec<u8>,
    pub(crate) checkpoint_not_after: u64,
    pub(crate) not_after: u64,
    pub(crate) channel: ExpectedChannel,
}

/// Ships no real D1 wiring. `Pending = Infallible` — fail-closed *by
/// type*, not by decision: `reserve_pending` always errs, so
/// `activate_if_authorized`/`cancel_pending` are structurally
/// unreachable (an uninhabited-type match), not merely convention.
pub(crate) struct NoD1AdmissionConfigured;
impl D1Admission for NoD1AdmissionConfigured {
    type Pending = std::convert::Infallible;
    type ActiveGate = std::convert::Infallible;

    fn reserve_pending(
        &self,
        _key: &D1AdmissionKey,
        _deadline: &CeremonyDeadline,
    ) -> Result<Self::Pending, IntentError> {
        Err(IntentError::NoD1AdmissionConfigured)
    }
    fn activate_if_authorized(
        &self,
        pending: Self::Pending,
        _deadline: &CeremonyDeadline,
    ) -> Result<Self::ActiveGate, IntentError> {
        match pending {}
    }
    fn cancel_pending(
        &self,
        pending: Self::Pending,
        _deadline: &CeremonyDeadline,
    ) -> Result<(), IntentError> {
        match pending {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_key() -> D1AdmissionKey {
        D1AdmissionKey {
            session_id: vec![1u8; 32],
            hh_id: "hh-1".to_string(),
            local_m_id: "m-local".to_string(),
            local_cert_fingerprint: vec![0xAAu8; 32],
            peer_m_id: "m-peer".to_string(),
            peer_cert_fingerprint: vec![0xBBu8; 32],
            delegated_key_id: "key-1".to_string(),
            delegated_pub: vec![0x02u8; 33],
            checkpoint_hash: vec![0xCCu8; 32],
            checkpoint_sequence: 7,
            checkpoint_event_head: vec![0xDDu8; 32],
            checkpoint_not_after: 2_000,
            not_after: 1_000,
            channel: ExpectedChannel::Dev,
        }
    }

    /// WIP audit item (1) RED: a key differing only in
    /// `checkpoint_event_head` must not compare equal.
    #[test]
    fn red_d1_admission_key_distinguishes_a_checkpoint_event_head_swap() {
        let a = base_key();
        let mut b = a.clone();
        b.checkpoint_event_head = vec![0xEEu8; 32];
        assert_ne!(a, b);
    }

    /// WIP audit item (1) RED: a key differing only in
    /// `checkpoint_not_after` must not compare equal.
    #[test]
    fn red_d1_admission_key_distinguishes_a_checkpoint_not_after_swap() {
        let a = base_key();
        let mut b = a.clone();
        b.checkpoint_not_after = a.checkpoint_not_after + 1;
        assert_ne!(a, b);
    }

    /// C.4 RED: a D1AdmissionKey that differs ONLY in the authenticated
    /// peer fingerprint (same m_id) must not be treated as the same
    /// binding — proves this crate's key type can actually distinguish a
    /// fingerprint swap rather than silently coalescing distinct
    /// authenticated identities down to `m_id` alone.
    #[test]
    fn red_d1_admission_key_distinguishes_a_fingerprint_swap_at_same_m_id() {
        let a = base_key();
        let mut b = a.clone();
        b.peer_cert_fingerprint = vec![0xFFu8; 32];
        assert_ne!(a, b);
    }

    /// C.4 RED: a key differing only in checkpoint_sequence (a revision
    /// swap) must likewise not compare equal.
    #[test]
    fn red_d1_admission_key_distinguishes_a_revision_swap() {
        let a = base_key();
        let mut b = a.clone();
        b.checkpoint_sequence = a.checkpoint_sequence + 1;
        assert_ne!(a, b);
    }

    /// C.4 RED: a key differing only in session_id (a different ceremony
    /// entirely) must not compare equal — admission must not carry over
    /// across ceremonies by m_id coincidence.
    #[test]
    fn red_d1_admission_key_distinguishes_a_different_session() {
        let a = base_key();
        let mut b = a.clone();
        b.session_id = vec![2u8; 32];
        assert_ne!(a, b);
    }
}
