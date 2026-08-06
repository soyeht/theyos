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
/// `pub` (2026-08-04, @kiana, WIP audit, seam-visibility correction — a
/// `pub(crate)` trait/enum cannot be implemented/matched on from a real,
/// different-crate `IntentNonceLedger` adapter at all; Rust visibility
/// requires the trait, its associated types, and everything in its method
/// signatures to be at least as visible as the impl needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceConsumeOutcome {
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

/// `pub` (2026-08-04, @kiana, WIP audit, seam-visibility correction) —
/// see [`NonceConsumeOutcome`]'s doc.
pub trait IntentNonceLedger {
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
    ///
    /// **`channel` (2026-08-04, @kiana, WIP audit, runtime-integration
    /// mismatch):** a real implementation persists an evidence record
    /// (e.g. household's `MeshIntentNonceEvidence { channel, digest,
    /// not_after }`) that includes the channel this ceremony ran under —
    /// same status as `not_after`/`digest`: audit/storage EVIDENCE, never
    /// part of the key's own `Eq`/`Hash` (erratum1 E2 still holds: folding
    /// `channel` into the key would let the same signed bytes replay once
    /// per channel).
    ///
    /// **Restart/durability contract (2026-08-04, @kiana, runtime-facade
    /// audit `3cbbfb37…`, item 7e — explicitly left to a real
    /// implementation, not over-claimed here; this crate ships only the
    /// in-memory `HashSet`-backed test double, which does NOT satisfy
    /// this):**
    ///
    /// - A [`Self::Committed`] record must survive process restart. A
    ///   nonce consumed before a crash, replayed after the process comes
    ///   back up, must return [`NonceConsumeOutcome::AlreadyConsumed`],
    ///   never [`NonceConsumeOutcome::Committed`] a second time — a
    ///   purely in-memory ledger (this crate's own [`NoIntentLedgerConfigured`]
    ///   aside, which never commits anything) is fail-open across a
    ///   restart and is not a valid production implementation.
    /// - A [`Self::Committed`] outcome is never rolled back by a LATER
    ///   step of the same ceremony failing. If `run_responder_handshake`
    ///   returns `Err` after `consume` already returned `Committed` (e.g.
    ///   the subsequent `ActivateAck` write fails), the nonce stays
    ///   burned — there is no compensating "un-consume" operation in this
    ///   trait, and a real implementation must not invent one. This is
    ///   deliberate, not an oversight: an attacker who can force a
    ///   post-consume failure must not be able to recover a fresh attempt
    ///   at the same nonce.
    /// - [`Self::MayHaveTakenEffect`] is a genuinely three-valued outcome,
    ///   not "assume not consumed and retry": a real implementation must
    ///   reread its own durable state before this exact key is ever
    ///   attempted again, and if that reread itself cannot definitively
    ///   resolve the ambiguity, it must keep returning
    ///   `MayHaveTakenEffect` (or `Unavailable`) rather than guessing
    ///   `Committed`. This crate's own test doubles (`InMemoryLedger` in
    ///   `auth_state_machine`'s tests, the `SharedLedger` double proving
    ///   concurrent-attempt exclusivity) exercise only the SEAM's shape —
    ///   neither is durable, and neither proves any real backend's actual
    ///   crash-recovery behavior.
    fn consume(
        &self,
        key: &IntentNonceKey,
        not_after: u64,
        digest: &[u8; 32],
        channel: crate::auth_state_machine::ExpectedChannel,
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
/// `pub` with private fields + read-only accessors (2026-08-04, @kiana,
/// WIP audit, seam-visibility correction): a real `IntentNonceLedger`
/// adapter needs to read this key's identity to persist/look it up, but
/// only this crate's own handshake code may construct one — matching the
/// crate-wide "typed facade, opaque requests/read-only getters, never a
/// caller-suppliable arbitrary constructor" discipline.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IntentNonceKey {
    hh_id: String,
    initiator_m_id: String,
    delegated_key_id: String,
    nonce: [u8; 32],
}

impl IntentNonceKey {
    pub(crate) fn new(
        hh_id: String,
        initiator_m_id: String,
        delegated_key_id: String,
        nonce: [u8; 32],
    ) -> Self {
        Self {
            hh_id,
            initiator_m_id,
            delegated_key_id,
            nonce,
        }
    }

    pub fn hh_id(&self) -> &str {
        &self.hh_id
    }
    pub fn initiator_m_id(&self) -> &str {
        &self.initiator_m_id
    }
    pub fn delegated_key_id(&self) -> &str {
        &self.delegated_key_id
    }
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
}

pub const LEDGER_DOMAIN: &str = "ledger-domain-v1";

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
        _channel: crate::auth_state_machine::ExpectedChannel,
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
/// `pub` (2026-08-04, @kiana, WIP audit, seam-visibility correction) —
/// see [`NonceConsumeOutcome`]'s doc.
///
/// **Contractually non-blocking (2026-08-04, @kiana, runtime-facade audit
/// `3cbbfb37…` P1-1):** called mid-ceremony, after the official
/// `CeremonyDeadline` has already been checked for that step but before
/// it is checked again — a `now()` that blocks indefinitely (e.g. on a
/// slow NTP round trip) would never reach a subsequent deadline check at
/// all. A real implementation must read a local, already-synchronized
/// clock and return in bounded, effectively-constant time; `Err` (never a
/// block) is the correct response to "no reliable time source right
/// now" (mirroring `require_reliable_time_floor`-style designs
/// elsewhere in this system).
pub trait Clock {
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

/// Outcome of [`D1Pending::cancel_before_ack`] (2026-08-04, @kiana,
/// runtime-facade audit `3cbbfb37…`, items 1+3 — replaces the earlier
/// `Result<(), IntentError>` `cancel_pending` signature). Authority is
/// closed in **every** variant before any of them is even computed — a
/// real implementation's token closes its own phase (an atomic CAS) as
/// the unconditional first step of cancellation, never gated on whether
/// the registry lock can be acquired. These variants describe only what
/// happened to the *bookkeeping entry*, never whether the session can
/// still forward (it structurally cannot, in every variant).
///
/// Verified directly against the real household-rs D1 registry
/// (`mesh_session_registry.rs`, worktree `goal/d1-pending-admission-v1`
/// @ `d721f889`, `PendingCancelOutcome`): its three variants
/// (`ClosedAndRemoved`/`ClosedCleanupDeferred`/`RegistryUnavailable`) map
/// 1:1 to the three here — this crate's names are chosen to read
/// correctly for any adapter, not just that one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum D1CancelOutcome {
    /// Authority closed, and the tracking entry was removed.
    CancelledAndRemoved,
    /// Authority closed, but the registry's bookkeeping was busy (e.g. a
    /// non-blocking lock attempt lost) — NOT an error and NOT an
    /// authority gap: the session cannot forward, and a later registry
    /// operation (or an explicit reconcile sweep) removes the stale
    /// entry. The barrier this permit held is still released.
    BarrierReleasedBookkeepingDeferred,
    /// Authority closed, but the registry itself is unavailable
    /// (`Unavailable`/poisoned), so no per-session bookkeeping could run
    /// at all.
    RegistryUnavailable,
}

/// The terminal operations on a reserved-but-not-yet-decided D1 admission
/// permit (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…`, items
/// 1+2+3 — replaces the earlier `D1Admission::activate_if_authorized`/
/// `cancel_pending` methods). Generic over `Active`, the type this
/// specific `Self` commits into — see [`D1Admission::Pending`]'s doc for
/// why this is a type *parameter* here rather than an associated type of
/// this trait: it lets [`D1Admission`] force, at the trait-bound level,
/// that whatever `Active<'a>` a `Pending<'a>` commits into is the SAME
/// `'a` the permit itself borrowed, for every lifetime at once — not a
/// convention an adapter author could get wrong.
///
/// **`commit_after_ack` is infallible and takes no deadline — on
/// purpose, definitively (2026-08-04, @kiana, runtime-facade audit
/// `3cbbfb37…` P0-1/P0-4, P0-2's closure criterion 2):** the earlier
/// `activate_if_authorized(self, deadline) -> Result<ActiveGate,
/// IntentError>` shape allowed a real implementation to refuse — with a
/// real roster/revision/membership recheck, and a real deadline check —
/// AFTER the peer already held a complete, valid `ActivateAck`. That is
/// exactly the split-brain the audit's P0-1 finding proved: the peer
/// believes the session is Active (it received a fully-written,
/// fully-valid Ack), while a local refusal at that point would leave
/// this side denying it. Verified directly against the real registry
/// (`PendingSessionAdmission::commit_after_ack`, same file/commit as
/// above): it takes `self` by value, returns `ActiveSessionRegistration`
/// directly (no `Result`, no deadline parameter), does no roster
/// recheck, takes no lock, and is NOT vetoed by an already-announced
/// revoke — its own doc explains why that is safe: an announced revoke
/// has already raised a lock-free counter that this crate's own
/// `try_authorize_forwarding`-equivalent rejects on *before* it ever
/// looks at Active/Closed, so the interval between commit and a
/// revoker's subsequent close admits no forwarding regardless of commit
/// having "succeeded" past the revoke's announcement. Call this as the
/// very next statement after the write that completed the Ack — see the
/// dedicated terminal-Ack helper this crate's own handshake functions
/// use, not the general frame-send functions.
///
/// **`cancel_before_ack` returns [`D1CancelOutcome`] directly, not
/// `Result<D1CancelOutcome, IntentError>`:** there is no distinct
/// "the call itself failed" case to report — every real outcome
/// (including "the registry was unreachable") is itself one of
/// [`D1CancelOutcome`]'s variants, matching the real
/// `cancel_before_ack(self) -> PendingCancelOutcome` signature exactly.
///
/// **`Self` must itself be Drop-idempotent-safe, lock-free, and
/// callback-free (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…`
/// P0-3, required):** because both terminal methods take `self` by
/// value, a permit that is simply dropped without calling either — a
/// panic unwind, an early return via `?` before either is reached —
/// still needs a defined, safe outcome. This crate cannot express a
/// "must impl `Drop`, and that `Drop` must be lock-free" bound on a GAT
/// (Rust has no such bound), so it is a documented requirement on every
/// real `Pending<'a>`: dropping one that never reached either terminal
/// method MUST close authority idempotently, and — verified against the
/// real `PendingSessionAdmission`'s own `Drop` — that closure must be
/// EXACTLY "one atomic CAS plus a wake, nothing else": no mutex
/// acquisition, no wait, no `Weak`/handle upgrade, no call into any
/// caller-supplied callback, no allocation. Everything that could block
/// or re-enter is therefore structurally absent, which is what lets it
/// run safely from a panic unwind and while other locks this same
/// registry owns are held by other threads. See
/// `red_pending_drop_never_blocks_even_while_a_shared_mutex_the_double_also_holds_is_locked_elsewhere`
/// below for a non-vacuous RED against a borrowed double proving exactly
/// this — not merely documented, actually measured.
pub trait D1Pending<Active> {
    fn commit_after_ack(self) -> Active;
    #[must_use]
    fn cancel_before_ack(self) -> D1CancelOutcome;
}

/// Two-stage D1 admission hook (2026-08-04, @kiana, D1 seam erratum +
/// erratum1 E4 + runtime-facade audit `3cbbfb37…` items 1+2+3): registering
/// a session and opening forwarding must never be tied to `ActivateAck`'s
/// write succeeding in one step — a concurrent revoke landing between "Ack
/// write succeeded" and "session marked Active" must still be able to
/// close the session before forwarding ever opens. This crate models the
/// SEAM only; no real D1 persistence, locking, or revision tracking lives
/// here.
///
/// **`Pending<'a>` is a GAT, not a plain associated type (2026-08-04,
/// @kiana, runtime-facade audit `3cbbfb37…` P0-2, definitive):** the real
/// token this seam must be implementable against,
/// `PendingSessionAdmission<'registry, H>` (household-rs
/// `mesh_session_registry.rs`, worktree `goal/d1-pending-admission-v1` @
/// `d721f889`), *borrows* `&'registry MeshSessionRegistry<H>` — there is
/// no single lifetime a non-generic `type Pending;` could name that fits
/// every call. `Active<'a>` is a GAT for the identical reason: the real
/// terminal type, `ActiveSessionRegistration<'registry, H>`, borrows the
/// SAME `'registry`. Both live directly on this trait — not `Active` as a
/// plain associated type of [`D1Pending`] — specifically so the bound
/// below can force them to share one lifetime:
///
/// ```text
/// type Pending<'a>: D1Pending<Self::Active<'a>> where Self: 'a;
/// type Active<'a> where Self: 'a;
/// ```
///
/// A real implementor's `Pending<'a>` MUST commit into that same-`'a`
/// `Active<'a>` — not some unrelated or `'static` type — because the
/// trait bound states it structurally, at the type-system level, not as
/// documentation an adapter author could satisfy incorrectly. This is
/// what lets `run_responder_handshake`/`run_initiator_handshake` carry
/// `D1::Active<'d1>` all the way into `ActiveMeshSession` without ever
/// needing to erase or re-box the borrow.
///
/// Ordering enforced by `run_responder_handshake`/`run_initiator_handshake`,
/// not by this trait's signature alone (erratum1 E4):
///
/// - Step 1, [`Self::reserve_pending`]: a real implementation does the
///   exact final D1 revision/membership recheck here and inserts the
///   session as `Pending` (forwarding gate CLOSED), returning an opaque,
///   `!Clone` permit borrowed for `'a` — this crate only sees
///   `Self::Pending<'a>` and never inspects its contents. Called BEFORE
///   the `ActivateAck` write; a real implementation must not hold any
///   registry mutex across that write, but a concurrent revoke must not
///   be able to *complete* while the permit is alive either (an
///   admission barrier, not a lock held across I/O).
/// - Step 2: `ActivateAck` `write_all`, executed exactly once, via this
///   crate's dedicated terminal-Ack helper.
/// - Step 2 succeeds: [`D1Pending::commit_after_ack`] runs IMMEDIATELY,
///   infallibly, with no other fallible or external operation between the
///   write's success and this call — see that method's own doc for why
///   it is infallible and unvetoed by an already-announced revoke.
/// - Step 2 fails/times out (partial write, or the read side never
///   observes a complete valid Ack): [`D1Pending::cancel_before_ack`]
///   aborts and removes the Pending entry, keeps the gate closed, and
///   releases the barrier — nothing ever becomes Active for this
///   attempt. The returned [`D1CancelOutcome`] is folded into the
///   propagated error, never discarded (`3cbbfb37…` P0-3).
///
/// No DATA is ever delivered against a `Pending` gate, and no session
/// exists without being tracked under one of these two terminal outcomes
/// — there is no third path.
///
/// This is genuinely, positively implementable from outside the crate —
/// not just something that survives a `compile_fail` negative check —
/// because the doctest below actually compiles a real external-style
/// `impl` against an owned double. A fuller, *borrowed*-lifetime double
/// whose `Drop` mutates a shared `Atomic` (proving the GAT shape is
/// satisfiable by something that actually borrows, the way the real
/// household token does) lives as a non-vacuous `#[test]` in this
/// module's test suite, not a doctest, so it can assert on outcomes.
///
/// ```
/// use mesh_session_core_rs::intent::{D1Admission, D1CancelOutcome, D1MembershipKey, D1Pending};
/// use mesh_session_core_rs::ingress::CeremonyDeadline;
/// use mesh_session_core_rs::error::IntentError;
///
/// // A real adapter (e.g. household-rs's MeshSessionRegistry) would wrap
/// // its own registry/lock/session-table state here instead.
/// struct ExternalAdapter;
///
/// struct OwnedPending(u64);
/// impl D1Pending<u64> for OwnedPending {
///     fn commit_after_ack(self) -> u64 {
///         self.0 // a real adapter's own opaque gate value
///     }
///     fn cancel_before_ack(self) -> D1CancelOutcome {
///         D1CancelOutcome::CancelledAndRemoved
///     }
/// }
///
/// impl D1Admission for ExternalAdapter {
///     type Pending<'a> = OwnedPending;
///     type Active<'a> = u64; // a real adapter's own opaque gate type
///
///     fn reserve_pending<'a>(
///         &'a self,
///         key: &D1MembershipKey,
///         deadline: &CeremonyDeadline,
///     ) -> Result<Self::Pending<'a>, IntentError> {
///         // A real implementation reads `key`'s accessors (session_id(),
///         // peer_m_id(), checkpoint_hash(), ...) and
///         // `deadline.remaining()`/`is_expired()` to do its own D1
///         // revision recheck and admission-barrier insert here.
///         let _ = (key.session_id(), deadline.is_expired());
///         Ok(OwnedPending(1))
///     }
/// }
///
/// let _adapter = ExternalAdapter; // compiles: the trait is usable from outside
/// ```
pub trait D1Admission {
    type Pending<'a>: D1Pending<Self::Active<'a>>
    where
        Self: 'a;
    type Active<'a>
    where
        Self: 'a;

    /// Step 1 — see the ordering note above. A real implementation
    /// verifies the *exact same* binding here (`D1MembershipKey`'s full
    /// session_id/authenticated-fingerprint/checkpoint fields — not
    /// merely a fresh read keyed by `peer_m_id` alone, which would let a
    /// stale or substituted fingerprint/revision slip through). This is
    /// the ONLY point that check runs (2026-08-04, @kiana, runtime-facade
    /// audit `3cbbfb37…` CFX-2, correction — supersedes an earlier,
    /// contradictory version of this doc that said "both here and again
    /// before committing in `commit_after_ack`"): `commit_after_ack` is
    /// infallible and performs no roster/revision/membership recheck at
    /// all — see its own doc for why re-litigating this exact question
    /// there would be wrong, not merely redundant. A real implementation's
    /// own internal state must carry the reserved binding forward from
    /// this call into the `Self::Pending<'a>` value it returns, rather
    /// than re-deriving a weaker one from scratch or expecting a second
    /// check to catch what this one missed.
    fn reserve_pending<'a>(
        &'a self,
        key: &D1MembershipKey,
        deadline: &CeremonyDeadline,
    ) -> Result<Self::Pending<'a>, IntentError>;
}

/// The exact binding D1 *membership* admission is granted against
/// (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…` P0-5/item 4,
/// definitive — replaces `D1AdmissionKey`, which mixed this with D4
/// signer authority; see [`IntentSignerBinding`] for that half).
/// `session_id` is this ceremony's own `h_final` — the Noise handshake
/// hash, unique per completed handshake and bound to both parties' keys
/// and full transcript — so admission can never be carried over to a
/// different ceremony by coincidence of matching `m_id`.
///
/// **Shape verified directly against the real D1 registry's own binding
/// type, not guessed (2026-08-04, @kiana, runtime-facade audit
/// `3cbbfb37…` P0-5):** `household-rs`'s `SealedBinding`
/// (`machine_roster_authority.rs`, same worktree/commit as
/// [`D1Admission`]'s doc) carries exactly `hh_id`, one `m_id`, one
/// `machine_cert_fingerprint`, `checkpoint_hash`, `checkpoint_sequence` —
/// a single peer identity, not a local/peer pair, and no
/// delegation/channel/expiry fields at all. D1 registry membership is
/// never asked to know or verify *this machine's own* identity — only
/// whether the PEER is active, non-revoked, and fingerprint-matched at
/// the exact revision — so `local_m_id`/`local_cert_fingerprint` (present
/// in the old `D1AdmissionKey`) are dropped here rather than carried as
/// dead weight a real adapter would never read.
/// `checkpoint_event_head`/`checkpoint_not_after`/`expires_at` are
/// likewise dropped: `SealedBinding` only ever compares
/// `checkpoint_hash`/`checkpoint_sequence` against its own tracked
/// revision, and the other three are already covered by this ceremony's
/// own separate auth checks (`check_checkpoint` against the peer's
/// claimed values, `effective_expires_at`) before this key is ever
/// built — carrying them here would be data a real D1 registry adapter
/// has no read site for.
/// `pub` with private fields + read-only accessors (same discipline as
/// [`IntentNonceKey`]): a real `D1Admission` adapter needs to read this
/// binding to persist/recheck it, but only this crate's own handshake
/// code may construct one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D1MembershipKey {
    session_id: Vec<u8>,
    hh_id: String,
    peer_m_id: String,
    peer_cert_fingerprint: Vec<u8>,
    checkpoint_hash: Vec<u8>,
    checkpoint_sequence: u64,
}

impl D1MembershipKey {
    pub(crate) fn new(
        session_id: Vec<u8>,
        hh_id: String,
        peer_m_id: String,
        peer_cert_fingerprint: Vec<u8>,
        checkpoint_hash: Vec<u8>,
        checkpoint_sequence: u64,
    ) -> Self {
        Self {
            session_id,
            hh_id,
            peer_m_id,
            peer_cert_fingerprint,
            checkpoint_hash,
            checkpoint_sequence,
        }
    }

    /// Lane R (@ilia, authorized 2026-08-05, scoped to exactly this):
    /// the runtime facade's own tests need a real `D1MembershipKey` to
    /// exercise `household-rs::SealedBinding::from_membership_key`
    /// end to end — this crate's own `new` is `pub(crate)` and its only
    /// two real construction sites
    /// (`run_responder_handshake`/`run_initiator_handshake`) are
    /// `pub(crate)` too, genuinely unreachable from any other crate. This
    /// is the escape hatch, gated `test-support`, mirroring
    /// `mesh-session-control-model-rs`'s own `_for_test` convention
    /// exactly (`ControlRecordCell::load_canonical_for_test`, etc.) —
    /// see the `compile_fail` doctest in `src/lib.rs` proving this does
    /// not exist in a default build.
    #[cfg(feature = "test-support")]
    pub fn new_for_test(
        session_id: Vec<u8>,
        hh_id: String,
        peer_m_id: String,
        peer_cert_fingerprint: Vec<u8>,
        checkpoint_hash: Vec<u8>,
        checkpoint_sequence: u64,
    ) -> Self {
        Self::new(
            session_id,
            hh_id,
            peer_m_id,
            peer_cert_fingerprint,
            checkpoint_hash,
            checkpoint_sequence,
        )
    }

    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
    pub fn hh_id(&self) -> &str {
        &self.hh_id
    }
    pub fn peer_m_id(&self) -> &str {
        &self.peer_m_id
    }
    pub fn peer_cert_fingerprint(&self) -> &[u8] {
        &self.peer_cert_fingerprint
    }
    pub fn checkpoint_hash(&self) -> &[u8] {
        &self.checkpoint_hash
    }
    pub fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }
}

/// The D4 signer-authority half of the old `D1AdmissionKey`
/// (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…` P0-5/item 4,
/// definitive). D1 membership (above) and D4 signer-generation authority
/// are separate authorities with separate real backends — `SealedBinding`
/// has no delegation/channel/generation fields at all, and D1's registry
/// has no way to resolve or prove any of them. This type exists so a
/// caller can carry the RESOLVED (never peer-claimed) D4 authority
/// alongside the D1 binding without the two being forced through one
/// constructor that neither authority can fully satisfy.
///
/// **`delegated_key_id`/`delegated_pub` stay protocol-role-scoped, not
/// local/peer-scoped:** these always name *the initiator's* delegation —
/// the party that actually signed the 0x06 intent — regardless of
/// whether the initiator is `local` or the peer in a given ceremony.
///
/// **`delegated_pub`/`generation`/`not_after` come from
/// [`ResolvedSignerAuthority`], never from a peer-embedded claim
/// (2026-08-04, @kiana, item 5):** this is the whole point of the split —
/// a `D1AdmissionKey.delegated_pub` populated from
/// `proof_i.delegation().delegated_pub()` was exactly the
/// self-consistency-only gap the audit's P0-5 finding closed.
/// `delegation_serial` is `MeshSessionDelegation::serial()` — the
/// delegation's own rotation number, a DIFFERENT axis from D4's
/// `generation` (which physical signing key/record generation is live) —
/// both are carried because [`RetainedGenerationResolver`]'s real
/// backend (frozen design `zain-mesh-session-signer-d4-v11.cbb757f8…`,
/// `GenerationRecord`/`sign_checked`, not yet real code anywhere in this
/// repository — "Zero código, admin/rust não tocado") revalidates both
/// against its own live record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentSignerBinding {
    hh_id: String,
    initiator_m_id: String,
    channel: ExpectedChannel,
    delegated_key_id: String,
    delegated_pub: Vec<u8>,
    generation: u64,
    delegation_serial: u64,
    not_after: u64,
}

impl IntentSignerBinding {
    pub(crate) fn new(
        hh_id: String,
        initiator_m_id: String,
        channel: ExpectedChannel,
        delegated_key_id: String,
        resolved: &ResolvedSignerAuthority,
        delegation_serial: u64,
    ) -> Self {
        Self {
            hh_id,
            initiator_m_id,
            channel,
            delegated_key_id,
            delegated_pub: resolved.delegated_pub.clone(),
            generation: resolved.generation,
            delegation_serial,
            not_after: resolved.not_after,
        }
    }

    pub fn hh_id(&self) -> &str {
        &self.hh_id
    }
    pub fn initiator_m_id(&self) -> &str {
        &self.initiator_m_id
    }
    pub fn channel(&self) -> ExpectedChannel {
        self.channel
    }
    pub fn delegated_key_id(&self) -> &str {
        &self.delegated_key_id
    }
    pub fn delegated_pub(&self) -> &[u8] {
        &self.delegated_pub
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn delegation_serial(&self) -> u64 {
        self.delegation_serial
    }
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}

/// A verified, D4-resolved signer authority for one initiator generation
/// (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…`, item 5). Never
/// constructed from a peer's own claimed `delegated_pub` — only from
/// [`RetainedGenerationResolver::resolve`], which a real implementation
/// backs with an independent, live D4 read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSignerAuthority {
    delegated_pub: Vec<u8>,
    generation: u64,
    not_after: u64,
}

impl ResolvedSignerAuthority {
    pub fn new(delegated_pub: Vec<u8>, generation: u64, not_after: u64) -> Self {
        Self {
            delegated_pub,
            generation,
            not_after,
        }
    }

    pub fn delegated_pub(&self) -> &[u8] {
        &self.delegated_pub
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}

/// D4 retained-generation resolver seam (2026-08-04, @kiana,
/// runtime-facade audit `3cbbfb37…`, item 5). Closes the gap the audit's
/// P0-5 finding identified: this crate previously built its verifier for
/// the initiator's frames/intent directly from
/// `proof_i.delegation().delegated_pub()` — the key the PEER embeds in
/// its own frame — which proves only self-consistency, never that the
/// embedded key is the one D4 actually still authorizes for
/// `(hh_id, initiator_m_id, channel, delegated_key_id)`. Called on the
/// responder side, BEFORE nonce consumption (`run_responder_handshake`
/// enforces this ordering, not this trait alone) — 0x06 and Proof-I must
/// be verified against the KEY THIS RETURNS, never the peer-claimed one.
///
/// **This crate does not implement D4** (same posture as the nonce
/// ledger/D1 admission — "não inventar D1/D4 persistence dentro do
/// core"). `zain-mesh-session-signer-d4-v11.cbb757f83666181cd6f253a3fecdfbbe0a960a262a5537eb2da14628a26a1b2d.md`
/// (self-hash verified) is a frozen DESIGN for the real backend
/// (`MeshSignerControlRecordV1`/`GenerationRecord`/`TypedSigner::sign_checked`)
/// but is explicitly "Zero código, admin/rust não tocado" — not real code
/// anywhere in this repository yet. This trait models the seam a real
/// implementation of that design would satisfy; it is deliberately
/// informed by, but never literally coupled to, those not-yet-real types.
pub trait RetainedGenerationResolver {
    /// Resolve and prove the exact retained D4 generation for
    /// `(hh_id, initiator_m_id, channel, delegated_key_id)` — public key,
    /// generation, and expiry all independently verified against D4's own
    /// live record, never assumed from a caller-supplied claim.
    fn resolve(
        &self,
        hh_id: &str,
        initiator_m_id: &str,
        channel: ExpectedChannel,
        delegated_key_id: &str,
        deadline: &CeremonyDeadline,
    ) -> Result<ResolvedSignerAuthority, IntentError>;
}

/// Ships no real D4 wiring — fails closed. Same precedent as
/// `NoIntentLedgerConfigured`/`NoD1AdmissionConfigured`.
pub(crate) struct NoRetainedGenerationResolverConfigured;
impl RetainedGenerationResolver for NoRetainedGenerationResolverConfigured {
    fn resolve(
        &self,
        _hh_id: &str,
        _initiator_m_id: &str,
        _channel: ExpectedChannel,
        _delegated_key_id: &str,
        _deadline: &CeremonyDeadline,
    ) -> Result<ResolvedSignerAuthority, IntentError> {
        Err(IntentError::NoRetainedGenerationResolverConfigured)
    }
}

/// Ships no real D1 wiring. `Pending<'a> = Infallible` — fail-closed *by
/// type*, not by decision: `reserve_pending` always errs, so
/// `D1Pending`'s methods are structurally unreachable (an
/// uninhabited-type match), not merely convention.
pub(crate) struct NoD1AdmissionConfigured;

impl<Active> D1Pending<Active> for std::convert::Infallible {
    fn commit_after_ack(self) -> Active {
        match self {}
    }
    fn cancel_before_ack(self) -> D1CancelOutcome {
        match self {}
    }
}

impl D1Admission for NoD1AdmissionConfigured {
    type Pending<'a> = std::convert::Infallible;
    type Active<'a> = std::convert::Infallible;

    fn reserve_pending<'a>(
        &'a self,
        _key: &D1MembershipKey,
        _deadline: &CeremonyDeadline,
    ) -> Result<Self::Pending<'a>, IntentError> {
        Err(IntentError::NoD1AdmissionConfigured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    fn base_membership_key() -> D1MembershipKey {
        D1MembershipKey {
            session_id: vec![1u8; 32],
            hh_id: "hh-1".to_string(),
            peer_m_id: "m-peer".to_string(),
            peer_cert_fingerprint: vec![0xBBu8; 32],
            checkpoint_hash: vec![0xCCu8; 32],
            checkpoint_sequence: 7,
        }
    }

    /// C.4 RED, preserved across the item-4 split: a D1MembershipKey that
    /// differs ONLY in the authenticated peer fingerprint (same m_id)
    /// must not be treated as the same binding.
    #[test]
    fn red_d1_membership_key_distinguishes_a_fingerprint_swap_at_same_m_id() {
        let a = base_membership_key();
        let mut b = a.clone();
        b.peer_cert_fingerprint = vec![0xFFu8; 32];
        assert_ne!(a, b);
    }

    /// C.4 RED, preserved: a key differing only in checkpoint_sequence (a
    /// revision swap) must likewise not compare equal.
    #[test]
    fn red_d1_membership_key_distinguishes_a_revision_swap() {
        let a = base_membership_key();
        let mut b = a.clone();
        b.checkpoint_sequence = a.checkpoint_sequence + 1;
        assert_ne!(a, b);
    }

    /// C.4 RED, preserved: a key differing only in session_id (a
    /// different ceremony entirely) must not compare equal — admission
    /// must not carry over across ceremonies by m_id coincidence.
    #[test]
    fn red_d1_membership_key_distinguishes_a_different_session() {
        let a = base_membership_key();
        let mut b = a.clone();
        b.session_id = vec![2u8; 32];
        assert_ne!(a, b);
    }

    fn base_signer_binding(resolved: &ResolvedSignerAuthority) -> IntentSignerBinding {
        IntentSignerBinding::new(
            "hh-1".to_string(),
            "m-initiator".to_string(),
            ExpectedChannel::Dev,
            "key-1".to_string(),
            resolved,
            3,
        )
    }

    /// item 4 RED: `IntentSignerBinding` carries the RESOLVED
    /// `delegated_pub`/`generation`/`not_after`, not fields a caller could
    /// pass independently of `ResolvedSignerAuthority` — a resolver that
    /// returns a different key must produce a different binding.
    #[test]
    fn red_intent_signer_binding_distinguishes_a_resolved_key_swap() {
        let a = ResolvedSignerAuthority::new(vec![0x02u8; 33], 5, 9_000);
        let b = ResolvedSignerAuthority::new(vec![0x03u8; 33], 5, 9_000);
        assert_ne!(base_signer_binding(&a), base_signer_binding(&b));
    }

    /// item 4 RED: a generation swap (same key bytes, different D4
    /// generation) must also distinguish the binding — generation and key
    /// bytes are independent axes `sign_checked`-style revalidation needs
    /// both of.
    #[test]
    fn red_intent_signer_binding_distinguishes_a_generation_swap() {
        let a = ResolvedSignerAuthority::new(vec![0x02u8; 33], 5, 9_000);
        let b = ResolvedSignerAuthority::new(vec![0x02u8; 33], 6, 9_000);
        assert_ne!(base_signer_binding(&a), base_signer_binding(&b));
    }

    const PHASE_PENDING: u8 = 0;
    const PHASE_ACTIVE: u8 = 1;
    const PHASE_CLOSED: u8 = 2;

    /// A borrowed double proving [`D1Admission`]'s GAT shape is
    /// satisfiable by something that genuinely borrows `&'a self` —
    /// unlike the doctest's owned `u64` mock — and whose `Drop`, exactly
    /// like the real `PendingSessionAdmission`, mutates only a shared
    /// `AtomicU8` (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…`
    /// P0-2).
    struct BorrowedRegistryDouble {
        phase: AtomicU8,
    }

    impl BorrowedRegistryDouble {
        fn new() -> Self {
            Self {
                phase: AtomicU8::new(PHASE_PENDING),
            }
        }
    }

    struct BorrowedPendingDouble<'a> {
        phase: &'a AtomicU8,
        completed: bool,
    }

    struct BorrowedActiveDouble<'a> {
        phase: &'a AtomicU8,
    }

    impl<'a> D1Pending<BorrowedActiveDouble<'a>> for BorrowedPendingDouble<'a> {
        fn commit_after_ack(mut self) -> BorrowedActiveDouble<'a> {
            self.completed = true;
            self.phase.store(PHASE_ACTIVE, Ordering::SeqCst);
            BorrowedActiveDouble { phase: self.phase }
        }
        fn cancel_before_ack(mut self) -> D1CancelOutcome {
            self.completed = true;
            self.phase.store(PHASE_CLOSED, Ordering::SeqCst);
            D1CancelOutcome::CancelledAndRemoved
        }
    }

    /// Mirrors the real `PendingSessionAdmission::drop`: one atomic store,
    /// nothing else — no lock, no wait, no callback, no allocation.
    impl Drop for BorrowedPendingDouble<'_> {
        fn drop(&mut self) {
            if !self.completed {
                self.phase.store(PHASE_CLOSED, Ordering::SeqCst);
            }
        }
    }

    impl D1Admission for BorrowedRegistryDouble {
        type Pending<'a> = BorrowedPendingDouble<'a>;
        type Active<'a> = BorrowedActiveDouble<'a>;

        fn reserve_pending<'a>(
            &'a self,
            _key: &D1MembershipKey,
            _deadline: &CeremonyDeadline,
        ) -> Result<Self::Pending<'a>, IntentError> {
            self.phase.store(PHASE_PENDING, Ordering::SeqCst);
            Ok(BorrowedPendingDouble {
                phase: &self.phase,
                completed: false,
            })
        }
    }

    /// Non-vacuous compile-positive + behavioral proof (2026-08-04,
    /// @kiana, runtime-facade audit `3cbbfb37…` P0-2): the GAT shape is
    /// satisfiable by a type that genuinely borrows `&'a self` (not an
    /// owned `u64`), `commit_after_ack` is infallible and reachable
    /// through the trait, and `Active<'a>` really does share `Pending<'a>`'s
    /// borrow — this would not compile at all if `D1Pending`'s `Active`
    /// were a free-standing associated type an adapter could mismatch.
    #[test]
    fn borrowed_adapter_satisfies_the_gat_shape_and_commit_reaches_active() {
        let registry = BorrowedRegistryDouble::new();
        let key = base_membership_key();
        let deadline = far_future_deadline();
        let pending = registry.reserve_pending(&key, &deadline).unwrap();
        assert_eq!(registry.phase.load(Ordering::SeqCst), PHASE_PENDING);
        let active = pending.commit_after_ack();
        assert_eq!(registry.phase.load(Ordering::SeqCst), PHASE_ACTIVE);
        assert_eq!(active.phase.load(Ordering::SeqCst), PHASE_ACTIVE);
    }

    #[test]
    fn borrowed_adapter_cancel_before_ack_reports_cancelled_and_removed() {
        let registry = BorrowedRegistryDouble::new();
        let key = base_membership_key();
        let deadline = far_future_deadline();
        let pending = registry.reserve_pending(&key, &deadline).unwrap();
        let outcome = pending.cancel_before_ack();
        assert_eq!(outcome, D1CancelOutcome::CancelledAndRemoved);
        assert_eq!(registry.phase.load(Ordering::SeqCst), PHASE_CLOSED);
    }

    /// RED, non-vacuous (2026-08-04, @kiana, runtime-facade audit
    /// `3cbbfb37…` P0-3): a real `Drop` must be lock-free. Proven here,
    /// not merely documented, by holding a `Mutex` on a background thread
    /// for far longer than any lock-free operation could take, then
    /// dropping a `Pending` value and asserting the drop returns almost
    /// immediately — a wrong `Drop` that tried `mutex.lock()` on a
    /// registry-wide lock like this one would block for the full hold
    /// duration and fail this assertion.
    #[test]
    fn red_pending_drop_never_blocks_even_while_a_shared_mutex_the_double_also_holds_is_locked_elsewhere()
     {
        let registry_wide_lock = Arc::new(Mutex::new(()));
        let held = Arc::clone(&registry_wide_lock);
        let (tx, rx) = mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            let _guard = held.lock().unwrap();
            tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(300));
        });
        rx.recv().unwrap(); // the other thread now holds `registry_wide_lock`

        let phase = AtomicU8::new(PHASE_PENDING);
        let pending = BorrowedPendingDouble {
            phase: &phase,
            completed: false,
        };
        let start = Instant::now();
        drop(pending); // must NOT touch `registry_wide_lock` at all
        let elapsed = start.elapsed();

        handle.join().unwrap();
        assert!(
            elapsed < Duration::from_millis(100),
            "Pending::drop took {elapsed:?} — a lock-free Drop must return almost \
             immediately even while an unrelated registry-wide mutex is held elsewhere",
        );
        assert_eq!(phase.load(Ordering::SeqCst), PHASE_CLOSED);
    }

    fn far_future_deadline() -> CeremonyDeadline {
        CeremonyDeadline::for_test(Instant::now(), Duration::from_secs(3600))
    }

    /// Independently-computed 0x06 (`SignedMeshConnectionIntent`) golden
    /// item 7d mechanism-level RED (2026-08-04, @kiana, runtime-facade
    /// audit `3cbbfb37…`; scope corrected per audit of `018aed57`'s CFX-1
    /// — this unit test alone does NOT close item 7d, it only proves the
    /// ledger's own concurrency contract in isolation; the full
    /// entrypoint-level closure is
    /// `auth_state_machine::tests::red_two_real_responder_ceremonies_racing_the_same_nonce_exactly_one_reaches_active`):
    /// two threads racing `IntentNonceLedger::consume` with the IDENTICAL
    /// key must produce exactly one `Committed` and one `AlreadyConsumed`
    /// — never two `Committed`s (a double-spend) and never two
    /// `AlreadyConsumed`s (nobody actually won). Uses a real thread-safe
    /// double (`Mutex<HashSet>`-backed check-and-set, same shape as
    /// `auth_state_machine`'s own `InMemoryLedger`) shared via `Arc`
    /// across genuine OS threads — not a sequential simulation. A
    /// `Barrier` maximizes the chance both threads are actually
    /// interleaved at the `consume` call, rather than trivially
    /// serialized by scheduling luck. This test does NOT go through
    /// `run_responder_handshake`/the combined check/D1, and does NOT
    /// prove "the loser never reaches Active" — it cannot, since it never
    /// constructs a session at all.
    #[test]
    fn two_concurrent_attempts_at_the_same_nonce_yield_exactly_one_winner() {
        use std::collections::HashSet;
        use std::sync::{Arc, Barrier, Mutex};
        use std::thread;

        struct SharedLedger {
            consumed: Mutex<HashSet<IntentNonceKey>>,
        }
        impl IntentNonceLedger for SharedLedger {
            fn consume(
                &self,
                key: &IntentNonceKey,
                _not_after: u64,
                _digest: &[u8; 32],
                _channel: ExpectedChannel,
                _deadline: &CeremonyDeadline,
            ) -> Result<NonceConsumeOutcome, IntentError> {
                let mut set = self.consumed.lock().unwrap();
                if !set.insert(key.clone()) {
                    return Ok(NonceConsumeOutcome::AlreadyConsumed);
                }
                Ok(NonceConsumeOutcome::Committed)
            }
        }

        let ledger = Arc::new(SharedLedger {
            consumed: Mutex::new(HashSet::new()),
        });
        let key = IntentNonceKey::new(
            "hh-1".to_string(),
            "m-initiator".to_string(),
            "key-1".to_string(),
            [0x7Au8; 32],
        );
        let barrier = Arc::new(Barrier::new(2));

        let attempt = |ledger: Arc<SharedLedger>, key: IntentNonceKey, barrier: Arc<Barrier>| {
            move || {
                barrier.wait();
                ledger
                    .consume(
                        &key,
                        u64::MAX,
                        &[0u8; 32],
                        ExpectedChannel::Dev,
                        &far_future_deadline(),
                    )
                    .unwrap()
            }
        };

        let h1 = thread::spawn(attempt(
            Arc::clone(&ledger),
            key.clone(),
            Arc::clone(&barrier),
        ));
        let h2 = thread::spawn(attempt(
            Arc::clone(&ledger),
            key.clone(),
            Arc::clone(&barrier),
        ));

        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        let committed = [r1, r2]
            .iter()
            .filter(|o| **o == NonceConsumeOutcome::Committed)
            .count();
        let already = [r1, r2]
            .iter()
            .filter(|o| **o == NonceConsumeOutcome::AlreadyConsumed)
            .count();
        assert_eq!(
            committed, 1,
            "expected exactly one Committed, got {r1:?}/{r2:?}"
        );
        assert_eq!(
            already, 1,
            "expected exactly one AlreadyConsumed (the loser), got {r1:?}/{r2:?}"
        );
    }

    /// Independently-computed 0x06 (`SignedMeshConnectionIntent`) golden
    /// vectors and inbound-rejection matrix (2026-08-04, @kiana,
    /// runtime-facade audit `3cbbfb37…`, item 7). Every constant below was
    /// produced by a standalone Python script — hand-rolled RFC 8949
    /// canonical CBOR (definite-length, shortest-form, length-then-
    /// lexicographic map-key sort — matching this crate's own documented
    /// rule, re-derived independently from the field names/RFC text, not
    /// copied from `cbor.rs`) and P-256 ECDSA-SHA256 with RFC 6979
    /// deterministic `k` via the independent `ecdsa` PyPI package — never
    /// via this crate's own `cbor::to_canonical_vec`/`sign_intent_record`.
    /// The script self-verified the signature against the public key
    /// before these bytes were copied in. A bug in this crate's own
    /// encoder or signer therefore cannot silently reproduce these exact
    /// bytes; only a *correct* implementation can.
    mod golden_0x06 {
        use super::*;
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};

        const GOLDEN_HH_ID: &str = "hh-golden";
        const GOLDEN_INITIATOR_M_ID: &str = "m-initiator-golden";
        const GOLDEN_TARGET_M_ID: &str = "m-target-golden";
        const GOLDEN_DELEGATED_KEY_ID: &str = "key-golden-1";
        const GOLDEN_NOT_AFTER: u64 = 1_700_000_000;

        /// `bytes(range(32))`/`bytes([0xA0+i for i in range(32)])`/etc. in
        /// the independent script — a generative formula, not a
        /// hand-transcribed literal, so there is nothing to transcribe
        /// wrong.
        fn seq32(start: u8) -> [u8; 32] {
            std::array::from_fn(|i| start.wrapping_add(i as u8))
        }

        const GOLDEN_PRIV_SCALAR: [u8; 32] = [
            0x04, 0xf3, 0xc2, 0xa1, 0x1b, 0x9d, 0x8e, 0x7f, 0x60, 0x12, 0x34, 0x56, 0x78, 0x9a,
            0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
            0x78, 0x9a, 0xbc, 0xde,
        ];

        const GOLDEN_PUB_SEC1: [u8; 33] = [
            0x03, 0x15, 0xef, 0x48, 0xd3, 0x31, 0x69, 0x61, 0xc2, 0x8f, 0x43, 0x5a, 0xeb, 0xbe,
            0x67, 0x0c, 0x4b, 0x3e, 0xba, 0xf1, 0xbf, 0x5e, 0x34, 0x0a, 0x21, 0xd2, 0xa9, 0x89,
            0x59, 0x74, 0x23, 0xc4, 0x26,
        ];

        const GOLDEN_PREIMAGE: [u8; 379] = [
            0x06, 0xab, 0x61, 0x76, 0x01, 0x65, 0x68, 0x68, 0x5f, 0x69, 0x64, 0x69, 0x68, 0x68,
            0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x65, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x58,
            0x20, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc,
            0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
            0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0x66, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x78, 0x20,
            0x73, 0x6f, 0x79, 0x65, 0x68, 0x74, 0x2f, 0x6d, 0x65, 0x73, 0x68, 0x2d, 0x63, 0x6f,
            0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6e,
            0x74, 0x2f, 0x76, 0x31, 0x69, 0x6e, 0x6f, 0x74, 0x5f, 0x61, 0x66, 0x74, 0x65, 0x72,
            0x1a, 0x65, 0x53, 0xf1, 0x00, 0x6b, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x6d,
            0x5f, 0x69, 0x64, 0x6f, 0x6d, 0x2d, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2d, 0x67,
            0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x6e, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f,
            0x72, 0x5f, 0x6d, 0x5f, 0x69, 0x64, 0x72, 0x6d, 0x2d, 0x69, 0x6e, 0x69, 0x74, 0x69,
            0x61, 0x74, 0x6f, 0x72, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x6f, 0x63, 0x68,
            0x65, 0x63, 0x6b, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x58,
            0x20, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
            0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
            0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x65,
            0x64, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x6c, 0x6b, 0x65, 0x79, 0x2d, 0x67,
            0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x2d, 0x31, 0x77, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
            0x5f, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72,
            0x69, 0x6e, 0x74, 0x58, 0x20, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
            0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0x78, 0x1a, 0x69, 0x6e, 0x69,
            0x74, 0x69, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x66, 0x69,
            0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x58, 0x20, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f,
        ];

        const GOLDEN_SIGNATURE: [u8; 64] = [
            0x85, 0xe2, 0xdc, 0x9b, 0xe5, 0xa6, 0x1d, 0xa5, 0x3e, 0x03, 0xd8, 0x44, 0x87, 0xf7,
            0xb0, 0xf6, 0x48, 0x29, 0xc2, 0xaa, 0xc7, 0xec, 0x37, 0xfa, 0xb3, 0x46, 0x5c, 0x49,
            0x0b, 0xee, 0x84, 0x72, 0x5b, 0x28, 0xe4, 0x8e, 0xd4, 0xbb, 0x7a, 0x8a, 0x9f, 0x26,
            0xe1, 0x82, 0xdc, 0xcb, 0xc5, 0x73, 0xd9, 0x40, 0x61, 0x19, 0xd9, 0x60, 0xaa, 0xd4,
            0x13, 0xe5, 0xea, 0x72, 0x12, 0x36, 0x4d, 0x60,
        ];

        const GOLDEN_FULL_CANONICAL: [u8; 448] = [
            0xac, 0x61, 0x76, 0x01, 0x63, 0x73, 0x69, 0x67, 0x58, 0x40, 0x85, 0xe2, 0xdc, 0x9b,
            0xe5, 0xa6, 0x1d, 0xa5, 0x3e, 0x03, 0xd8, 0x44, 0x87, 0xf7, 0xb0, 0xf6, 0x48, 0x29,
            0xc2, 0xaa, 0xc7, 0xec, 0x37, 0xfa, 0xb3, 0x46, 0x5c, 0x49, 0x0b, 0xee, 0x84, 0x72,
            0x5b, 0x28, 0xe4, 0x8e, 0xd4, 0xbb, 0x7a, 0x8a, 0x9f, 0x26, 0xe1, 0x82, 0xdc, 0xcb,
            0xc5, 0x73, 0xd9, 0x40, 0x61, 0x19, 0xd9, 0x60, 0xaa, 0xd4, 0x13, 0xe5, 0xea, 0x72,
            0x12, 0x36, 0x4d, 0x60, 0x65, 0x68, 0x68, 0x5f, 0x69, 0x64, 0x69, 0x68, 0x68, 0x2d,
            0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x65, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x58, 0x20,
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
            0xdc, 0xdd, 0xde, 0xdf, 0x66, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x78, 0x20, 0x73,
            0x6f, 0x79, 0x65, 0x68, 0x74, 0x2f, 0x6d, 0x65, 0x73, 0x68, 0x2d, 0x63, 0x6f, 0x6e,
            0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x74,
            0x2f, 0x76, 0x31, 0x69, 0x6e, 0x6f, 0x74, 0x5f, 0x61, 0x66, 0x74, 0x65, 0x72, 0x1a,
            0x65, 0x53, 0xf1, 0x00, 0x6b, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x6d, 0x5f,
            0x69, 0x64, 0x6f, 0x6d, 0x2d, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2d, 0x67, 0x6f,
            0x6c, 0x64, 0x65, 0x6e, 0x6e, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72,
            0x5f, 0x6d, 0x5f, 0x69, 0x64, 0x72, 0x6d, 0x2d, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61,
            0x74, 0x6f, 0x72, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x6f, 0x63, 0x68, 0x65,
            0x63, 0x6b, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x58, 0x20,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
            0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
            0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x65, 0x64,
            0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x6c, 0x6b, 0x65, 0x79, 0x2d, 0x67, 0x6f,
            0x6c, 0x64, 0x65, 0x6e, 0x2d, 0x31, 0x77, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f,
            0x63, 0x65, 0x72, 0x74, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69,
            0x6e, 0x74, 0x58, 0x20, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
            0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
            0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0x78, 0x1a, 0x69, 0x6e, 0x69, 0x74,
            0x69, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x66, 0x69, 0x6e,
            0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x58, 0x20, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];

        const GOLDEN_DIGEST: [u8; 32] = [
            0xef, 0x2a, 0x79, 0x41, 0x27, 0x81, 0x46, 0x8c, 0x43, 0x10, 0x25, 0x73, 0x7b, 0x8a,
            0x78, 0x22, 0x59, 0xd3, 0x64, 0xc5, 0x11, 0x45, 0x3a, 0xb1, 0x7e, 0xbb, 0x04, 0x91,
            0xc1, 0xa1, 0x4b, 0x5e,
        ];

        const GOLDEN_FULL_CANONICAL_HIGH_S: [u8; 448] = [
            0xac, 0x61, 0x76, 0x01, 0x63, 0x73, 0x69, 0x67, 0x58, 0x40, 0x85, 0xe2, 0xdc, 0x9b,
            0xe5, 0xa6, 0x1d, 0xa5, 0x3e, 0x03, 0xd8, 0x44, 0x87, 0xf7, 0xb0, 0xf6, 0x48, 0x29,
            0xc2, 0xaa, 0xc7, 0xec, 0x37, 0xfa, 0xb3, 0x46, 0x5c, 0x49, 0x0b, 0xee, 0x84, 0x72,
            0xa4, 0xd7, 0x1b, 0x70, 0x2b, 0x44, 0x85, 0x76, 0x60, 0xd9, 0x1e, 0x7d, 0x23, 0x34,
            0x3a, 0x8b, 0xe3, 0xa6, 0x99, 0x93, 0xcd, 0xb6, 0xf3, 0xb0, 0xdf, 0xd3, 0xe0, 0x50,
            0xea, 0x2c, 0xd7, 0xf1, 0x65, 0x68, 0x68, 0x5f, 0x69, 0x64, 0x69, 0x68, 0x68, 0x2d,
            0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x65, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x58, 0x20,
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
            0xdc, 0xdd, 0xde, 0xdf, 0x66, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x78, 0x20, 0x73,
            0x6f, 0x79, 0x65, 0x68, 0x74, 0x2f, 0x6d, 0x65, 0x73, 0x68, 0x2d, 0x63, 0x6f, 0x6e,
            0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x74,
            0x2f, 0x76, 0x31, 0x69, 0x6e, 0x6f, 0x74, 0x5f, 0x61, 0x66, 0x74, 0x65, 0x72, 0x1a,
            0x65, 0x53, 0xf1, 0x00, 0x6b, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x6d, 0x5f,
            0x69, 0x64, 0x6f, 0x6d, 0x2d, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2d, 0x67, 0x6f,
            0x6c, 0x64, 0x65, 0x6e, 0x6e, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72,
            0x5f, 0x6d, 0x5f, 0x69, 0x64, 0x72, 0x6d, 0x2d, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61,
            0x74, 0x6f, 0x72, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x6f, 0x63, 0x68, 0x65,
            0x63, 0x6b, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x58, 0x20,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
            0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
            0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x65, 0x64,
            0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x6c, 0x6b, 0x65, 0x79, 0x2d, 0x67, 0x6f,
            0x6c, 0x64, 0x65, 0x6e, 0x2d, 0x31, 0x77, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f,
            0x63, 0x65, 0x72, 0x74, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69,
            0x6e, 0x74, 0x58, 0x20, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
            0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
            0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0x78, 0x1a, 0x69, 0x6e, 0x69, 0x74,
            0x69, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x66, 0x69, 0x6e,
            0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x58, 0x20, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];

        const GOLDEN_DUP_KEY_FULL: [u8; 451] = [
            0xad, 0x61, 0x76, 0x01, 0x61, 0x76, 0x01, 0x63, 0x73, 0x69, 0x67, 0x58, 0x40, 0x85,
            0xe2, 0xdc, 0x9b, 0xe5, 0xa6, 0x1d, 0xa5, 0x3e, 0x03, 0xd8, 0x44, 0x87, 0xf7, 0xb0,
            0xf6, 0x48, 0x29, 0xc2, 0xaa, 0xc7, 0xec, 0x37, 0xfa, 0xb3, 0x46, 0x5c, 0x49, 0x0b,
            0xee, 0x84, 0x72, 0x5b, 0x28, 0xe4, 0x8e, 0xd4, 0xbb, 0x7a, 0x8a, 0x9f, 0x26, 0xe1,
            0x82, 0xdc, 0xcb, 0xc5, 0x73, 0xd9, 0x40, 0x61, 0x19, 0xd9, 0x60, 0xaa, 0xd4, 0x13,
            0xe5, 0xea, 0x72, 0x12, 0x36, 0x4d, 0x60, 0x65, 0x68, 0x68, 0x5f, 0x69, 0x64, 0x69,
            0x68, 0x68, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x65, 0x6e, 0x6f, 0x6e, 0x63,
            0x65, 0x58, 0x20, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca,
            0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
            0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0x66, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e,
            0x78, 0x20, 0x73, 0x6f, 0x79, 0x65, 0x68, 0x74, 0x2f, 0x6d, 0x65, 0x73, 0x68, 0x2d,
            0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x69, 0x6e, 0x74,
            0x65, 0x6e, 0x74, 0x2f, 0x76, 0x31, 0x69, 0x6e, 0x6f, 0x74, 0x5f, 0x61, 0x66, 0x74,
            0x65, 0x72, 0x1a, 0x65, 0x53, 0xf1, 0x00, 0x6b, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
            0x5f, 0x6d, 0x5f, 0x69, 0x64, 0x6f, 0x6d, 0x2d, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
            0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x6e, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61,
            0x74, 0x6f, 0x72, 0x5f, 0x6d, 0x5f, 0x69, 0x64, 0x72, 0x6d, 0x2d, 0x69, 0x6e, 0x69,
            0x74, 0x69, 0x61, 0x74, 0x6f, 0x72, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x6f,
            0x63, 0x68, 0x65, 0x63, 0x6b, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x68, 0x61, 0x73,
            0x68, 0x58, 0x20, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
            0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
            0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61,
            0x74, 0x65, 0x64, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x6c, 0x6b, 0x65, 0x79,
            0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x2d, 0x31, 0x77, 0x74, 0x61, 0x72, 0x67,
            0x65, 0x74, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72,
            0x70, 0x72, 0x69, 0x6e, 0x74, 0x58, 0x20, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
            0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
            0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0x78, 0x1a, 0x69,
            0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x5f,
            0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x58, 0x20, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f,
        ];

        const GOLDEN_UNSORTED_FULL: [u8; 448] = [
            0xac, 0x63, 0x73, 0x69, 0x67, 0x58, 0x40, 0x85, 0xe2, 0xdc, 0x9b, 0xe5, 0xa6, 0x1d,
            0xa5, 0x3e, 0x03, 0xd8, 0x44, 0x87, 0xf7, 0xb0, 0xf6, 0x48, 0x29, 0xc2, 0xaa, 0xc7,
            0xec, 0x37, 0xfa, 0xb3, 0x46, 0x5c, 0x49, 0x0b, 0xee, 0x84, 0x72, 0x5b, 0x28, 0xe4,
            0x8e, 0xd4, 0xbb, 0x7a, 0x8a, 0x9f, 0x26, 0xe1, 0x82, 0xdc, 0xcb, 0xc5, 0x73, 0xd9,
            0x40, 0x61, 0x19, 0xd9, 0x60, 0xaa, 0xd4, 0x13, 0xe5, 0xea, 0x72, 0x12, 0x36, 0x4d,
            0x60, 0x69, 0x6e, 0x6f, 0x74, 0x5f, 0x61, 0x66, 0x74, 0x65, 0x72, 0x1a, 0x65, 0x53,
            0xf1, 0x00, 0x65, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x58, 0x20, 0xc0, 0xc1, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1,
            0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
            0x70, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x6b, 0x65, 0x79,
            0x5f, 0x69, 0x64, 0x6c, 0x6b, 0x65, 0x79, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e,
            0x2d, 0x31, 0x6f, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f,
            0x68, 0x61, 0x73, 0x68, 0x58, 0x20, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
            0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
            0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x77, 0x74, 0x61, 0x72,
            0x67, 0x65, 0x74, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65,
            0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x58, 0x20, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
            0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
            0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0x6b, 0x74,
            0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x6d, 0x5f, 0x69, 0x64, 0x6f, 0x6d, 0x2d, 0x74,
            0x61, 0x72, 0x67, 0x65, 0x74, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x78, 0x1a,
            0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x63, 0x65, 0x72, 0x74,
            0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x58, 0x20,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x6e, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72,
            0x5f, 0x6d, 0x5f, 0x69, 0x64, 0x72, 0x6d, 0x2d, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61,
            0x74, 0x6f, 0x72, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x65, 0x68, 0x68, 0x5f,
            0x69, 0x64, 0x69, 0x68, 0x68, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x66, 0x64,
            0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x78, 0x20, 0x73, 0x6f, 0x79, 0x65, 0x68, 0x74, 0x2f,
            0x6d, 0x65, 0x73, 0x68, 0x2d, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
            0x6e, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2f, 0x76, 0x31, 0x61, 0x76, 0x01,
        ];

        const GOLDEN_UNKNOWN_FIELD_FULL: [u8; 459] = [
            0xad, 0x61, 0x76, 0x01, 0x63, 0x73, 0x69, 0x67, 0x58, 0x40, 0x85, 0xe2, 0xdc, 0x9b,
            0xe5, 0xa6, 0x1d, 0xa5, 0x3e, 0x03, 0xd8, 0x44, 0x87, 0xf7, 0xb0, 0xf6, 0x48, 0x29,
            0xc2, 0xaa, 0xc7, 0xec, 0x37, 0xfa, 0xb3, 0x46, 0x5c, 0x49, 0x0b, 0xee, 0x84, 0x72,
            0x5b, 0x28, 0xe4, 0x8e, 0xd4, 0xbb, 0x7a, 0x8a, 0x9f, 0x26, 0xe1, 0x82, 0xdc, 0xcb,
            0xc5, 0x73, 0xd9, 0x40, 0x61, 0x19, 0xd9, 0x60, 0xaa, 0xd4, 0x13, 0xe5, 0xea, 0x72,
            0x12, 0x36, 0x4d, 0x60, 0x65, 0x68, 0x68, 0x5f, 0x69, 0x64, 0x69, 0x68, 0x68, 0x2d,
            0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x65, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x58, 0x20,
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
            0xdc, 0xdd, 0xde, 0xdf, 0x66, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x78, 0x20, 0x73,
            0x6f, 0x79, 0x65, 0x68, 0x74, 0x2f, 0x6d, 0x65, 0x73, 0x68, 0x2d, 0x63, 0x6f, 0x6e,
            0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x74,
            0x2f, 0x76, 0x31, 0x69, 0x6e, 0x6f, 0x74, 0x5f, 0x61, 0x66, 0x74, 0x65, 0x72, 0x1a,
            0x65, 0x53, 0xf1, 0x00, 0x69, 0x7a, 0x7a, 0x7a, 0x5f, 0x65, 0x78, 0x74, 0x72, 0x61,
            0x01, 0x6b, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x6d, 0x5f, 0x69, 0x64, 0x6f,
            0x6d, 0x2d, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65,
            0x6e, 0x6e, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x6d, 0x5f,
            0x69, 0x64, 0x72, 0x6d, 0x2d, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72,
            0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x6f, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x70,
            0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x58, 0x20, 0x50, 0x51, 0x52,
            0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x6b, 0x65,
            0x79, 0x5f, 0x69, 0x64, 0x6c, 0x6b, 0x65, 0x79, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65,
            0x6e, 0x2d, 0x31, 0x77, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x63, 0x65, 0x72,
            0x74, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x58,
            0x20, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
            0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
            0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0x78, 0x1a, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74,
            0x6f, 0x72, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72,
            0x70, 0x72, 0x69, 0x6e, 0x74, 0x58, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];

        fn golden_signer() -> SigningKey {
            SigningKey::from_slice(&GOLDEN_PRIV_SCALAR).expect("valid nonzero P-256 scalar")
        }

        fn golden_unsigned_intent() -> SignedMeshConnectionIntent {
            SignedMeshConnectionIntent::new(
                GOLDEN_HH_ID.to_string(),
                GOLDEN_INITIATOR_M_ID.to_string(),
                seq32(0x00).to_vec(),
                GOLDEN_TARGET_M_ID.to_string(),
                seq32(0xA0).to_vec(),
                seq32(0x50).to_vec(),
                GOLDEN_DELEGATED_KEY_ID.to_string(),
                seq32(0xC0).to_vec(),
                GOLDEN_NOT_AFTER,
                vec![0u8; 64],
            )
            .unwrap()
        }

        #[test]
        fn golden_pub_key_matches_independently_derived_verifying_key() {
            let vk = *golden_signer().verifying_key();
            assert_eq!(vk.to_encoded_point(true).as_bytes(), &GOLDEN_PUB_SEC1[..]);
        }

        #[test]
        fn golden_preimage_matches_independently_computed_canonical_cbor() {
            let unsigned = golden_unsigned_intent();
            let preimage = IntentSigningPreimage::for_intent(&unsigned).unwrap();
            assert_eq!(preimage.as_bytes(), &GOLDEN_PREIMAGE[..]);
        }

        #[test]
        fn golden_signature_matches_independently_computed_rfc6979_signature() {
            let sk = golden_signer();
            let unsigned = golden_unsigned_intent();
            let preimage = IntentSigningPreimage::for_intent(&unsigned).unwrap();
            let sig: Signature = sk.sign(preimage.as_bytes());
            let sig = sig.normalize_s().unwrap_or(sig);
            let sig_bytes: [u8; 64] = sig.to_bytes().into();
            assert_eq!(
                sig_bytes, GOLDEN_SIGNATURE,
                "this crate's p256-based RFC 6979 signing did not match the \
                 independent Python `ecdsa` package's RFC 6979 signing over \
                 the identical preimage and private key"
            );
        }

        #[test]
        fn golden_full_canonical_matches_independently_computed_bytes() {
            let signed = golden_unsigned_intent().with_sig(GOLDEN_SIGNATURE.to_vec());
            let full = cbor::to_canonical_vec(&signed).unwrap();
            assert_eq!(full, GOLDEN_FULL_CANONICAL.to_vec());
        }

        #[test]
        fn golden_intent_digest_matches_independently_computed_digest() {
            let signed = golden_unsigned_intent().with_sig(GOLDEN_SIGNATURE.to_vec());
            assert_eq!(intent_digest(&signed).unwrap(), GOLDEN_DIGEST);
        }

        #[test]
        fn golden_decode_round_trips_the_full_wire_bytes() {
            let expected = golden_unsigned_intent().with_sig(GOLDEN_SIGNATURE.to_vec());
            let mut plaintext = vec![INTENT_TYPE_BYTE];
            plaintext.extend_from_slice(&GOLDEN_FULL_CANONICAL);
            let decoded = decode_intent_record(&plaintext).unwrap();
            assert_eq!(decoded, expected);
            let verifier =
                crate::auth_frames::RawP256FrameVerifier(*golden_signer().verifying_key());
            verify_intent_record(&decoded, &verifier).unwrap();
        }

        fn body_with_type(type_byte: u8, body: &[u8]) -> Vec<u8> {
            let mut v = vec![type_byte];
            v.extend_from_slice(body);
            v
        }

        #[test]
        fn red_type_swap_0x01_through_0x05_rejected_by_decode_intent_record() {
            for type_byte in 0x01u8..=0x05 {
                let plaintext = body_with_type(type_byte, &GOLDEN_FULL_CANONICAL);
                match decode_intent_record(&plaintext) {
                    Err(IntentError::UnexpectedTypeByte(got)) => assert_eq!(got, type_byte),
                    other => panic!(
                        "type byte {type_byte:#04x}: expected UnexpectedTypeByte, got {other:?}"
                    ),
                }
            }
        }

        #[test]
        fn red_0x06_rejected_by_decode_auth_frame() {
            let plaintext = body_with_type(INTENT_TYPE_BYTE, &GOLDEN_FULL_CANONICAL);
            let err = crate::auth_frames::decode_auth_frame(&plaintext).unwrap_err();
            assert!(matches!(
                err,
                AuthFrameError::Wire(crate::error::WireError::UnknownTypeByte(0x06))
            ));
        }

        #[test]
        fn red_0x07_reserved_unreachable_via_decode_intent_record() {
            let plaintext = body_with_type(CAPABILITY_TYPE_BYTE_RESERVED, &GOLDEN_FULL_CANONICAL);
            match decode_intent_record(&plaintext) {
                Err(IntentError::UnexpectedTypeByte(0x07)) => {}
                other => panic!("expected UnexpectedTypeByte(0x07), got {other:?}"),
            }
        }

        #[test]
        fn red_0x07_reserved_also_unreachable_via_decode_auth_frame() {
            let plaintext = body_with_type(CAPABILITY_TYPE_BYTE_RESERVED, &GOLDEN_FULL_CANONICAL);
            let err = crate::auth_frames::decode_auth_frame(&plaintext).unwrap_err();
            assert!(matches!(
                err,
                AuthFrameError::Wire(crate::error::WireError::UnknownTypeByte(0x07))
            ));
        }

        #[test]
        fn red_high_s_signature_rejected_without_normalization() {
            let plaintext = body_with_type(INTENT_TYPE_BYTE, &GOLDEN_FULL_CANONICAL_HIGH_S);
            match decode_intent_record(&plaintext) {
                Err(IntentError::HighSRejected) => {}
                other => panic!("expected HighSRejected, got {other:?}"),
            }
        }

        #[test]
        fn red_duplicate_key_rejected_by_decode_intent_record() {
            let plaintext = body_with_type(INTENT_TYPE_BYTE, &GOLDEN_DUP_KEY_FULL);
            assert!(decode_intent_record(&plaintext).is_err());
        }

        #[test]
        fn red_unsorted_keys_rejected_by_decode_intent_record() {
            let plaintext = body_with_type(INTENT_TYPE_BYTE, &GOLDEN_UNSORTED_FULL);
            assert!(decode_intent_record(&plaintext).is_err());
        }

        #[test]
        fn red_unknown_field_rejected_by_decode_intent_record() {
            let plaintext = body_with_type(INTENT_TYPE_BYTE, &GOLDEN_UNKNOWN_FIELD_FULL);
            assert!(decode_intent_record(&plaintext).is_err());
        }

        #[test]
        fn red_trailing_byte_rejected_by_decode_intent_record() {
            let mut body = GOLDEN_FULL_CANONICAL.to_vec();
            body.push(0x00);
            let plaintext = body_with_type(INTENT_TYPE_BYTE, &body);
            assert!(decode_intent_record(&plaintext).is_err());
        }
    }
}
