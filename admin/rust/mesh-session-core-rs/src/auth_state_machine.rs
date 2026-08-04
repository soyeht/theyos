//! Auth state machine, v6 §13, Idle → Active. Drives the 3 Noise flights
//! (item 2) then the 5 auth frames (`auth_frames.rs`) in the order v6 §13
//! and its erratum (`63222d40…`) require, returning an opaque
//! [`ActiveMeshSession`] only once ActivateAck is durably written.
//!
//! **Scope boundary, restated:** this drives *authentication*, not
//! traffic. Nothing past `ActivateAck` (DATA/CLOSE/REKEY wire) is
//! implemented — rekey exists here only as the generic counter (item 4)
//! now coupled to the real `snow::TransportState::rekey_outgoing/incoming`
//! calls, with no concrete marker-record wire format invented.
//!
//! **Delegation gate ordering (2026-08-04, @kiana):** before a peer
//! frame's embedded `delegated_pub` is ever trusted enough to verify that
//! *same* frame's outer signature, the delegation must pass, strictly in
//! this order: [`DelegationPolicy::validate`] (TTL), then
//! [`DelegationSignatureVerifier::verify_delegation`] (M_priv signature —
//! this crate ships only [`NoVerifierConfigured`], which always fails, so
//! as shipped this gate never opens), then
//! [`MeshSessionDelegation::check_partial_binding`]. Only after all three
//! pass does `auth_frames::verifier_from_delegated_pub` get called.
//! Self-consistency (a frame's signature matching its own embedded key)
//! never substitutes for that gate.
//!
//! **Both entry points are `pub(crate)` (2026-08-04, @kiana):** this slice
//! implements only *partial* delegation binding (no D-1/roster), so
//! nothing here can distinguish a real identity from a self-consistent,
//! fully fabricated one. `run_responder_handshake`/`run_initiator_handshake`
//! accept whatever `LocalIdentity`/`LocalCheckpoint`/`ExpectedResponder`
//! the caller supplies and check them only against each other, never
//! against a live roster — if either function (or the types they take)
//! were `pub`, any external crate could call them directly with an
//! invented identity and obtain a genuine `ActiveMeshSession`, without
//! even needing a peer to misbehave. Until D-1/D-9 exist and this crate
//! gains a real, sealed, roster-backed admission authority to gate on,
//! both stay crate-internal; only this crate's own tests drive them.
//!
//! Consequently, a plain (non-test) build has no production caller for
//! anything in this module yet — `#![allow(dead_code)]` reflects that as
//! the expected, intentional current state, not an oversight. `cargo test`
//! exercises all of it via this module's own test suite.
#![allow(dead_code)]

use std::io::{Read, Write};

use snow::TransportState;

use crate::auth_frames::{
    self, Activate, ActivateAck, AuthFrame, ConnectionIntentDigest, FinalConfirm,
    MeshSessionFrameSigner, ProofI, ProofR,
};
use crate::delegation::{
    DelegationPolicy, DelegationSignatureVerifier, MeshSessionDelegation, PartialBindingInputs,
};
use crate::error::{AuthFrameError, NoiseSetupError};
use crate::ingress::{CeremonyDeadline, IngressEvidence, PrevalidatedIngress};
use crate::noise::{self, Role};
use crate::rekey::{self, RekeyThreshold, SessionRekeyState};
use crate::wire;

/// Local device's own identity + delegation, presented in Proof-R/Proof-I.
///
/// **`pub(crate)` on purpose (2026-08-04, @kiana):** this slice only checks
/// *partial* binding (no D-1/roster) — `run_responder_handshake` accepts
/// whatever `hh_id`/`m_id`/`cert_fingerprint`/checkpoint a caller supplies
/// and, because they're checked only against each other (self-consistency,
/// never against a live roster), a self-consistent-but-fabricated identity
/// completes the ceremony and yields a real `ActiveMeshSession`. If this
/// type and its constructing functions were `pub`, any external crate
/// could reach for exactly that bypass directly, without even needing a
/// malicious peer — the caller of `run_responder_handshake` itself would
/// be choosing the "local" identity being vouched for. Until D-1/D-9
/// exist and inject a sealed, roster-backed admission authority, this
/// stays crate-internal; only this crate's own tests may construct one.
pub(crate) struct LocalIdentity {
    pub(crate) hh_id: String,
    pub(crate) m_id: String,
    pub(crate) cert_fingerprint: Vec<u8>,
    pub(crate) delegation: MeshSessionDelegation,
}

/// The 4 checkpoint scalar fields Proof-R/Proof-I carry, obtained live by
/// the caller (this crate does not construct or consult a roster —
/// `checkpoint: MachineRosterCheckpointV1` itself is out of scope, only
/// these 4 already-extracted scalars are needed here). `pub(crate)` for
/// the same reason as [`LocalIdentity`].
pub(crate) struct LocalCheckpoint {
    pub(crate) hash: Vec<u8>,
    pub(crate) sequence: u64,
    pub(crate) event_head: Vec<u8>,
    pub(crate) not_after: u64,
}

fn send_frame<S: Write + wire::DeadlineBoundedIo>(
    stream: &mut S,
    transport: &mut TransportState,
    frame: &AuthFrame,
    deadline: &CeremonyDeadline,
) -> Result<(), AuthFrameError> {
    let plaintext = auth_frames::encode_auth_frame(frame)?;
    let mut ciphertext = vec![0u8; plaintext.len() + 16];
    let ct_len = transport
        .write_message(&plaintext, &mut ciphertext)
        .map_err(NoiseSetupError::from)?;
    wire::write_transport_record(stream, &ciphertext[..ct_len], deadline)?;
    Ok(())
}

fn recv_frame<S: Read + wire::DeadlineBoundedIo>(
    stream: &mut S,
    transport: &mut TransportState,
    deadline: &CeremonyDeadline,
) -> Result<AuthFrame, AuthFrameError> {
    let ciphertext = wire::read_transport_record(stream, deadline)?;
    let mut plaintext = vec![0u8; ciphertext.len()];
    let pt_len = transport
        .read_message(&ciphertext, &mut plaintext)
        .map_err(NoiseSetupError::from)?;
    auth_frames::decode_auth_frame(&plaintext[..pt_len])
}

/// Same shape as `send_frame`/`recv_frame`, but for the 0x06 intent
/// record — deliberately NOT routed through `encode_auth_frame`/
/// `decode_auth_frame` (D9 carrier-B: `IntentRecord` is not an
/// `AuthFrame`). Reuses the identical Noise transport-record framing, so
/// it inherits the same `MAX_CBOR_BODY_LEN`/canonicality/no-alloc-before-
/// validate discipline with no new DoS surface.
fn send_intent_record<S: Write + wire::DeadlineBoundedIo>(
    stream: &mut S,
    transport: &mut TransportState,
    intent: &crate::intent::SignedMeshConnectionIntent,
    deadline: &CeremonyDeadline,
) -> Result<(), AuthFrameError> {
    let plaintext = crate::intent::encode_intent_record(intent)?;
    let mut ciphertext = vec![0u8; plaintext.len() + 16];
    let ct_len = transport
        .write_message(&plaintext, &mut ciphertext)
        .map_err(NoiseSetupError::from)?;
    wire::write_transport_record(stream, &ciphertext[..ct_len], deadline)?;
    Ok(())
}

fn recv_intent_record<S: Read + wire::DeadlineBoundedIo>(
    stream: &mut S,
    transport: &mut TransportState,
    deadline: &CeremonyDeadline,
) -> Result<crate::intent::SignedMeshConnectionIntent, AuthFrameError> {
    let ciphertext = wire::read_transport_record(stream, deadline)?;
    let mut plaintext = vec![0u8; ciphertext.len()];
    let pt_len = transport
        .read_message(&ciphertext, &mut plaintext)
        .map_err(NoiseSetupError::from)?;
    Ok(crate::intent::decode_intent_record(&plaintext[..pt_len])?)
}

/// The channel this ceremony is running under. Typed rather than a bare
/// `&str` (2026-08-04, @kiana, round 5) so a caller cannot pass an
/// arbitrary string and have it silently trusted — only these two values
/// exist, matching the same "dev"/"release" literals `delegation.rs`'s
/// own shape validation already fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ExpectedChannel {
    Dev,
    Release,
}

impl ExpectedChannel {
    fn as_str(self) -> &'static str {
        match self {
            ExpectedChannel::Dev => "dev",
            ExpectedChannel::Release => "release",
        }
    }
}

/// The exact `roles`/`transcript_kinds` a delegation must carry to
/// authorize a B-SESSAO mesh-session auth-frame ceremony specifically —
/// a norm shared with D-4, not a generic property of every
/// `MeshSessionDelegation` (v6 §5 deliberately leaves the schema itself
/// unconstrained here; see `delegation.rs`'s own `validate_shape` note).
/// A delegation validly signed and shaped, but scoped to a different
/// role/kind/channel, must not be treated as authorizing frames it was
/// never issued for (2026-08-04, @kiana, round 5).
const EXPECTED_DELEGATION_ROLES: [&str; 2] = ["initiator", "responder"];
const EXPECTED_TRANSCRIPT_KINDS: [&str; 3] = ["final-confirm", "activate", "activate-ack"];

/// Exact-set comparison: same length, same elements — no extras,
/// duplicates, or omissions, order-independent. A plain sorted-Vec
/// compare already rejects a duplicate that displaces a required element
/// (e.g. `["initiator","initiator"]` against `["initiator","responder"]`
/// sorts to `["initiator","initiator"] != ["initiator","responder"]`).
fn string_set_matches_exactly(actual: &[String], expected: &[&str]) -> bool {
    let mut sorted_actual: Vec<&str> = actual.iter().map(String::as_str).collect();
    sorted_actual.sort_unstable();
    let mut sorted_expected: Vec<&str> = expected.to_vec();
    sorted_expected.sort_unstable();
    sorted_actual == sorted_expected
}

/// The delegation gate, strictly ordered: policy TTL, then injected
/// signature verification, then this ceremony's exact role/kind/channel
/// scope, then partial binding. `NoVerifierConfigured` (this crate's only
/// shipped `DelegationSignatureVerifier`) always fails the middle step,
/// so this gate never opens on an unmodified build — see the module doc.
///
/// **Scope checks added (2026-08-04, @kiana, round 5):** a validly-signed
/// delegation, correctly bound to the presenting identity, used to be
/// enough to pass this gate regardless of what `roles`/`transcript_kinds`/
/// `channel` it actually declared — a delegation scoped to some other
/// purpose or environment (e.g. a "release" delegation replayed into a
/// "dev" ceremony) would still authorize frames here. Checked right after
/// signature verification, before partial binding, so these REDs don't
/// need a matching `ctx` to reach them.
fn pass_delegation_gate<Ver: DelegationSignatureVerifier>(
    delegation: &MeshSessionDelegation,
    policy: &DelegationPolicy,
    verifier: &Ver,
    ctx: &PartialBindingInputs,
    expected_channel: ExpectedChannel,
) -> Result<(), AuthFrameError> {
    policy.validate(delegation)?;
    delegation
        .verify_signature(verifier)
        .map_err(|_| AuthFrameError::DelegationGate)?;
    if !string_set_matches_exactly(delegation.roles(), &EXPECTED_DELEGATION_ROLES) {
        return Err(AuthFrameError::DelegationRolesMismatch);
    }
    if !string_set_matches_exactly(delegation.transcript_kinds(), &EXPECTED_TRANSCRIPT_KINDS) {
        return Err(AuthFrameError::DelegationTranscriptKindsMismatch);
    }
    if delegation.channel() != expected_channel.as_str() {
        return Err(AuthFrameError::DelegationChannelMismatch);
    }
    delegation.check_partial_binding(ctx)?;
    Ok(())
}

fn check_h_final(frame_h_final: &[u8], expected: &[u8]) -> Result<(), AuthFrameError> {
    if frame_h_final != expected {
        return Err(AuthFrameError::HFinalMismatch);
    }
    Ok(())
}

/// A single opaque, monotonic ceremony deadline (2026-08-04, @kiana,
/// definitive B — supersedes the earlier `Clock`/wall-clock-`u64`
/// formulation), checked fresh against the same `Instant` at each call
/// site — never a cached scalar, which could not bound a peer that
/// trickles bytes across many separate blocking reads. Called at each
/// major phase boundary (after Noise, after the intent record, after the
/// combined check/nonce consumption, after FinalConfirm, after Activate)
/// — this catches a slow-loris that completes individual frames slowly
/// across many of these boundaries; each individual read/write's *own*
/// per-syscall bounding is `wire::DeadlineBoundedIo`'s job, against this
/// exact same [`CeremonyDeadline`] token, never a second/different clock.
fn check_ceremony_deadline(deadline: &CeremonyDeadline) -> Result<(), AuthFrameError> {
    if deadline.is_expired() {
        return Err(crate::error::IntentError::DeadlineExceeded.into());
    }
    Ok(())
}

/// Binds the local K_mesh signer to the local delegation *before either
/// handshake function writes anything* (2026-08-04, @kiana, round 3):
/// previously `local.delegation` and `k_mesh` were accepted as two
/// separate parameters with nothing proving they actually name the same
/// key. A signer holding a different key than `delegation.delegated_pub`
/// would sign real frames with real (locally self-consistent) signatures
/// that any peer verifying against the delegation's `delegated_pub` would
/// still reject — but only after a full round trip, and only because the
/// peer happened to check. This closes it locally, at the very first
/// opportunity: compare the signer's own reported public key (never
/// secret material — see [`MeshSessionFrameSigner::public_key`]) against
/// `local.delegation.delegated_pub()` and fail closed before the Noise
/// handshake — and therefore before any byte reaches the wire — even
/// starts.
fn check_signer_matches_delegation<Sig: MeshSessionFrameSigner>(
    k_mesh: &Sig,
    delegation: &MeshSessionDelegation,
) -> Result<(), AuthFrameError> {
    let signer_pub = k_mesh.public_key().to_encoded_point(true);
    if signer_pub.as_bytes() != delegation.delegated_pub() {
        return Err(AuthFrameError::SignerKeyMismatchDelegation);
    }
    Ok(())
}

/// Checks the LOCAL delegation's own `channel` against what the caller
/// says this ceremony expects — before any I/O, same preflight spot as
/// [`check_signer_matches_delegation`] (2026-08-04, @kiana, round 5).
/// `pass_delegation_gate` separately re-checks channel on the RECEIVED
/// (peer's) delegation; this is the local half of that same requirement
/// — "channel deve... bater na delegação local antes de I/O e na
/// delegação recebida antes de confiar K_mesh."
fn check_local_delegation_channel(
    delegation: &MeshSessionDelegation,
    expected_channel: ExpectedChannel,
) -> Result<(), AuthFrameError> {
    if delegation.channel() != expected_channel.as_str() {
        return Err(AuthFrameError::DelegationChannelMismatch);
    }
    Ok(())
}

/// Compares all 4 checkpoint scalars a frame signs (v6 §6), not just
/// `hash` (2026-08-04, @kiana: `hash` alone was checked, leaving
/// `sequence`/`event_head`/`not_after` — also part of the signed body —
/// unverified; a peer could send the right hash with mismatched
/// sequence/event_head/not_after and nothing here would catch it).
#[allow(clippy::too_many_arguments)]
fn check_checkpoint(
    frame_hash: &[u8],
    frame_sequence: u64,
    frame_event_head: &[u8],
    frame_not_after: u64,
    local: &LocalCheckpoint,
) -> Result<(), AuthFrameError> {
    if frame_hash != local.hash.as_slice()
        || frame_sequence != local.sequence
        || frame_event_head != local.event_head.as_slice()
        || frame_not_after != local.not_after
    {
        return Err(AuthFrameError::CheckpointMismatch);
    }
    Ok(())
}

fn sig_array(sig: &[u8]) -> Result<[u8; 64], AuthFrameError> {
    sig.to_vec()
        .try_into()
        .map_err(|_| AuthFrameError::ShapeMismatch)
}

/// The result of a completed auth ceremony. Opaque: does not expose the
/// raw stream or `TransportState` — see the module hardening note (also
/// noise.rs's) on why `HandshakeOutcome` itself is `pub(crate)`. Rekey
/// operations couple the counter transition to the real Noise-level
/// rekey call; there is no way to advance one without the other.
///
/// **`gate: G` embedded, not tupled (2026-08-04, @kiana, definitive A) —
/// supersedes the earlier `(ActiveMeshSession<S>, D1::ActiveGate)`
/// tuple-return formulation:** `D1Admission::activate_if_authorized`
/// still returns the opaque gate, but the handshake function that
/// constructs a session moves it directly into this private field in the
/// same expression — the gate is never a separate value a caller could
/// receive and then drop, hold, or move independently of the session that
/// depends on it. There is no accessor: nothing in this crate, and
/// nothing an external caller could write, can extract `gate` while
/// retaining a usable `ActiveMeshSession`. Dropping the session drops
/// `G`, running whatever unregister/revoke semantics the real
/// `D1::ActiveGate` type's own `Drop` impl gives it — the session's own
/// lifetime *is* the gate's.
///
/// Even a caller who already holds a value of this type (the type itself
/// is `pub` so it can appear in a signature — only *constructing* one is
/// `pub(crate)`) cannot pattern-match `gate` back out, because the field
/// is private:
///
/// ```compile_fail
/// use mesh_session_core_rs::auth_state_machine::ActiveMeshSession;
/// fn takes_gate_only<T, G>(session: ActiveMeshSession<T, G>) -> G {
///     let ActiveMeshSession { gate, .. } = session; // field is private — does not compile
///     gate
/// }
/// ```
pub struct ActiveMeshSession<T, G> {
    #[allow(dead_code)]
    // kept for a future DATA-driving caller; not read by anything in this crate yet
    stream: T,
    transport: TransportState,
    rekey: SessionRekeyState,
    peer_hh_id: String,
    peer_m_id: String,
    peer_cert_fingerprint: Vec<u8>,
    ingress_evidence: IngressEvidence,
    h_final: Vec<u8>,
    #[allow(dead_code)]
    // never read by this crate — its entire purpose is to exist and Drop
    // at the right time; see the struct doc.
    gate: G,
}

impl<T, G> ActiveMeshSession<T, G> {
    pub fn peer_hh_id(&self) -> &str {
        &self.peer_hh_id
    }
    pub fn peer_m_id(&self) -> &str {
        &self.peer_m_id
    }
    pub fn peer_cert_fingerprint(&self) -> &[u8] {
        &self.peer_cert_fingerprint
    }
    pub fn h_final(&self) -> &[u8] {
        &self.h_final
    }
    pub fn ingress_evidence(&self) -> &IngressEvidence {
        &self.ingress_evidence
    }

    pub fn before_send_non_marker(
        &mut self,
    ) -> Result<rekey::SendNonMarkerPermit, crate::error::RekeyError> {
        self.rekey.tx().before_send_non_marker()
    }
    pub fn after_send_non_marker(
        &mut self,
        permit: rekey::SendNonMarkerPermit,
    ) -> Result<(), crate::error::RekeyError> {
        self.rekey.tx().after_send_non_marker(permit)
    }
    pub fn before_outgoing_rekey(
        &mut self,
    ) -> Result<rekey::SendMarkerPermit, crate::error::RekeyError> {
        self.rekey.tx().before_send_marker()
    }
    /// Couples the tx counter transition to the real
    /// `TransportState::rekey_outgoing()` — a caller cannot commit one
    /// without the other. Validates the permit (issuer + generation/
    /// policy_count snapshot) *before* touching `transport` (2026-08-04,
    /// @kiana): the real Noise-level rekey must never fire on a stale or
    /// foreign permit, so the check that can reject it runs first.
    pub fn commit_outgoing_rekey(
        &mut self,
        permit: rekey::SendMarkerPermit,
    ) -> Result<(), crate::error::RekeyError> {
        self.rekey.tx().validate_marker_permit(&permit)?;
        self.transport.rekey_outgoing();
        self.rekey.tx().after_send_marker(permit)
    }
    pub fn observe_incoming_non_marker(&mut self) -> Result<(), crate::error::RekeyError> {
        self.rekey.rx().on_receive(rekey::IncomingRecord::NonMarker)
    }
    /// Couples the rx counter transition to the real
    /// `TransportState::rekey_incoming()` — validated first, and the real
    /// rekey only happens if validation succeeds.
    pub fn commit_incoming_rekey(
        &mut self,
        next_generation: u64,
    ) -> Result<(), crate::error::RekeyError> {
        self.rekey
            .rx()
            .on_receive(rekey::IncomingRecord::Marker { next_generation })?;
        self.transport.rekey_incoming();
        Ok(())
    }
}

/// D9 carrier-B addendum §4 combined check, items not already covered by
/// the existing Proof-I checks the caller runs first (`check_h_final`,
/// `expected_peer_m_id`/fingerprint, `check_checkpoint`,
/// `pass_delegation_gate` — which already enforces item 2 and, since it
/// takes `expected_channel`, item 7 too — and `verify_frame` for Proof-I's
/// own signature). This function covers items 3/4/5/6/8; item 1 already
/// ran inside `decode_intent_record`; item 9 is "checkpoint is audit-only
/// on the intent, live-checked via Proof-I's own checkpoint elsewhere" —
/// deliberately not touched here, `intent_record.checkpoint_hash()` is
/// never read by this function.
///
/// Returns the nonce-ledger key on success — this function does NOT
/// consume the nonce itself; the caller does that as a separate, final,
/// single call site (addendum §5).
#[allow(clippy::too_many_arguments)]
fn run_combined_intent_check(
    intent_record: &crate::intent::SignedMeshConnectionIntent,
    received_intent_digest: &[u8; 32],
    proof_i: &ProofI,
    initiator_verifier: &auth_frames::RawP256FrameVerifier,
    local: &LocalIdentity,
    now: u64,
) -> Result<crate::intent::IntentNonceKey, AuthFrameError> {
    // Item 3: intent signature verified against the SAME resolved key as
    // Proof-I's own delegation — never a key the intent names itself
    // (self-consistency does not authorize).
    crate::intent::verify_intent_record(intent_record, initiator_verifier)
        .map_err(AuthFrameError::from)?;

    // Item 4: delegated_key_id byte-for-byte equality.
    if intent_record.delegated_key_id() != proof_i.delegation().delegated_key_id() {
        return Err(crate::error::IntentError::KeyIdMismatch.into());
    }

    // Item 5: Proof-I's digest commitment matches the record actually
    // received (not merely trusted).
    if proof_i.connection_intent_digest().as_bytes() != received_intent_digest {
        return Err(crate::error::IntentError::DigestMismatch.into());
    }

    // Item 6: household/initiator/target/fingerprint, cross-checked
    // against both Proof-I and this responder's own local identity — the
    // intent's own `target_*` fields must name THIS machine.
    if intent_record.hh_id() != proof_i.hh_id()
        || intent_record.initiator_m_id() != proof_i.self_m_id()
        || intent_record.initiator_cert_fingerprint() != proof_i.self_cert_fingerprint()
        || intent_record.target_m_id() != local.m_id
        || intent_record.target_cert_fingerprint() != local.cert_fingerprint.as_slice()
    {
        return Err(crate::error::IntentError::IdentityMismatch.into());
    }

    // Item 8: half-open TTL against the delegation's own window, not just
    // the intent's own claim.
    if !(now < intent_record.not_after()
        && intent_record.not_after() <= proof_i.delegation().not_after())
    {
        return Err(crate::error::IntentError::TtlInvalid.into());
    }

    // 2026-08-04, @kiana, erratum1 E2: the nonce key deliberately excludes
    // both channel and intent_digest — see IntentNonceKey's own doc.
    let nonce: [u8; 32] = intent_record
        .nonce()
        .try_into()
        .map_err(|_| crate::error::IntentError::ShapeMismatch)?;
    Ok(crate::intent::IntentNonceKey {
        hh_id: intent_record.hh_id().to_string(),
        initiator_m_id: intent_record.initiator_m_id().to_string(),
        delegated_key_id: intent_record.delegated_key_id().to_string(),
        nonce,
    })
}

/// Drive the responder side: Idle → Handshaking → SendingProofR →
/// AwaitingIntent → AwaitingProofI → SendingFinalConfirm →
/// AwaitingActivate → Active. `ingress` is consumed internally — its
/// stream and evidence are never handed back to the caller separately
/// (hardened 2026-08-04). See the module doc for why this is
/// `pub(crate)`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_responder_handshake<S, Sig, Ver, Ledger, D1, C>(
    ingress: PrevalidatedIngress<S>,
    local: &LocalIdentity,
    checkpoint: &LocalCheckpoint,
    expected_channel: ExpectedChannel,
    policy: &DelegationPolicy,
    delegation_verifier: &Ver,
    k_mesh: &Sig,
    nonce_ledger: &Ledger,
    d1_admission: &D1,
    clock: &C,
    rekey_threshold: RekeyThreshold,
) -> Result<ActiveMeshSession<S, D1::ActiveGate>, AuthFrameError>
where
    S: Read + Write + wire::DeadlineBoundedIo,
    Sig: MeshSessionFrameSigner,
    Ver: DelegationSignatureVerifier,
    Ledger: crate::intent::IntentNonceLedger,
    D1: crate::intent::D1Admission,
    C: crate::intent::Clock,
{
    check_signer_matches_delegation(k_mesh, &local.delegation)?;
    check_local_delegation_channel(&local.delegation, expected_channel)?;
    // 2026-08-04, @kiana, round 4: minted here — before any I/O at all,
    // long before ActivateAck is ever written — not after. See the
    // hardening note on ActiveMeshSession's construction below for why.
    let rekey = SessionRekeyState::new(rekey_threshold)?;

    let (mut stream, ingress_evidence, deadline) = ingress.consume();
    // 2026-08-04, @kiana, definitive B: `deadline` is the opaque,
    // monotonic `CeremonyDeadline` born at admission (`admit_at_accept`),
    // not a separately-suppliable parameter this function's caller could
    // pick independently. Expiry checked before the first Noise byte too,
    // not only after — an already-expired admission never even attempts
    // the handshake.
    check_ceremony_deadline(&deadline)?;

    let handshake = noise::run_xx_handshake(&mut stream, Role::Responder, &deadline)?;
    let mut transport = handshake.transport;
    let h_final = handshake.handshake_hash;
    check_ceremony_deadline(&deadline)?;

    // --- Frame 1: Proof-R, R -> I ---
    let proof_r = ProofR::new(
        h_final.clone(),
        local.hh_id.clone(),
        local.m_id.clone(),
        local.cert_fingerprint.clone(),
        checkpoint.hash.clone(),
        checkpoint.sequence,
        checkpoint.event_head.clone(),
        checkpoint.not_after,
        local.delegation.clone(),
        vec![0u8; 64],
    )?;
    let proof_r = auth_frames::sign_frame(proof_r, k_mesh)?;
    send_frame(
        &mut stream,
        &mut transport,
        &AuthFrame::ProofR(proof_r),
        &deadline,
    )?;

    // --- Intent record, 0x06, I -> R (D9 carrier-B addendum §3): state
    // SendingProofR -> AwaitingIntent -> AwaitingProofI. Exactly one
    // record is legal here; anything else (Proof-I arriving instead, a
    // duplicate 0x06, or 0x07) fails this read/decode and closes without
    // FinalConfirm, without needing a separate dedup/ordering check —
    // decode_intent_record rejects any type byte but 0x06, and this is
    // the ONE read call in the whole function that accepts one, ever.
    // Combined-check item 1 (domain/version/shape/canonicality/low-S) is
    // fully checked inside decode_intent_record; nothing here is
    // authority yet and no nonce is consumed yet (addendum §3).
    let intent_record = recv_intent_record(&mut stream, &mut transport, &deadline)?;
    let received_intent_digest = crate::intent::intent_digest(&intent_record)?;
    check_ceremony_deadline(&deadline)?;

    // --- Frame 2: Proof-I, I -> R ---
    let proof_i = match recv_frame(&mut stream, &mut transport, &deadline)? {
        AuthFrame::ProofI(f) => f,
        _ => return Err(AuthFrameError::RoleOrKindMismatch),
    };
    check_h_final(proof_i.h_final(), &h_final)?;
    // 2026-08-04, @kiana: the responder must confirm the initiator's own
    // signed intent was actually to reach *this* machine — without this,
    // a validly-signed Proof-I addressed to a different responder (R2)
    // would be silently accepted by whichever responder (R1) it actually
    // reached. Must fail before FinalConfirm is ever sent.
    if proof_i.expected_peer_m_id() != local.m_id
        || proof_i.expected_peer_cert_fingerprint() != local.cert_fingerprint
    {
        return Err(AuthFrameError::ExpectedPeerMismatch);
    }
    check_checkpoint(
        proof_i.checkpoint_hash(),
        proof_i.checkpoint_sequence(),
        proof_i.checkpoint_event_head(),
        proof_i.checkpoint_not_after(),
        checkpoint,
    )?;
    pass_delegation_gate(
        proof_i.delegation(),
        policy,
        delegation_verifier,
        &PartialBindingInputs {
            proof_hh_id: proof_i.hh_id().to_string(),
            local_hh_id: local.hh_id.clone(),
            proof_self_m_id: proof_i.self_m_id().to_string(),
            proof_self_cert_fingerprint: proof_i.self_cert_fingerprint().to_vec(),
        },
        expected_channel,
    )?;
    let initiator_verifier =
        auth_frames::verifier_from_delegated_pub(proof_i.delegation().delegated_pub())?;
    auth_frames::verify_frame(&proof_i, &sig_array(proof_i.sig())?, &initiator_verifier)?;

    let initiator_m_id = proof_i.self_m_id().to_string();
    let initiator_cert_fingerprint = proof_i.self_cert_fingerprint().to_vec();
    let initiator_hh_id = proof_i.hh_id().to_string();

    // --- Combined intent check (D9 carrier-B addendum §4), then the
    // single nonce-consumption call site (addendum §5) ---
    let now = clock.now().map_err(AuthFrameError::from)?;
    let nonce_key = run_combined_intent_check(
        &intent_record,
        &received_intent_digest,
        &proof_i,
        &initiator_verifier,
        local,
        now,
    )?;
    // 2026-08-04, @kiana, C.3: checked immediately before consume — an
    // already-expired deadline here means zero nonce burn is attempted.
    check_ceremony_deadline(&deadline)?;
    // 2026-08-04, @kiana: not_after/digest passed as evidence, never
    // folded into the replay key itself (erratum1 E2). C.2: only
    // Committed lets the ceremony proceed; the other 3 outcomes close it,
    // never a blind retry — MayHaveTakenEffect in particular requires a
    // real ledger to reread/reconcile before this key is ever tried
    // again, which this function cannot and does not attempt itself.
    match nonce_ledger.consume(
        &nonce_key,
        intent_record.not_after(),
        &received_intent_digest,
        &deadline,
    )? {
        crate::intent::NonceConsumeOutcome::Committed => {}
        crate::intent::NonceConsumeOutcome::AlreadyConsumed => {
            return Err(crate::error::IntentError::NonceAlreadyConsumed.into());
        }
        crate::intent::NonceConsumeOutcome::MayHaveTakenEffect => {
            return Err(crate::error::IntentError::NonceCommitAmbiguous.into());
        }
        crate::intent::NonceConsumeOutcome::Unavailable => {
            return Err(crate::error::IntentError::NonceLedgerUnavailable.into());
        }
    }
    check_ceremony_deadline(&deadline)?;

    // --- Frame 3: FinalConfirm, R -> I ---
    let final_confirm = FinalConfirm::new(
        h_final.clone(),
        initiator_m_id.clone(),
        initiator_cert_fingerprint.clone(),
        local.m_id.clone(),
        vec![0u8; 64],
    )?;
    let final_confirm = auth_frames::sign_frame(final_confirm, k_mesh)?;
    send_frame(
        &mut stream,
        &mut transport,
        &AuthFrame::FinalConfirm(final_confirm.clone()),
        &deadline,
    )?;
    check_ceremony_deadline(&deadline)?;

    // --- Frame 4: Activate, I -> R ---
    let activate = match recv_frame(&mut stream, &mut transport, &deadline)? {
        AuthFrame::Activate(f) => f,
        _ => return Err(AuthFrameError::RoleOrKindMismatch),
    };
    check_h_final(activate.h_final(), &h_final)?;
    if activate.responder_m_id() != local.m_id {
        return Err(AuthFrameError::ExpectedPeerMismatch);
    }
    let expected_final_confirm_digest = auth_frames::frame_digest(&final_confirm)?;
    if activate.final_confirm_digest() != expected_final_confirm_digest {
        return Err(AuthFrameError::DigestMismatch);
    }
    auth_frames::verify_frame(&activate, &sig_array(activate.sig())?, &initiator_verifier)?;
    check_ceremony_deadline(&deadline)?;

    // --- Erratum + erratum1 E4: two-phase D1 admission around
    // ActivateAck's atomic linearization ---
    // 1. verify done above. 2. build the Ack (PendingAuthorized, DATA gate
    // still closed — there is no DATA gate object because DATA is out of
    // scope; the gate is structural: no ActiveMeshSession exists yet).
    let activate_digest = auth_frames::frame_digest(&activate)?;
    let activate_ack = ActivateAck::new(
        h_final.clone(),
        local.m_id.clone(),
        activate_digest.to_vec(),
        vec![0u8; 64],
    )?;
    let activate_ack = auth_frames::sign_frame(activate_ack, k_mesh)?;

    // 2026-08-04, @kiana, erratum1 E4 + C.4 (definitive): reserve the D1
    // Pending permit BEFORE the Ack write, against the FULL authenticated
    // binding — this ceremony's own session_id (h_final), the AUTHENTICATED
    // initiator fingerprint (verified above via pass_delegation_gate/
    // verify_frame, not a bare claim), the resolved delegated_pub, and the
    // live checkpoint/expiry this ceremony actually ran against. A real
    // implementation must recheck this exact binding again in
    // `activate_if_authorized`, not merely re-read by `peer_m_id`.
    // Role-neutral (2026-08-04, @kiana): on the responder side, `peer_*`
    // is the initiator (the other party) and `local_*` is this machine.
    let d1_key = crate::intent::D1AdmissionKey {
        session_id: h_final.clone(),
        hh_id: initiator_hh_id.clone(),
        peer_m_id: initiator_m_id.clone(),
        peer_cert_fingerprint: initiator_cert_fingerprint.clone(),
        local_m_id: local.m_id.clone(),
        local_cert_fingerprint: local.cert_fingerprint.clone(),
        delegated_key_id: nonce_key.delegated_key_id.clone(),
        delegated_pub: proof_i.delegation().delegated_pub().to_vec(),
        checkpoint_hash: checkpoint.hash.clone(),
        checkpoint_sequence: checkpoint.sequence,
        checkpoint_event_head: checkpoint.event_head.clone(),
        checkpoint_not_after: checkpoint.not_after,
        not_after: intent_record.not_after(),
        channel: expected_channel,
    };
    let pending = d1_admission.reserve_pending(&d1_key, &deadline)?;

    // 3. write_all (write_transport_record uses write_all internally).
    // 2026-08-04, @kiana, round 4: `rekey` was minted at the top of this
    // function, before any I/O — nothing fallible runs between here and
    // the D1 outcome below except the two D1 calls themselves.
    match send_frame(
        &mut stream,
        &mut transport,
        &AuthFrame::ActivateAck(activate_ack),
        &deadline,
    ) {
        Ok(()) => {}
        Err(e) => {
            // 3b: write failed/partial — abort, remove Pending, gate
            // never opens, zero effect for this attempt (same "erratum"
            // discipline the write itself already had, now extended one
            // step further to cover the D1 permit too). 2026-08-04,
            // @kiana, WIP audit item (b): `e` (the write failure) is the
            // actual cause and is what this attempt reports; a
            // cancel-confirmation failure is explicitly acknowledged
            // (not left as an unchecked Result) rather than silently
            // discarded — `Self::Pending`'s own Drop is the structural
            // safety net if cancellation itself cannot be confirmed, see
            // `D1Admission::cancel_pending`'s doc.
            let _ = d1_admission.cancel_pending(pending, &deadline);
            return Err(e);
        }
    }

    // 3a/4: write succeeded. NOTHING fallible or external runs between
    // this line and the call below — activate_if_authorized is the very
    // next statement, consuming `pending` — so a concurrent revoke
    // observed by a real implementation at this exact synchronized point
    // can still close the session instead of opening it; only on Ok(gate)
    // below does an ActiveMeshSession ever get constructed, and `gate` is
    // embedded directly into it (2026-08-04, @kiana, definitive A —
    // never returned separately, never droppable while the session lives).
    let gate = d1_admission.activate_if_authorized(pending, &deadline)?;

    // 2026-08-04, @kiana, lifecycle CFX: exactly one operation between Ack
    // write success and here (the call above) — now, and only now, clear
    // the per-ceremony socket deadline this stream may have accumulated,
    // BEFORE the session is ever exposed. A real `TcpStream`'s
    // `SO_RCVTIMEO`/`SO_SNDTIMEO` persist across `arm_io_deadline` calls;
    // without this, Active's own future DATA/CLOSE/rekey I/O would
    // silently inherit whatever (possibly near-zero) timeout the last
    // ceremony syscall happened to arm. If clearing fails, `gate` is
    // dropped right here — never embedded into a session — so its own
    // `Drop` unregisters/revokes exactly as if this attempt had failed at
    // any earlier step; no `ActiveMeshSession` is ever returned.
    if stream.clear_io_deadline().is_err() {
        drop(gate);
        return Err(crate::error::IntentError::PostActivationCleanupFailed.into());
    }

    Ok(ActiveMeshSession {
        stream,
        transport,
        rekey,
        peer_hh_id: initiator_hh_id,
        peer_m_id: initiator_m_id,
        peer_cert_fingerprint: initiator_cert_fingerprint,
        ingress_evidence,
        h_final,
        gate,
    })
}

/// Drive the initiator side: Idle → Handshaking → AwaitingProofR →
/// SendingProofI → AwaitingFinalConfirm → SendingActivate →
/// AwaitingActivateAck → Active. See the module doc for why this is
/// `pub(crate)`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_initiator_handshake<S, Sig, Ver, D1, C>(
    ingress: PrevalidatedIngress<S>,
    pending_intent: crate::intent::PendingIntent,
    local: &LocalIdentity,
    checkpoint: &LocalCheckpoint,
    expected_channel: ExpectedChannel,
    policy: &DelegationPolicy,
    delegation_verifier: &Ver,
    k_mesh: &Sig,
    d1_admission: &D1,
    // 2026-08-04: kept for signature symmetry with `run_responder_handshake`
    // (which needs `Clock` for the combined intent check's TTL read) —
    // the initiator side's own TTL/freshness checks all run through
    // `PendingIntent::verify_binds_to` against `local.delegation`
    // directly, so this crate never reads a live clock here. Flagged to
    // kiana as a candidate for removal rather than dropped unilaterally,
    // since it changes this function's public shape.
    #[allow(unused_variables)] clock: &C,
    rekey_threshold: RekeyThreshold,
) -> Result<ActiveMeshSession<S, D1::ActiveGate>, AuthFrameError>
where
    S: Read + Write + wire::DeadlineBoundedIo,
    Sig: MeshSessionFrameSigner,
    Ver: DelegationSignatureVerifier,
    D1: crate::intent::D1Admission,
    C: crate::intent::Clock,
{
    check_signer_matches_delegation(k_mesh, &local.delegation)?;
    check_local_delegation_channel(&local.delegation, expected_channel)?;
    // 2026-08-04, @kiana, C.5 (widened, WIP audit item 3): the FULL
    // binding this token was built against — signer key bytes, identity
    // scalars, delegation version (serial/window, actual delegated_pub
    // bytes), and the checkpoint it was built for — cross-checked against
    // what this ceremony is actually about to run with, before any I/O.
    // Supersedes the earlier bare `pending_intent.channel() !=
    // expected_channel` check, which is now one of several fields this
    // covers.
    pending_intent.verify_binds_to(local, checkpoint, k_mesh, expected_channel)?;
    // 2026-08-04, @kiana, D9 carrier-B addendum §3 step 2 / erratum1 E1:
    // ExpectedResponder is derived from the admission token, never a
    // second, independently-suppliable parameter — the initiator is the
    // ONLY side that ever has or trusts one.
    let expected = pending_intent.expected_responder();
    // 2026-08-04, @kiana, round 4: minted here — before Proof-I, before
    // Activate, before anything is sent at all. If the mint fails, this
    // side sends literally nothing, so there is no possibility the peer
    // observes any progress from this attempt at all.
    let rekey = SessionRekeyState::new(rekey_threshold)?;

    let (mut stream, ingress_evidence, deadline) = ingress.consume();
    // 2026-08-04, @kiana, definitive B: opaque monotonic deadline born at
    // admission, same as the responder side — checked before the first
    // Noise byte too.
    check_ceremony_deadline(&deadline)?;

    let handshake = noise::run_xx_handshake(&mut stream, Role::Initiator, &deadline)?;
    let mut transport = handshake.transport;
    let h_final = handshake.handshake_hash;
    check_ceremony_deadline(&deadline)?;

    // --- Frame 1: Proof-R, R -> I ---
    let proof_r = match recv_frame(&mut stream, &mut transport, &deadline)? {
        AuthFrame::ProofR(f) => f,
        _ => return Err(AuthFrameError::RoleOrKindMismatch),
    };
    check_h_final(proof_r.h_final(), &h_final)?;
    // v6 §1: "Se Proof-R não corresponde -> ExpectedPeerMismatch -> zero Proof-I -> close."
    if proof_r.hh_id() != expected.hh_id
        || proof_r.self_m_id() != expected.m_id
        || proof_r.self_cert_fingerprint() != expected.cert_fingerprint
    {
        return Err(AuthFrameError::ExpectedPeerMismatch);
    }
    check_checkpoint(
        proof_r.checkpoint_hash(),
        proof_r.checkpoint_sequence(),
        proof_r.checkpoint_event_head(),
        proof_r.checkpoint_not_after(),
        checkpoint,
    )?;
    pass_delegation_gate(
        proof_r.delegation(),
        policy,
        delegation_verifier,
        &PartialBindingInputs {
            proof_hh_id: proof_r.hh_id().to_string(),
            local_hh_id: local.hh_id.clone(),
            proof_self_m_id: proof_r.self_m_id().to_string(),
            proof_self_cert_fingerprint: proof_r.self_cert_fingerprint().to_vec(),
        },
        expected_channel,
    )?;
    let responder_verifier =
        auth_frames::verifier_from_delegated_pub(proof_r.delegation().delegated_pub())?;
    auth_frames::verify_frame(&proof_r, &sig_array(proof_r.sig())?, &responder_verifier)?;

    // --- Intent record, 0x06, I -> R (D9 carrier-B addendum §3) ---
    // Sent only now that Proof-R has been verified in full — "Proof-R
    // inválido implica zero bytes 0x06 escritos." State: AwaitingProofR
    // -> SendingIntent -> SendingProofI.
    send_intent_record(
        &mut stream,
        &mut transport,
        pending_intent.intent(),
        &deadline,
    )?;
    // connection_intent_digest is derived from the SAME record just sent
    // — never an independently-suppliable value (2026-08-04, @kiana,
    // integration addendum: "raw digest/bare ids não iniciam handshake").
    let connection_intent_digest =
        ConnectionIntentDigest::from_bytes(crate::intent::intent_digest(pending_intent.intent())?);
    check_ceremony_deadline(&deadline)?;

    // --- Frame 2: Proof-I, I -> R ---
    let proof_i = ProofI::new(
        h_final.clone(),
        local.hh_id.clone(),
        local.m_id.clone(),
        expected.m_id.clone(),
        local.cert_fingerprint.clone(),
        expected.cert_fingerprint.to_vec(),
        checkpoint.hash.clone(),
        checkpoint.sequence,
        checkpoint.event_head.clone(),
        checkpoint.not_after,
        local.delegation.clone(),
        connection_intent_digest,
        vec![0u8; 64],
    )?;
    let proof_i = auth_frames::sign_frame(proof_i, k_mesh)?;
    send_frame(
        &mut stream,
        &mut transport,
        &AuthFrame::ProofI(proof_i),
        &deadline,
    )?;
    check_ceremony_deadline(&deadline)?;

    // --- Frame 3: FinalConfirm, R -> I ---
    let final_confirm = match recv_frame(&mut stream, &mut transport, &deadline)? {
        AuthFrame::FinalConfirm(f) => f,
        _ => return Err(AuthFrameError::RoleOrKindMismatch),
    };
    check_h_final(final_confirm.h_final(), &h_final)?;
    if final_confirm.initiator_m_id() != local.m_id
        || final_confirm.initiator_cert_fingerprint() != local.cert_fingerprint
        || final_confirm.responder_m_id() != expected.m_id
    {
        return Err(AuthFrameError::ExpectedPeerMismatch);
    }
    auth_frames::verify_frame(
        &final_confirm,
        &sig_array(final_confirm.sig())?,
        &responder_verifier,
    )?;
    check_ceremony_deadline(&deadline)?;

    // --- Frame 4: Activate, I -> R ---
    let final_confirm_digest = auth_frames::frame_digest(&final_confirm)?;
    let activate = Activate::new(
        h_final.clone(),
        expected.m_id.clone(),
        final_confirm_digest.to_vec(),
        vec![0u8; 64],
    )?;
    let activate = auth_frames::sign_frame(activate, k_mesh)?;

    // 2026-08-04, @kiana, erratum1 E4 closing paragraph + C.4 (definitive):
    // the initiator applies the SAME local discipline while awaiting
    // ActivateAck, against the SAME richer, authenticated binding as the
    // responder side — Pending/gate closed before Activate is sent,
    // commit immediately on a valid Ack, cancel on any error/timeout in
    // between.
    // Role-neutral (2026-08-04, @kiana): on the initiator side, `local_*`
    // is this machine (the initiator) and `peer_*` is the responder.
    let d1_key = crate::intent::D1AdmissionKey {
        session_id: h_final.clone(),
        hh_id: local.hh_id.clone(),
        local_m_id: local.m_id.clone(),
        local_cert_fingerprint: local.cert_fingerprint.clone(),
        peer_m_id: expected.m_id.clone(),
        peer_cert_fingerprint: expected.cert_fingerprint.to_vec(),
        delegated_key_id: pending_intent.intent().delegated_key_id().to_string(),
        delegated_pub: local.delegation.delegated_pub().to_vec(),
        checkpoint_hash: checkpoint.hash.clone(),
        checkpoint_sequence: checkpoint.sequence,
        checkpoint_event_head: checkpoint.event_head.clone(),
        checkpoint_not_after: checkpoint.not_after,
        not_after: pending_intent.intent().not_after(),
        channel: expected_channel,
    };
    let pending = d1_admission.reserve_pending(&d1_key, &deadline)?;

    // --- Frame 5: ActivateAck, R -> I ---
    // "I só transita Active após decrypt + verify ActivateAck" (v6 §13).
    // Everything from sending Activate through fully verifying the Ack is
    // one fallible unit: ANY failure here must cancel the just-reserved
    // Pending before propagating, not just return the error directly.
    let ack_result = (|| -> Result<ActivateAck, AuthFrameError> {
        send_frame(
            &mut stream,
            &mut transport,
            &AuthFrame::Activate(activate.clone()),
            &deadline,
        )?;
        let activate_ack = match recv_frame(&mut stream, &mut transport, &deadline)? {
            AuthFrame::ActivateAck(f) => f,
            _ => return Err(AuthFrameError::RoleOrKindMismatch),
        };
        check_h_final(activate_ack.h_final(), &h_final)?;
        if activate_ack.responder_m_id() != expected.m_id {
            return Err(AuthFrameError::ExpectedPeerMismatch);
        }
        let expected_activate_digest = auth_frames::frame_digest(&activate)?;
        if activate_ack.activate_digest() != expected_activate_digest {
            return Err(AuthFrameError::DigestMismatch);
        }
        auth_frames::verify_frame(
            &activate_ack,
            &sig_array(activate_ack.sig())?,
            &responder_verifier,
        )?;
        check_ceremony_deadline(&deadline)?;
        Ok(activate_ack)
    })();

    let _activate_ack = match ack_result {
        Ok(ack) => ack,
        Err(e) => {
            // 2026-08-04, @kiana, WIP audit item (b): cancel_pending now
            // returns Result rather than silently swallowing a real
            // implementation's own inability to confirm cleanup. The
            // ORIGINAL failure `e` is still what this attempt reports —
            // it is the actual cause — but a cancel-confirmation failure
            // is not silently discarded either; it is explicitly
            // acknowledged here rather than left as an unchecked Result.
            // A residual gap: this narrow abort path has nowhere to
            // surface a cancel-ambiguity distinctly from `e` without this
            // crate inventing an error-aggregation mechanism the frozen
            // spec does not otherwise call for.
            let _ = d1_admission.cancel_pending(pending, &deadline);
            return Err(e);
        }
    };

    // Ack valid, verified in full: commit the local Pending immediately,
    // nothing fallible/external between the check above and this call.
    let gate = d1_admission.activate_if_authorized(pending, &deadline)?;

    // 2026-08-04, @kiana, lifecycle CFX — see the identical note in
    // run_responder_handshake: clear the per-ceremony socket deadline
    // before ever exposing the session; if that fails, drop `gate`
    // (triggering its own revoke) and return an error instead of a
    // session with a leaked timeout.
    if stream.clear_io_deadline().is_err() {
        drop(gate);
        return Err(crate::error::IntentError::PostActivationCleanupFailed.into());
    }

    // 2026-08-04, @kiana, round 4: `rekey` was minted at the top of this
    // function, before Activate was ever sent — nothing fallible remains
    // between ActivateAck's verification above and this `Ok` below.
    Ok(ActiveMeshSession {
        stream,
        transport,
        rekey,
        peer_hh_id: expected.hh_id.clone(),
        peer_m_id: expected.m_id.clone(),
        peer_cert_fingerprint: expected.cert_fingerprint.to_vec(),
        ingress_evidence,
        h_final,
        gate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RekeyError;
    use crate::ingress::{CeremonyBudget, CeremonyDeadlinePolicy};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use rand_core::OsRng;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    struct TestKMesh(SigningKey);
    impl MeshSessionFrameSigner for TestKMesh {
        fn sign_mesh_session_frame(
            &self,
            preimage: &crate::auth_frames::MeshSessionFramePreimage,
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

    /// Test-only stand-in that accepts any delegation, unconditionally —
    /// proves the *state machine's wiring* (order of calls, what gates
    /// what) independent of the still-undecided real preimage/verifier.
    /// Never shipped as part of this crate's real API.
    struct AlwaysAcceptDelegation;
    impl DelegationSignatureVerifier for AlwaysAcceptDelegation {
        fn verify_delegation(
            &self,
            _delegation: &MeshSessionDelegation,
        ) -> Result<(), crate::error::DelegationError> {
            Ok(())
        }
    }

    /// Always-succeeding D1Admission double: `Pending`/`ActiveGate` are
    /// just `()`. Used by tests where D1 admission's own mechanism isn't
    /// under test — the dedicated D1 REDs inject their own doubles.
    struct AlwaysAdmitD1;
    impl crate::intent::D1Admission for AlwaysAdmitD1 {
        type Pending = ();
        type ActiveGate = ();
        fn reserve_pending(
            &self,
            _key: &crate::intent::D1AdmissionKey,
            _deadline: &CeremonyDeadline,
        ) -> Result<(), crate::error::IntentError> {
            Ok(())
        }
        fn activate_if_authorized(
            &self,
            _pending: (),
            _deadline: &CeremonyDeadline,
        ) -> Result<(), crate::error::IntentError> {
            Ok(())
        }
        fn cancel_pending(
            &self,
            _pending: (),
            _deadline: &CeremonyDeadline,
        ) -> Result<(), crate::error::IntentError> {
            Ok(())
        }
    }

    /// In-memory, single-process nonce ledger double — real check-and-set
    /// semantics (a `HashSet`), enough to prove replay rejection without
    /// any real persistence. `not_after`/`digest`/`deadline` are accepted
    /// (matching the real trait shape) but unused by this simple double —
    /// no eviction/blocking policy is under test here.
    struct InMemoryLedger {
        consumed: std::sync::Mutex<std::collections::HashSet<crate::intent::IntentNonceKey>>,
    }
    impl InMemoryLedger {
        fn new() -> Self {
            Self {
                consumed: std::sync::Mutex::new(std::collections::HashSet::new()),
            }
        }
    }
    impl crate::intent::IntentNonceLedger for InMemoryLedger {
        fn consume(
            &self,
            key: &crate::intent::IntentNonceKey,
            _not_after: u64,
            _digest: &[u8; 32],
            _deadline: &CeremonyDeadline,
        ) -> Result<crate::intent::NonceConsumeOutcome, crate::error::IntentError> {
            let mut set = self.consumed.lock().unwrap();
            if !set.insert(key.clone()) {
                return Ok(crate::intent::NonceConsumeOutcome::AlreadyConsumed);
            }
            Ok(crate::intent::NonceConsumeOutcome::Committed)
        }
    }

    /// Fixed-reading clock double. Fine for happy-path tests where the
    /// deadline is far in the future; the deadline-specific REDs use a
    /// dedicated advancing/expired clock instead.
    struct FixedClock(u64);
    impl crate::intent::Clock for FixedClock {
        fn now(&self) -> Result<u64, crate::error::IntentError> {
            Ok(self.0)
        }
    }

    fn far_future_deadline() -> CeremonyDeadline {
        CeremonyDeadline::for_test(std::time::Instant::now(), Duration::from_secs(3600))
    }

    /// A generous `CeremonyBudget` for happy-path tests where the ceremony
    /// deadline itself isn't under test — the deadline-specific REDs build
    /// their own tight/expired `CeremonyDeadline` via
    /// `CeremonyDeadline::for_test`/`already_expired_for_test` instead.
    fn far_future_budget() -> CeremonyBudget {
        let policy = CeremonyDeadlinePolicy::new(Duration::from_secs(3600)).unwrap();
        CeremonyBudget::new(Duration::from_secs(3600), &policy).unwrap()
    }

    /// Builds a `PendingIntent` whose initiator-side fields (hh_id/m_id/
    /// fingerprint/delegated_key_id) are derived from `local` (2026-08-04,
    /// @kiana: `IntentDetails` no longer carries them independently — see
    /// its own doc), `target_*` fields name the given responder, and
    /// `checkpoint_hash` matches `checkpoint` exactly (so
    /// `PendingIntent::verify_binds_to`'s checkpoint-binding check passes
    /// by construction in fixtures that pass the SAME checkpoint to both
    /// this and the later `run_initiator_handshake` call).
    #[allow(clippy::too_many_arguments)]
    fn pending_intent_for(
        k_mesh: &TestKMesh,
        local: &LocalIdentity,
        checkpoint: &LocalCheckpoint,
        target_m_id: &str,
        target_cert_fingerprint: Vec<u8>,
        nonce: [u8; 32],
        not_after: u64,
        channel: ExpectedChannel,
    ) -> crate::intent::PendingIntent {
        crate::intent::PendingIntent::build_and_sign(
            crate::intent::IntentDetails {
                target_m_id: target_m_id.to_string(),
                target_cert_fingerprint,
                nonce: nonce.to_vec(),
                not_after,
            },
            channel,
            local,
            checkpoint,
            k_mesh,
        )
        .unwrap()
    }

    fn fixed_checkpoint() -> LocalCheckpoint {
        LocalCheckpoint {
            hash: vec![0xAA; 32],
            sequence: 1,
            event_head: vec![0xBB; 32],
            not_after: 1_000_000,
        }
    }

    /// A delegation whose `delegated_pub` really is the SEC1-compressed
    /// form of `verifying` (so `verifier_from_delegated_pub`, which reads
    /// `delegated_pub` straight out of the received frame, constructs a
    /// verifier that actually matches the key `k_mesh` signs with),
    /// whose `hh_id`/`delegator_m_id`/`delegator_cert_fingerprint` match
    /// the identity presenting it (so `check_partial_binding`'s
    /// non-roster triple-equality checks — which compare the frame's own
    /// `hh_id`/`self_m_id`/`self_cert_fingerprint` against these exact
    /// fields — actually pass), and whose `roles`/`transcript_kinds`
    /// exactly match `EXPECTED_DELEGATION_ROLES`/`EXPECTED_TRANSCRIPT_KINDS`
    /// (2026-08-04, @kiana, round 5: `pass_delegation_gate` now enforces
    /// this exactly, so every fixture that expects to pass the gate needs
    /// to already satisfy it — see the round-5 REDs for what happens when
    /// it doesn't).
    fn delegation_for_key(
        verifying: &VerifyingKey,
        hh_id: &str,
        delegator_m_id: &str,
        delegator_cert_fingerprint: Vec<u8>,
        not_before: u64,
        not_after: u64,
    ) -> MeshSessionDelegation {
        let delegated_pub = verifying.to_encoded_point(true).as_bytes().to_vec();
        crate::delegation::DelegationWire {
            version: crate::delegation::DELEGATION_VERSION,
            kind: crate::delegation::DELEGATION_KIND.to_string(),
            domain: crate::delegation::DELEGATION_DOMAIN.to_string(),
            hh_id: hh_id.to_string(),
            delegator_m_id: delegator_m_id.to_string(),
            delegator_cert_fingerprint,
            delegated_pub,
            delegated_key_id: "key-1".to_string(),
            profile: crate::delegation::DELEGATION_PROFILE.to_string(),
            transcript_kinds: EXPECTED_TRANSCRIPT_KINDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            roles: EXPECTED_DELEGATION_ROLES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            channel: "dev".to_string(),
            serial: 1,
            not_before,
            not_after,
            sig: vec![0u8; 64],
        }
        .try_into()
        .unwrap()
    }

    /// Like [`delegation_for_key`], but every scoping field is caller
    /// controlled — used to build deliberately mis-scoped delegations for
    /// the round-5 REDs (missing/extra/duplicate role or transcript kind,
    /// wrong channel). `hh_id`/`delegator_m_id`/`delegator_cert_fingerprint`
    /// still default to values `pass_delegation_gate`'s scoping checks
    /// don't depend on — irrelevant for these tests since the checks
    /// under test fire before `check_partial_binding` is ever reached.
    fn delegation_wire_with(
        verifying: &VerifyingKey,
        roles: Vec<String>,
        transcript_kinds: Vec<String>,
        channel: &str,
    ) -> MeshSessionDelegation {
        let delegated_pub = verifying.to_encoded_point(true).as_bytes().to_vec();
        crate::delegation::DelegationWire {
            version: crate::delegation::DELEGATION_VERSION,
            kind: crate::delegation::DELEGATION_KIND.to_string(),
            domain: crate::delegation::DELEGATION_DOMAIN.to_string(),
            hh_id: "hh-1".to_string(),
            delegator_m_id: "someone-1".to_string(),
            delegator_cert_fingerprint: vec![0xCC; 32],
            delegated_pub,
            delegated_key_id: "key-1".to_string(),
            profile: crate::delegation::DELEGATION_PROFILE.to_string(),
            transcript_kinds,
            roles,
            channel: channel.to_string(),
            serial: 1,
            not_before: 0,
            not_after: u64::MAX / 2,
            sig: vec![0u8; 64],
        }
        .try_into()
        .unwrap()
    }

    fn valid_roles() -> Vec<String> {
        EXPECTED_DELEGATION_ROLES
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn valid_transcript_kinds() -> Vec<String> {
        EXPECTED_TRANSCRIPT_KINDS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn identity(
        hh_id: &str,
        m_id: &str,
        cert_fingerprint: Vec<u8>,
        delegation: MeshSessionDelegation,
    ) -> LocalIdentity {
        LocalIdentity {
            hh_id: hh_id.to_string(),
            m_id: m_id.to_string(),
            cert_fingerprint,
            delegation,
        }
    }

    /// Drives a full, real handshake over a real TCP loopback with both
    /// sides using `AlwaysAcceptDelegation` (the delegation-gate wiring is
    /// covered separately by `delegation_gate_blocks_with_no_verifier_configured`)
    /// and a real per-side P-256 K_mesh keypair, each with a delegation
    /// whose `delegated_pub` genuinely matches that key. Returns both
    /// sides' Active sessions for further assertions (POS-4, etc.).
    fn full_handshake() -> (
        ActiveMeshSession<TcpStream, ()>,
        ActiveMeshSession<TcpStream, ()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let responder_key = SigningKey::random(&mut OsRng);
        let responder_verifying = VerifyingKey::from(&responder_key);
        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_verifying = VerifyingKey::from(&initiator_key);

        let responder_delegation = delegation_for_key(
            &responder_verifying,
            "hh-1",
            "responder-1",
            vec![0xCC; 32],
            0,
            u64::MAX / 2,
        );
        let responder_identity =
            identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence { observed_at: 1 },
                    far_future_budget(),
                );
                run_responder_handshake(
                    ingress,
                    &responder_identity,
                    &checkpoint,
                    ExpectedChannel::Dev,
                    &DelegationPolicy::test(u64::MAX / 2),
                    &AlwaysAcceptDelegation,
                    &k_mesh,
                    &InMemoryLedger::new(),
                    &AlwaysAdmitD1,
                    &FixedClock(0),
                    RekeyThreshold::new(3).unwrap(),
                )
                .unwrap()
            }
        });

        let initiator_delegation = delegation_for_key(
            &initiator_verifying,
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            0,
            u64::MAX / 2,
        );
        let initiator_identity =
            identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
        let sock = TcpStream::connect(addr).unwrap();
        let ingress = PrevalidatedIngress::admit_at_accept(
            sock,
            IngressEvidence { observed_at: 2 },
            far_future_budget(),
        );
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &initiator_identity,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0x99; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );
        let initiator_session = run_initiator_handshake(
            ingress,
            pending_intent,
            &initiator_identity,
            &fixed_checkpoint(),
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        )
        .unwrap();

        let responder_session = responder.join().unwrap();
        (initiator_session, responder_session)
    }

    #[test]
    fn full_handshake_reaches_active_on_both_sides_with_matching_h_final() {
        let (initiator, responder) = full_handshake();
        assert_eq!(initiator.h_final(), responder.h_final());
        assert_eq!(initiator.peer_m_id(), "responder-1");
        assert_eq!(responder.peer_m_id(), "initiator-1");
        assert_eq!(initiator.ingress_evidence().observed_at, 2);
        assert_eq!(responder.ingress_evidence().observed_at, 1);
    }

    /// Like `full_handshake`, but lets the caller substitute the
    /// initiator's own checkpoint (used for the checkpoint-mutant REDs)
    /// and returns both sides' raw `Result` instead of unwrapping, so a
    /// test can assert on the responder's rejection.
    type SessionResult = Result<ActiveMeshSession<TcpStream, ()>, AuthFrameError>;

    fn full_handshake_with_initiator_checkpoint(
        initiator_checkpoint: LocalCheckpoint,
    ) -> (SessionResult, SessionResult) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let responder_key = SigningKey::random(&mut OsRng);
        let responder_verifying = VerifyingKey::from(&responder_key);
        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_verifying = VerifyingKey::from(&initiator_key);

        let responder_delegation = delegation_for_key(
            &responder_verifying,
            "hh-1",
            "responder-1",
            vec![0xCC; 32],
            0,
            u64::MAX / 2,
        );
        let responder_identity =
            identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence { observed_at: 1 },
                    far_future_budget(),
                );
                run_responder_handshake(
                    ingress,
                    &responder_identity,
                    &checkpoint,
                    ExpectedChannel::Dev,
                    &DelegationPolicy::test(u64::MAX / 2),
                    &AlwaysAcceptDelegation,
                    &k_mesh,
                    &InMemoryLedger::new(),
                    &AlwaysAdmitD1,
                    &FixedClock(0),
                    RekeyThreshold::new(3).unwrap(),
                )
            }
        });

        let initiator_delegation = delegation_for_key(
            &initiator_verifying,
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            0,
            u64::MAX / 2,
        );
        let initiator_identity =
            identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
        let sock = TcpStream::connect(addr).unwrap();
        let ingress = PrevalidatedIngress::admit_at_accept(
            sock,
            IngressEvidence { observed_at: 2 },
            far_future_budget(),
        );
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &initiator_identity,
            &initiator_checkpoint,
            "responder-1",
            vec![0xCC; 32],
            [0x98; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );
        let initiator_result = run_initiator_handshake(
            ingress,
            pending_intent,
            &initiator_identity,
            &initiator_checkpoint,
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        );

        let responder_result = responder.join().unwrap();
        (initiator_result, responder_result)
    }

    // These three mutate the INITIATOR's own local checkpoint away from
    // what the responder's real Proof-R carries. Since the initiator
    // checks received Proof-R against its own checkpoint *before* it ever
    // builds/sends Proof-I, this is caught on the initiator side — proving
    // check_checkpoint's full-4-scalar comparison on the Proof-R path.
    // (The responder never receives a Proof-I at all in this shape, so it
    // just observes the dropped connection, not CheckpointMismatch
    // itself — see red_proof_i_checkpoint_mutant_rejected_by_responder
    // below for the symmetric proof on the Proof-I/responder path.)
    #[test]
    fn red_checkpoint_sequence_mutant_rejected() {
        let mut bad = fixed_checkpoint();
        bad.sequence += 1; // hash still matches; sequence alone differs
        let (initiator_result, _responder_result) = full_handshake_with_initiator_checkpoint(bad);
        assert!(matches!(
            initiator_result,
            Err(AuthFrameError::CheckpointMismatch)
        ));
    }

    #[test]
    fn red_checkpoint_event_head_mutant_rejected() {
        let mut bad = fixed_checkpoint();
        bad.event_head = vec![0xFF; 32]; // hash still matches; event_head alone differs
        let (initiator_result, _responder_result) = full_handshake_with_initiator_checkpoint(bad);
        assert!(matches!(
            initiator_result,
            Err(AuthFrameError::CheckpointMismatch)
        ));
    }

    #[test]
    fn red_checkpoint_not_after_mutant_rejected() {
        let mut bad = fixed_checkpoint();
        bad.not_after += 1; // hash still matches; not_after alone differs
        let (initiator_result, _responder_result) = full_handshake_with_initiator_checkpoint(bad);
        assert!(matches!(
            initiator_result,
            Err(AuthFrameError::CheckpointMismatch)
        ));
    }

    #[test]
    fn red_proof_i_expected_peer_mismatch_rejected_before_final_confirm() {
        // Simulates a validly-signed Proof-I whose signed intent was to
        // reach a DIFFERENT responder (R2) arriving instead at this
        // responder (R1) — constructed directly (bypassing
        // run_initiator_handshake's own field population, which would
        // never build this) to prove R1's own check is real and not
        // merely redundant with the initiator's ExpectedResponder check.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder_key = SigningKey::random(&mut OsRng);
        let responder_verifying = VerifyingKey::from(&responder_key);
        let responder_delegation = delegation_for_key(
            &responder_verifying,
            "hh-1",
            "responder-1",
            vec![0xCC; 32],
            0,
            u64::MAX / 2,
        );
        let responder_identity =
            identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence { observed_at: 1 },
                    far_future_budget(),
                );
                run_responder_handshake(
                    ingress,
                    &responder_identity,
                    &checkpoint,
                    ExpectedChannel::Dev,
                    &DelegationPolicy::test(u64::MAX / 2),
                    &AlwaysAcceptDelegation,
                    &k_mesh,
                    &InMemoryLedger::new(),
                    &AlwaysAdmitD1,
                    &FixedClock(0),
                    RekeyThreshold::new(3).unwrap(),
                )
            }
        });

        // Attacker/misdirected initiator: real Noise handshake, real
        // Proof-R receipt, but a hand-built Proof-I whose
        // expected_peer_m_id/fingerprint name a DIFFERENT machine
        // ("responder-2") than the one it is actually talking to.
        let mut sock = TcpStream::connect(addr).unwrap();
        let handshake =
            noise::run_xx_handshake(&mut sock, Role::Initiator, &far_future_deadline()).unwrap();
        let mut transport = handshake.transport;
        let h_final = handshake.handshake_hash;
        match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
            AuthFrame::ProofR(_) => {}
            _ => panic!("expected ProofR"),
        }

        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_delegation = delegation_for_key(
            &VerifyingKey::from(&initiator_key),
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            0,
            u64::MAX / 2,
        );
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &identity(
                "hh-1",
                "initiator-1",
                vec![0xEE; 32],
                initiator_delegation.clone(),
            ),
            &checkpoint,
            "responder-1",
            vec![0xCC; 32],
            [0x97; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );
        send_intent_record(
            &mut sock,
            &mut transport,
            pending_intent.intent(),
            &far_future_deadline(),
        )
        .unwrap();
        let connection_intent_digest = ConnectionIntentDigest::from_bytes(
            crate::intent::intent_digest(pending_intent.intent()).unwrap(),
        );
        let proof_i = ProofI::new(
            h_final.clone(),
            "hh-1".to_string(),
            "initiator-1".to_string(),
            "responder-2".to_string(), // WRONG — real peer is responder-1
            vec![0xEE; 32],
            vec![0xDD; 32], // some other machine's fingerprint
            checkpoint.hash.clone(),
            checkpoint.sequence,
            checkpoint.event_head.clone(),
            checkpoint.not_after,
            initiator_delegation,
            connection_intent_digest,
            vec![0u8; 64],
        )
        .unwrap();
        let proof_i = auth_frames::sign_frame(proof_i, &k_mesh).unwrap();
        send_frame(
            &mut sock,
            &mut transport,
            &AuthFrame::ProofI(proof_i),
            &far_future_deadline(),
        )
        .unwrap();

        let responder_result = responder.join().unwrap();
        assert!(matches!(
            responder_result,
            Err(AuthFrameError::ExpectedPeerMismatch)
        ));
    }

    #[test]
    fn red_proof_i_checkpoint_mutant_rejected_by_responder() {
        // Symmetric to the expected-peer test above: a hand-built Proof-I,
        // correctly addressed this time, but with checkpoint_sequence
        // mutated away from the responder's real checkpoint — proves the
        // RESPONDER's own check_checkpoint call (on the Proof-I path)
        // independently catches all 4 scalars, not just hash, mirroring
        // the initiator-side proof above (which exercises the Proof-R
        // path instead).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder_key = SigningKey::random(&mut OsRng);
        let responder_verifying = VerifyingKey::from(&responder_key);
        let responder_delegation = delegation_for_key(
            &responder_verifying,
            "hh-1",
            "responder-1",
            vec![0xCC; 32],
            0,
            u64::MAX / 2,
        );
        let responder_identity =
            identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence { observed_at: 1 },
                    far_future_budget(),
                );
                run_responder_handshake(
                    ingress,
                    &responder_identity,
                    &checkpoint,
                    ExpectedChannel::Dev,
                    &DelegationPolicy::test(u64::MAX / 2),
                    &AlwaysAcceptDelegation,
                    &k_mesh,
                    &InMemoryLedger::new(),
                    &AlwaysAdmitD1,
                    &FixedClock(0),
                    RekeyThreshold::new(3).unwrap(),
                )
            }
        });

        let mut sock = TcpStream::connect(addr).unwrap();
        let handshake =
            noise::run_xx_handshake(&mut sock, Role::Initiator, &far_future_deadline()).unwrap();
        let mut transport = handshake.transport;
        let h_final = handshake.handshake_hash;
        match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
            AuthFrame::ProofR(_) => {}
            _ => panic!("expected ProofR"),
        }

        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_delegation = delegation_for_key(
            &VerifyingKey::from(&initiator_key),
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            0,
            u64::MAX / 2,
        );
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &identity(
                "hh-1",
                "initiator-1",
                vec![0xEE; 32],
                initiator_delegation.clone(),
            ),
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0x96; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );
        send_intent_record(
            &mut sock,
            &mut transport,
            pending_intent.intent(),
            &far_future_deadline(),
        )
        .unwrap();
        let connection_intent_digest = ConnectionIntentDigest::from_bytes(
            crate::intent::intent_digest(pending_intent.intent()).unwrap(),
        );
        let mut bad_checkpoint = fixed_checkpoint();
        bad_checkpoint.sequence += 1; // hash matches; sequence alone differs
        let proof_i = ProofI::new(
            h_final.clone(),
            "hh-1".to_string(),
            "initiator-1".to_string(),
            "responder-1".to_string(), // correctly addressed this time
            vec![0xEE; 32],
            vec![0xCC; 32], // matches the real responder's fingerprint
            bad_checkpoint.hash.clone(),
            bad_checkpoint.sequence,
            bad_checkpoint.event_head.clone(),
            bad_checkpoint.not_after,
            initiator_delegation,
            connection_intent_digest,
            vec![0u8; 64],
        )
        .unwrap();
        let proof_i = auth_frames::sign_frame(proof_i, &k_mesh).unwrap();
        send_frame(
            &mut sock,
            &mut transport,
            &AuthFrame::ProofI(proof_i),
            &far_future_deadline(),
        )
        .unwrap();

        let responder_result = responder.join().unwrap();
        assert!(matches!(
            responder_result,
            Err(AuthFrameError::CheckpointMismatch)
        ));
    }

    /// A stream double that panics the instant anything touches it — used
    /// to prove `check_signer_matches_delegation` rejects a mismatched
    /// signer key *before any write* (2026-08-04, @kiana, round 3: "REDs:
    /// ... signer public key != delegation rejeitado antes de qualquer
    /// write"). A plain `matches!` on the returned error would only prove
    /// the function eventually returns the right `Err` — it would not
    /// prove the stream (and therefore the Noise handshake, and every
    /// frame write) was never touched first. If the check ran even one
    /// statement too late, this panics instead of silently passing.
    struct PanicsOnIo;
    impl Read for PanicsOnIo {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            panic!("stream was read before check_signer_matches_delegation rejected");
        }
    }
    impl Write for PanicsOnIo {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            panic!("stream was written before check_signer_matches_delegation rejected");
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("stream was flushed before check_signer_matches_delegation rejected");
        }
    }
    impl wire::DeadlineBoundedIo for PanicsOnIo {
        fn arm_io_deadline(&mut self, _remaining: Duration) -> std::io::Result<()> {
            panic!("stream deadline was armed before check_signer_matches_delegation rejected");
        }
        fn clear_io_deadline(&mut self) -> std::io::Result<()> {
            panic!("stream deadline was cleared before check_signer_matches_delegation rejected");
        }
    }

    #[test]
    fn red_responder_signer_key_mismatched_delegation_rejected_before_any_write() {
        let delegation_key = SigningKey::random(&mut OsRng);
        let delegation = delegation_for_key(
            &VerifyingKey::from(&delegation_key),
            "hh-1",
            "responder-1",
            vec![0xCC; 32],
            0,
            u64::MAX / 2,
        );
        let local = identity("hh-1", "responder-1", vec![0xCC; 32], delegation);
        // Deliberately a DIFFERENT key than the one delegation.delegated_pub
        // encodes — the signer does not hold the delegated key.
        let mismatched_k_mesh = TestKMesh(SigningKey::random(&mut OsRng));

        let ingress = PrevalidatedIngress::admit_at_accept(
            PanicsOnIo,
            IngressEvidence { observed_at: 1 },
            far_future_budget(),
        );
        let result = run_responder_handshake(
            ingress,
            &local,
            &fixed_checkpoint(),
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &mismatched_k_mesh,
            &InMemoryLedger::new(),
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::SignerKeyMismatchDelegation)
        ));
    }

    #[test]
    fn red_initiator_signer_key_mismatched_delegation_rejected_before_any_write() {
        let delegation_key = SigningKey::random(&mut OsRng);
        let delegation = delegation_for_key(
            &VerifyingKey::from(&delegation_key),
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            0,
            u64::MAX / 2,
        );
        let local = identity("hh-1", "initiator-1", vec![0xEE; 32], delegation);
        let mismatched_k_mesh = TestKMesh(SigningKey::random(&mut OsRng));
        let pending_intent = pending_intent_for(
            &mismatched_k_mesh,
            &local,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0x95; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );

        let ingress = PrevalidatedIngress::admit_at_accept(
            PanicsOnIo,
            IngressEvidence { observed_at: 1 },
            far_future_budget(),
        );
        let result = run_initiator_handshake(
            ingress,
            pending_intent,
            &local,
            &fixed_checkpoint(),
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &mismatched_k_mesh,
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::SignerKeyMismatchDelegation)
        ));
    }

    /// Total-ceremony slow-loris RED (2026-08-04, @kiana, definitive):
    /// an admission whose `CeremonyDeadline` is already fully expired
    /// (`CeremonyDeadline::already_expired_for_test`, threaded in via
    /// `PrevalidatedIngress::new_for_test` — the only way to construct a
    /// pre-expired deadline outside production code) must be rejected
    /// before the FIRST Noise byte, on both sides — `PanicsOnIo` proves
    /// zero I/O of any kind (read, write, or even arming/clearing a
    /// deadline) is ever attempted.
    #[test]
    fn red_initiator_total_ceremony_deadline_already_expired_zero_io_attempted() {
        let key = SigningKey::random(&mut OsRng);
        let delegation = delegation_for_key(
            &VerifyingKey::from(&key),
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            0,
            u64::MAX / 2,
        );
        let local = identity("hh-1", "initiator-1", vec![0xEE; 32], delegation);
        let k_mesh = TestKMesh(key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &local,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0x89; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );

        let ingress = PrevalidatedIngress::new_for_test(
            PanicsOnIo,
            IngressEvidence { observed_at: 1 },
            CeremonyDeadline::already_expired_for_test(),
        );
        let result = run_initiator_handshake(
            ingress,
            pending_intent,
            &local,
            &fixed_checkpoint(),
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::Intent(
                crate::error::IntentError::DeadlineExceeded
            ))
        ));
    }

    #[test]
    fn red_responder_total_ceremony_deadline_already_expired_zero_io_attempted() {
        let key = SigningKey::random(&mut OsRng);
        let delegation = delegation_for_key(
            &VerifyingKey::from(&key),
            "hh-1",
            "responder-1",
            vec![0xCC; 32],
            0,
            u64::MAX / 2,
        );
        let local = identity("hh-1", "responder-1", vec![0xCC; 32], delegation);
        let k_mesh = TestKMesh(key);

        let ingress = PrevalidatedIngress::new_for_test(
            PanicsOnIo,
            IngressEvidence { observed_at: 1 },
            CeremonyDeadline::already_expired_for_test(),
        );
        let result = run_responder_handshake(
            ingress,
            &local,
            &fixed_checkpoint(),
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
            &InMemoryLedger::new(),
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::Intent(
                crate::error::IntentError::DeadlineExceeded
            ))
        ));
    }

    /// 2026-08-04, @kiana, round 4: `SessionRekeyState::new`'s RNG-backed
    /// mint used to run AFTER the responder durably wrote ActivateAck —
    /// a real (if rare) RNG failure there would have let the write reach
    /// the peer while this side returned `Err` and produced no
    /// `ActiveMeshSession`, breaking the erratum's atomic-linearization
    /// guarantee (peer could still reach Active alone). The mint now
    /// runs first, before any I/O. Uses the `test_failpoint` (real
    /// deterministic failure injection, not a hope that `OsRng` fails)
    /// plus `PanicsOnIo` to prove not just that the right `Err` comes
    /// back, but that the responder never touches the stream at all —
    /// so, a fortiori, ActivateAck (and every earlier frame) is never
    /// written.
    #[test]
    fn red_responder_rekey_mint_failure_writes_zero_bytes_before_returning() {
        let responder_key = SigningKey::random(&mut OsRng);
        let delegation = delegation_for_key(
            &VerifyingKey::from(&responder_key),
            "hh-1",
            "responder-1",
            vec![0xCC; 32],
            0,
            u64::MAX / 2,
        );
        let local = identity("hh-1", "responder-1", vec![0xCC; 32], delegation);
        let k_mesh = TestKMesh(responder_key);

        crate::rekey::test_failpoint::force_next_fresh_to_fail();
        let ingress = PrevalidatedIngress::admit_at_accept(
            PanicsOnIo,
            IngressEvidence { observed_at: 1 },
            far_future_budget(),
        );
        let result = run_responder_handshake(
            ingress,
            &local,
            &fixed_checkpoint(),
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
            &InMemoryLedger::new(),
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::Rekey(RekeyError::RngFailure))
        ));
    }

    /// Same finding, initiator side (2026-08-04, @kiana, round 4): the
    /// mint now runs before Proof-I, before Activate — before anything
    /// is ever sent. If it fails, this side sends literally nothing, so
    /// there is no way this attempt could cause a peer to reach Active.
    /// `PanicsOnIo` proves zero I/O, not just the right `Err`.
    #[test]
    fn red_initiator_rekey_mint_failure_writes_zero_bytes_before_returning() {
        let initiator_key = SigningKey::random(&mut OsRng);
        let delegation = delegation_for_key(
            &VerifyingKey::from(&initiator_key),
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            0,
            u64::MAX / 2,
        );
        let local = identity("hh-1", "initiator-1", vec![0xEE; 32], delegation);
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &local,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0x94; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );

        crate::rekey::test_failpoint::force_next_fresh_to_fail();
        let ingress = PrevalidatedIngress::admit_at_accept(
            PanicsOnIo,
            IngressEvidence { observed_at: 1 },
            far_future_budget(),
        );
        let result = run_initiator_handshake(
            ingress,
            pending_intent,
            &local,
            &fixed_checkpoint(),
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::Rekey(RekeyError::RngFailure))
        ));
    }

    // --- 2026-08-04, @kiana, round 5: pass_delegation_gate scope checks ---
    // A validly-signed, correctly-bound delegation used to authorize
    // frames regardless of what roles/transcript_kinds/channel it
    // actually declared. These call `pass_delegation_gate` directly —
    // it's a pure function of (delegation, policy, verifier, ctx,
    // expected_channel) — since the new checks run right after signature
    // verification and before check_partial_binding, `ctx` never needs
    // to actually match for these to reach the check under test.

    fn gate_ctx() -> PartialBindingInputs {
        PartialBindingInputs {
            proof_hh_id: "hh-1".to_string(),
            local_hh_id: "hh-1".to_string(),
            proof_self_m_id: "someone-1".to_string(),
            proof_self_cert_fingerprint: vec![0xCC; 32],
        }
    }

    #[test]
    fn red_delegation_gate_rejects_roles_missing_a_required_role() {
        let key = SigningKey::random(&mut OsRng);
        let delegation = delegation_wire_with(
            &VerifyingKey::from(&key),
            vec!["initiator".to_string()], // omits "responder"
            valid_transcript_kinds(),
            "dev",
        );
        let result = pass_delegation_gate(
            &delegation,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &gate_ctx(),
            ExpectedChannel::Dev,
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::DelegationRolesMismatch)
        ));
    }

    #[test]
    fn red_delegation_gate_rejects_roles_with_an_unexpected_extra_role() {
        let key = SigningKey::random(&mut OsRng);
        let delegation = delegation_wire_with(
            &VerifyingKey::from(&key),
            vec![
                "initiator".to_string(),
                "responder".to_string(),
                "observer".to_string(), // not in EXPECTED_DELEGATION_ROLES
            ],
            valid_transcript_kinds(),
            "dev",
        );
        let result = pass_delegation_gate(
            &delegation,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &gate_ctx(),
            ExpectedChannel::Dev,
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::DelegationRolesMismatch)
        ));
    }

    #[test]
    fn red_delegation_gate_rejects_roles_with_a_duplicate() {
        // Same length as EXPECTED_DELEGATION_ROLES (2), but a duplicate
        // "initiator" displaces "responder" entirely -- proves the check
        // is a real set comparison, not just a length check.
        let key = SigningKey::random(&mut OsRng);
        let delegation = delegation_wire_with(
            &VerifyingKey::from(&key),
            vec!["initiator".to_string(), "initiator".to_string()],
            valid_transcript_kinds(),
            "dev",
        );
        let result = pass_delegation_gate(
            &delegation,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &gate_ctx(),
            ExpectedChannel::Dev,
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::DelegationRolesMismatch)
        ));
    }

    #[test]
    fn red_delegation_gate_rejects_transcript_kinds_missing_a_required_kind() {
        let key = SigningKey::random(&mut OsRng);
        let delegation = delegation_wire_with(
            &VerifyingKey::from(&key),
            valid_roles(),
            vec!["final-confirm".to_string(), "activate".to_string()], // omits "activate-ack"
            "dev",
        );
        let result = pass_delegation_gate(
            &delegation,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &gate_ctx(),
            ExpectedChannel::Dev,
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::DelegationTranscriptKindsMismatch)
        ));
    }

    #[test]
    fn red_delegation_gate_rejects_transcript_kinds_with_an_unexpected_extra_kind() {
        let key = SigningKey::random(&mut OsRng);
        let delegation = delegation_wire_with(
            &VerifyingKey::from(&key),
            valid_roles(),
            vec![
                "final-confirm".to_string(),
                "activate".to_string(),
                "activate-ack".to_string(),
                "proof-r".to_string(), // not in EXPECTED_TRANSCRIPT_KINDS
            ],
            "dev",
        );
        let result = pass_delegation_gate(
            &delegation,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &gate_ctx(),
            ExpectedChannel::Dev,
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::DelegationTranscriptKindsMismatch)
        ));
    }

    #[test]
    fn red_delegation_gate_rejects_transcript_kinds_with_a_duplicate() {
        // Same length as EXPECTED_TRANSCRIPT_KINDS (3), but a duplicated
        // "final-confirm" displaces "activate-ack" entirely.
        let key = SigningKey::random(&mut OsRng);
        let delegation = delegation_wire_with(
            &VerifyingKey::from(&key),
            valid_roles(),
            vec![
                "final-confirm".to_string(),
                "final-confirm".to_string(),
                "activate".to_string(),
            ],
            "dev",
        );
        let result = pass_delegation_gate(
            &delegation,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &gate_ctx(),
            ExpectedChannel::Dev,
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::DelegationTranscriptKindsMismatch)
        ));
    }

    #[test]
    fn red_delegation_gate_rejects_channel_not_matching_expected() {
        let key = SigningKey::random(&mut OsRng);
        let delegation = delegation_wire_with(
            &VerifyingKey::from(&key),
            valid_roles(),
            valid_transcript_kinds(),
            "release",
        );
        let result = pass_delegation_gate(
            &delegation,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &gate_ctx(),
            ExpectedChannel::Dev, // caller expects dev; delegation says release
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::DelegationChannelMismatch)
        ));
    }

    /// Wiring confirmation, responder side: proves the roles/kinds/channel
    /// check is actually reached via `run_responder_handshake`'s own call
    /// to `pass_delegation_gate` on the RECEIVED (Proof-I) delegation, not
    /// just correct in isolation as the direct `pass_delegation_gate`
    /// tests above prove. Manual-attacker-harness pattern (real Noise
    /// handshake + hand-built, correctly-addressed, validly-signed but
    /// mis-scoped Proof-I).
    #[test]
    fn red_responder_rejects_received_delegation_with_missing_role() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder_key = SigningKey::random(&mut OsRng);
        let responder_delegation = delegation_for_key(
            &VerifyingKey::from(&responder_key),
            "hh-1",
            "responder-1",
            vec![0xCC; 32],
            0,
            u64::MAX / 2,
        );
        let responder_identity =
            identity("hh-1", "responder-1", vec![0xCC; 32], responder_delegation);

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence { observed_at: 1 },
                    far_future_budget(),
                );
                run_responder_handshake(
                    ingress,
                    &responder_identity,
                    &checkpoint,
                    ExpectedChannel::Dev,
                    &DelegationPolicy::test(u64::MAX / 2),
                    &AlwaysAcceptDelegation,
                    &k_mesh,
                    &InMemoryLedger::new(),
                    &AlwaysAdmitD1,
                    &FixedClock(0),
                    RekeyThreshold::new(3).unwrap(),
                )
            }
        });

        let mut sock = TcpStream::connect(addr).unwrap();
        let handshake =
            noise::run_xx_handshake(&mut sock, Role::Initiator, &far_future_deadline()).unwrap();
        let mut transport = handshake.transport;
        let h_final = handshake.handshake_hash;
        match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
            AuthFrame::ProofR(_) => {}
            _ => panic!("expected ProofR"),
        }

        let initiator_key = SigningKey::random(&mut OsRng);
        let bad_delegation = delegation_wire_with(
            &VerifyingKey::from(&initiator_key),
            vec!["initiator".to_string()], // omits "responder"
            valid_transcript_kinds(),
            "dev",
        );
        let checkpoint = fixed_checkpoint();
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &identity(
                "hh-1",
                "initiator-1",
                vec![0xEE; 32],
                bad_delegation.clone(),
            ),
            &checkpoint,
            "responder-1",
            vec![0xCC; 32],
            [0x93; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );
        send_intent_record(
            &mut sock,
            &mut transport,
            pending_intent.intent(),
            &far_future_deadline(),
        )
        .unwrap();
        let connection_intent_digest = ConnectionIntentDigest::from_bytes(
            crate::intent::intent_digest(pending_intent.intent()).unwrap(),
        );
        let proof_i = ProofI::new(
            h_final.clone(),
            "hh-1".to_string(),
            "initiator-1".to_string(),
            "responder-1".to_string(),
            vec![0xEE; 32],
            vec![0xCC; 32],
            checkpoint.hash.clone(),
            checkpoint.sequence,
            checkpoint.event_head.clone(),
            checkpoint.not_after,
            bad_delegation,
            connection_intent_digest,
            vec![0u8; 64],
        )
        .unwrap();
        let proof_i = auth_frames::sign_frame(proof_i, &k_mesh).unwrap();
        send_frame(
            &mut sock,
            &mut transport,
            &AuthFrame::ProofI(proof_i),
            &far_future_deadline(),
        )
        .unwrap();

        let responder_result = responder.join().unwrap();
        assert!(matches!(
            responder_result,
            Err(AuthFrameError::DelegationRolesMismatch)
        ));
    }

    /// Symmetric wiring confirmation, initiator side: a hand-built,
    /// correctly-addressed, validly-signed but mis-scoped Proof-R must be
    /// rejected via `run_initiator_handshake`'s own call to
    /// `pass_delegation_gate`.
    #[test]
    fn red_initiator_rejects_received_delegation_with_missing_role() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let attacker = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let handshake =
                noise::run_xx_handshake(&mut sock, Role::Responder, &far_future_deadline())
                    .unwrap();
            let mut transport = handshake.transport;
            let h_final = handshake.handshake_hash;

            let responder_key = SigningKey::random(&mut OsRng);
            let bad_delegation = delegation_wire_with(
                &VerifyingKey::from(&responder_key),
                vec!["initiator".to_string()], // omits "responder"
                valid_transcript_kinds(),
                "dev",
            );
            let checkpoint = fixed_checkpoint();
            let proof_r = ProofR::new(
                h_final.clone(),
                "hh-1".to_string(),
                "responder-1".to_string(),
                vec![0xCC; 32],
                checkpoint.hash.clone(),
                checkpoint.sequence,
                checkpoint.event_head.clone(),
                checkpoint.not_after,
                bad_delegation,
                vec![0u8; 64],
            )
            .unwrap();
            let k_mesh = TestKMesh(responder_key);
            let proof_r = auth_frames::sign_frame(proof_r, &k_mesh).unwrap();
            send_frame(
                &mut sock,
                &mut transport,
                &AuthFrame::ProofR(proof_r),
                &far_future_deadline(),
            )
            .unwrap();
        });

        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_delegation = delegation_for_key(
            &VerifyingKey::from(&initiator_key),
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            0,
            u64::MAX / 2,
        );
        let initiator_identity =
            identity("hh-1", "initiator-1", vec![0xEE; 32], initiator_delegation);
        let sock = TcpStream::connect(addr).unwrap();
        let ingress = PrevalidatedIngress::admit_at_accept(
            sock,
            IngressEvidence { observed_at: 2 },
            far_future_budget(),
        );
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &initiator_identity,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0x92; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );
        let result = run_initiator_handshake(
            ingress,
            pending_intent,
            &initiator_identity,
            &fixed_checkpoint(),
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        );
        attacker.join().unwrap();
        assert!(matches!(
            result,
            Err(AuthFrameError::DelegationRolesMismatch)
        ));
    }

    /// Local pre-I/O channel check, responder side (2026-08-04, @kiana,
    /// round 5): the LOCAL delegation's own channel must match what the
    /// caller says this ceremony expects, checked before any I/O.
    /// `PanicsOnIo` proves zero I/O, not just the right `Err`.
    #[test]
    fn red_responder_local_delegation_channel_mismatch_rejected_before_any_write() {
        let responder_key = SigningKey::random(&mut OsRng);
        let delegation = delegation_wire_with(
            &VerifyingKey::from(&responder_key),
            valid_roles(),
            valid_transcript_kinds(),
            "release", // local delegation says release
        );
        let local = identity("hh-1", "responder-1", vec![0xCC; 32], delegation);
        let k_mesh = TestKMesh(responder_key);

        let ingress = PrevalidatedIngress::admit_at_accept(
            PanicsOnIo,
            IngressEvidence { observed_at: 1 },
            far_future_budget(),
        );
        let result = run_responder_handshake(
            ingress,
            &local,
            &fixed_checkpoint(),
            ExpectedChannel::Dev, // caller expects dev
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
            &InMemoryLedger::new(),
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::DelegationChannelMismatch)
        ));
    }

    /// Symmetric to the above, initiator side.
    #[test]
    fn red_initiator_local_delegation_channel_mismatch_rejected_before_any_write() {
        let initiator_key = SigningKey::random(&mut OsRng);
        let delegation = delegation_wire_with(
            &VerifyingKey::from(&initiator_key),
            valid_roles(),
            valid_transcript_kinds(),
            "release",
        );
        let local = identity("hh-1", "initiator-1", vec![0xEE; 32], delegation);
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &local,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0x91; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );

        let ingress = PrevalidatedIngress::admit_at_accept(
            PanicsOnIo,
            IngressEvidence { observed_at: 1 },
            far_future_budget(),
        );
        let result = run_initiator_handshake(
            ingress,
            pending_intent,
            &local,
            &fixed_checkpoint(),
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        );
        assert!(matches!(
            result,
            Err(AuthFrameError::DelegationChannelMismatch)
        ));
    }

    #[test]
    fn red_commit_outgoing_rekey_with_foreign_permit_does_not_touch_transport() {
        let (mut initiator, _responder) = full_handshake();
        let other_threshold = RekeyThreshold::new(1).unwrap();
        let donor = rekey::DirectionalRekeyState::new(other_threshold).unwrap();
        let foreign_permit = donor.before_send_marker().unwrap();

        let err = initiator.commit_outgoing_rekey(foreign_permit).unwrap_err();
        assert!(matches!(err, crate::error::RekeyError::StalePermit));
        // The tx counter must be completely unaffected — validate_marker_permit
        // rejected before transport.rekey_outgoing() or after_send_marker
        // ever ran.
        assert_eq!(initiator.rekey.tx().generation(), 0);
        assert_eq!(initiator.rekey.tx().policy_count(), 0);
    }

    #[test]
    fn delegation_gate_blocks_with_no_verifier_configured() {
        // The initiator side uses AlwaysAcceptDelegation (so it gets far
        // enough to actually send Proof-I) and a delegation whose
        // delegated_pub genuinely matches its K_mesh key (so its own
        // outer-frame signature checks pass); the RESPONDER uses the
        // crate's REAL shipped verifier, NoVerifierConfigured — proving
        // the gate is genuinely closed by default, on the side under test,
        // not just in prose.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder_key = SigningKey::random(&mut OsRng);
        let responder_verifying = VerifyingKey::from(&responder_key);
        let responder_identity = identity(
            "hh-1",
            "responder-1",
            vec![0xCC; 32],
            delegation_for_key(
                &responder_verifying,
                "hh-1",
                "responder-1",
                vec![0xCC; 32],
                0,
                u64::MAX / 2,
            ),
        );
        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence { observed_at: 1 },
                    far_future_budget(),
                );
                run_responder_handshake(
                    ingress,
                    &responder_identity,
                    &checkpoint,
                    ExpectedChannel::Dev,
                    &DelegationPolicy::test(u64::MAX / 2),
                    &crate::delegation::NoVerifierConfigured,
                    &k_mesh,
                    &InMemoryLedger::new(),
                    &AlwaysAdmitD1,
                    &FixedClock(0),
                    RekeyThreshold::new(3).unwrap(),
                )
            }
        });

        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_identity = identity(
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            delegation_for_key(
                &VerifyingKey::from(&initiator_key),
                "hh-1",
                "initiator-1",
                vec![0xEE; 32],
                0,
                u64::MAX / 2,
            ),
        );
        let sock = TcpStream::connect(addr).unwrap();
        let ingress = PrevalidatedIngress::admit_at_accept(
            sock,
            IngressEvidence { observed_at: 2 },
            far_future_budget(),
        );
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &initiator_identity,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0x90; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );
        let initiator_result = run_initiator_handshake(
            ingress,
            pending_intent,
            &initiator_identity,
            &fixed_checkpoint(),
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
            &AlwaysAdmitD1,
            &FixedClock(0),
            RekeyThreshold::new(3).unwrap(),
        );

        // The responder gates on Proof-I's delegation and rejects with
        // DelegationGate specifically; the initiator, having already sent
        // Proof-I, is left blocked waiting for FinalConfirm that never
        // comes (the responder errors out and drops the socket) — it
        // fails too, but with a connection error, not DelegationGate.
        let responder_result = responder.join().unwrap();
        assert!(matches!(
            responder_result,
            Err(AuthFrameError::DelegationGate)
        ));
        assert!(initiator_result.is_err());
        assert!(!matches!(
            initiator_result,
            Err(AuthFrameError::DelegationGate)
        ));
    }

    #[test]
    fn pos4_rekey_with_a_real_snow_pair_both_directions() {
        let (mut initiator, mut responder) = full_handshake();

        // Drive initiator's TX through exactly one rekey (N=3: 2 non-marker
        // + marker), coupled to a REAL TransportState::rekey_outgoing().
        let p1 = initiator.before_send_non_marker().unwrap();
        initiator.after_send_non_marker(p1).unwrap();
        let p2 = initiator.before_send_non_marker().unwrap();
        initiator.after_send_non_marker(p2).unwrap();
        let marker_permit = initiator.before_outgoing_rekey().unwrap();
        let next_generation = marker_permit.next_generation();
        initiator.commit_outgoing_rekey(marker_permit).unwrap();

        // Responder's RX mirrors it, coupled to a REAL
        // TransportState::rekey_incoming().
        responder.observe_incoming_non_marker().unwrap();
        responder.observe_incoming_non_marker().unwrap();
        responder.commit_incoming_rekey(next_generation).unwrap();

        // Prove the REAL Noise keys actually rotated together: encrypt on
        // the new initiator generation, decrypt on the new responder
        // generation.
        let plaintext = b"post-rekey application data";
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let ct_len = initiator
            .transport
            .write_message(plaintext, &mut ciphertext)
            .unwrap();
        let mut recovered = vec![0u8; plaintext.len()];
        let pt_len = responder
            .transport
            .read_message(&ciphertext[..ct_len], &mut recovered)
            .unwrap();
        assert_eq!(&recovered[..pt_len], plaintext);
    }

    #[test]
    fn red_simultaneous_independent_rekey_real_rx_and_tx_do_not_interfere() {
        let (mut initiator, mut responder) = full_handshake();

        // Drive initiator TX to a rekey...
        let p1 = initiator.before_send_non_marker().unwrap();
        initiator.after_send_non_marker(p1).unwrap();
        let p2 = initiator.before_send_non_marker().unwrap();
        initiator.after_send_non_marker(p2).unwrap();
        let marker_permit = initiator.before_outgoing_rekey().unwrap();
        let tx_next_generation = marker_permit.next_generation();
        initiator.commit_outgoing_rekey(marker_permit).unwrap();

        // ...simultaneously with responder driving ITS OWN tx (opposite
        // direction) to a rekey, real coupling on both.
        let p1 = responder.before_send_non_marker().unwrap();
        responder.after_send_non_marker(p1).unwrap();
        let p2 = responder.before_send_non_marker().unwrap();
        responder.after_send_non_marker(p2).unwrap();
        let responder_marker_permit = responder.before_outgoing_rekey().unwrap();
        let rx_next_generation = responder_marker_permit.next_generation();
        responder
            .commit_outgoing_rekey(responder_marker_permit)
            .unwrap();

        // Now settle both receive sides for the marks each peer sent.
        responder.observe_incoming_non_marker().unwrap();
        responder.observe_incoming_non_marker().unwrap();
        responder.commit_incoming_rekey(tx_next_generation).unwrap();

        initiator.observe_incoming_non_marker().unwrap();
        initiator.observe_incoming_non_marker().unwrap();
        initiator.commit_incoming_rekey(rx_next_generation).unwrap();

        // Real bidirectional traffic on the new generations, both ways.
        let mut ct = vec![0u8; 64];
        let n = initiator.transport.write_message(b"i->r", &mut ct).unwrap();
        let mut pt = vec![0u8; 64];
        let m = responder.transport.read_message(&ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], b"i->r");

        let n = responder.transport.write_message(b"r->i", &mut ct).unwrap();
        let m = initiator.transport.read_message(&ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], b"r->i");
    }

    #[test]
    fn red_wrong_generation_marker_rejected_and_does_not_touch_real_transport() {
        let (mut initiator, _responder) = full_handshake();
        let before = initiator.rekey.rx().generation();
        let err = initiator.commit_incoming_rekey(999).unwrap_err();
        assert!(matches!(err, RekeyError::WrongGeneration { .. }));
        assert_eq!(initiator.rekey.rx().generation(), before);
    }
}
