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
    self, Activate, ActivateAck, AuthFrame, ConnectionIntentDigest, ExpectedResponder,
    FinalConfirm, MeshSessionFrameSigner, ProofI, ProofR,
};
use crate::delegation::{
    DelegationPolicy, DelegationSignatureVerifier, MeshSessionDelegation, PartialBindingInputs,
};
use crate::error::{AuthFrameError, NoiseSetupError};
use crate::ingress::{IngressEvidence, PrevalidatedIngress};
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

fn send_frame<S: Write>(
    stream: &mut S,
    transport: &mut TransportState,
    frame: &AuthFrame,
) -> Result<(), AuthFrameError> {
    let plaintext = auth_frames::encode_auth_frame(frame)?;
    let mut ciphertext = vec![0u8; plaintext.len() + 16];
    let ct_len = transport
        .write_message(&plaintext, &mut ciphertext)
        .map_err(NoiseSetupError::from)?;
    wire::write_transport_record(stream, &ciphertext[..ct_len])?;
    Ok(())
}

fn recv_frame<S: Read>(
    stream: &mut S,
    transport: &mut TransportState,
) -> Result<AuthFrame, AuthFrameError> {
    let ciphertext = wire::read_transport_record(stream)?;
    let mut plaintext = vec![0u8; ciphertext.len()];
    let pt_len = transport
        .read_message(&ciphertext, &mut plaintext)
        .map_err(NoiseSetupError::from)?;
    auth_frames::decode_auth_frame(&plaintext[..pt_len])
}

/// The delegation gate, strictly ordered: policy TTL, then injected
/// signature verification, then partial binding. `NoVerifierConfigured`
/// (this crate's only shipped `DelegationSignatureVerifier`) always fails
/// the middle step, so this gate never opens on an unmodified build — see
/// the module doc.
fn pass_delegation_gate<Ver: DelegationSignatureVerifier>(
    delegation: &MeshSessionDelegation,
    policy: &DelegationPolicy,
    verifier: &Ver,
    ctx: &PartialBindingInputs,
) -> Result<(), AuthFrameError> {
    policy.validate(delegation)?;
    delegation
        .verify_signature(verifier)
        .map_err(|_| AuthFrameError::DelegationGate)?;
    delegation.check_partial_binding(ctx)?;
    Ok(())
}

fn check_h_final(frame_h_final: &[u8], expected: &[u8]) -> Result<(), AuthFrameError> {
    if frame_h_final != expected {
        return Err(AuthFrameError::HFinalMismatch);
    }
    Ok(())
}

fn check_checkpoint(frame_hash: &[u8], local: &LocalCheckpoint) -> Result<(), AuthFrameError> {
    if frame_hash != local.hash.as_slice() {
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
pub struct ActiveMeshSession<T> {
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
}

impl<T> ActiveMeshSession<T> {
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
    /// without the other.
    pub fn commit_outgoing_rekey(&mut self, permit: rekey::SendMarkerPermit) {
        self.transport.rekey_outgoing();
        self.rekey.tx().after_send_marker(permit);
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

/// Drive the responder side: Idle → Handshaking → SendingProofR →
/// AwaitingProofI → SendingFinalConfirm → AwaitingActivate → Active.
/// `ingress` is consumed internally — its stream and evidence are never
/// handed back to the caller separately (hardened 2026-08-04). See the
/// module doc for why this is `pub(crate)`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_responder_handshake<S, Sig, Ver>(
    ingress: PrevalidatedIngress<S>,
    local: &LocalIdentity,
    checkpoint: &LocalCheckpoint,
    policy: &DelegationPolicy,
    delegation_verifier: &Ver,
    k_mesh: &Sig,
    rekey_threshold: RekeyThreshold,
) -> Result<ActiveMeshSession<S>, AuthFrameError>
where
    S: Read + Write,
    Sig: MeshSessionFrameSigner,
    Ver: DelegationSignatureVerifier,
{
    let (mut stream, ingress_evidence) = ingress.consume();

    let handshake = noise::run_xx_handshake(&mut stream, Role::Responder)?;
    let mut transport = handshake.transport;
    let h_final = handshake.handshake_hash;

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
    send_frame(&mut stream, &mut transport, &AuthFrame::ProofR(proof_r))?;

    // --- Frame 2: Proof-I, I -> R ---
    let proof_i = match recv_frame(&mut stream, &mut transport)? {
        AuthFrame::ProofI(f) => f,
        _ => return Err(AuthFrameError::RoleOrKindMismatch),
    };
    check_h_final(proof_i.h_final(), &h_final)?;
    check_checkpoint(proof_i.checkpoint_hash(), checkpoint)?;
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
    )?;
    let initiator_verifier =
        auth_frames::verifier_from_delegated_pub(proof_i.delegation().delegated_pub())?;
    auth_frames::verify_frame(&proof_i, &sig_array(proof_i.sig())?, &initiator_verifier)?;

    let initiator_m_id = proof_i.self_m_id().to_string();
    let initiator_cert_fingerprint = proof_i.self_cert_fingerprint().to_vec();
    let initiator_hh_id = proof_i.hh_id().to_string();

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
    )?;

    // --- Frame 4: Activate, I -> R ---
    let activate = match recv_frame(&mut stream, &mut transport)? {
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

    // --- Erratum: atomic ActivateAck linearization ---
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
    // 3. write_all (write_transport_record uses write_all internally) —
    // 4. only on success does an ActiveMeshSession get constructed below;
    // 5. on failure this returns Err and NO ActiveMeshSession, EVER,
    //    exists for this attempt — zero effect, matching the erratum.
    send_frame(
        &mut stream,
        &mut transport,
        &AuthFrame::ActivateAck(activate_ack),
    )?;

    Ok(ActiveMeshSession {
        stream,
        transport,
        rekey: SessionRekeyState::new(rekey_threshold),
        peer_hh_id: initiator_hh_id,
        peer_m_id: initiator_m_id,
        peer_cert_fingerprint: initiator_cert_fingerprint,
        ingress_evidence,
        h_final,
    })
}

/// Drive the initiator side: Idle → Handshaking → AwaitingProofR →
/// SendingProofI → AwaitingFinalConfirm → SendingActivate →
/// AwaitingActivateAck → Active. See the module doc for why this is
/// `pub(crate)`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_initiator_handshake<S, Sig, Ver>(
    ingress: PrevalidatedIngress<S>,
    expected: &ExpectedResponder,
    local: &LocalIdentity,
    checkpoint: &LocalCheckpoint,
    connection_intent_digest: ConnectionIntentDigest,
    policy: &DelegationPolicy,
    delegation_verifier: &Ver,
    k_mesh: &Sig,
    rekey_threshold: RekeyThreshold,
) -> Result<ActiveMeshSession<S>, AuthFrameError>
where
    S: Read + Write,
    Sig: MeshSessionFrameSigner,
    Ver: DelegationSignatureVerifier,
{
    let (mut stream, ingress_evidence) = ingress.consume();

    let handshake = noise::run_xx_handshake(&mut stream, Role::Initiator)?;
    let mut transport = handshake.transport;
    let h_final = handshake.handshake_hash;

    // --- Frame 1: Proof-R, R -> I ---
    let proof_r = match recv_frame(&mut stream, &mut transport)? {
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
    check_checkpoint(proof_r.checkpoint_hash(), checkpoint)?;
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
    )?;
    let responder_verifier =
        auth_frames::verifier_from_delegated_pub(proof_r.delegation().delegated_pub())?;
    auth_frames::verify_frame(&proof_r, &sig_array(proof_r.sig())?, &responder_verifier)?;

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
    send_frame(&mut stream, &mut transport, &AuthFrame::ProofI(proof_i))?;

    // --- Frame 3: FinalConfirm, R -> I ---
    let final_confirm = match recv_frame(&mut stream, &mut transport)? {
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

    // --- Frame 4: Activate, I -> R ---
    let final_confirm_digest = auth_frames::frame_digest(&final_confirm)?;
    let activate = Activate::new(
        h_final.clone(),
        expected.m_id.clone(),
        final_confirm_digest.to_vec(),
        vec![0u8; 64],
    )?;
    let activate = auth_frames::sign_frame(activate, k_mesh)?;
    send_frame(
        &mut stream,
        &mut transport,
        &AuthFrame::Activate(activate.clone()),
    )?;

    // --- Frame 5: ActivateAck, R -> I ---
    // "I só transita Active após decrypt + verify ActivateAck" (v6 §13).
    let activate_ack = match recv_frame(&mut stream, &mut transport)? {
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

    Ok(ActiveMeshSession {
        stream,
        transport,
        rekey: SessionRekeyState::new(rekey_threshold),
        peer_hh_id: expected.hh_id.clone(),
        peer_m_id: expected.m_id.clone(),
        peer_cert_fingerprint: expected.cert_fingerprint.to_vec(),
        ingress_evidence,
        h_final,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::test_support::sample_delegation;
    use crate::error::RekeyError;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use rand_core::OsRng;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    struct TestKMesh(SigningKey);
    impl MeshSessionFrameSigner for TestKMesh {
        fn sign_mesh_session_frame(
            &self,
            preimage: &crate::auth_frames::MeshSessionFramePreimage,
        ) -> [u8; 64] {
            let sig: Signature = self.0.sign(preimage.as_bytes());
            let sig = sig.normalize_s().unwrap_or(sig);
            sig.to_bytes().into()
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
    /// verifier that actually matches the key `k_mesh` signs with) and
    /// whose `hh_id`/`delegator_m_id`/`delegator_cert_fingerprint` match
    /// the identity presenting it (so `check_partial_binding`'s
    /// non-roster triple-equality checks — which compare the frame's own
    /// `hh_id`/`self_m_id`/`self_cert_fingerprint` against these exact
    /// fields — actually pass).
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
            transcript_kinds: vec!["identity-proof".to_string()],
            roles: vec!["initiator".to_string(), "responder".to_string()],
            channel: "dev".to_string(),
            serial: 1,
            not_before,
            not_after,
            sig: vec![0u8; 64],
        }
        .try_into()
        .unwrap()
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
    fn full_handshake() -> (ActiveMeshSession<TcpStream>, ActiveMeshSession<TcpStream>) {
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
                let ingress = PrevalidatedIngress::new(sock, IngressEvidence { observed_at: 1 });
                run_responder_handshake(
                    ingress,
                    &responder_identity,
                    &checkpoint,
                    &DelegationPolicy::test(u64::MAX / 2),
                    &AlwaysAcceptDelegation,
                    &k_mesh,
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
        let expected = ExpectedResponder {
            hh_id: "hh-1".to_string(),
            m_id: "responder-1".to_string(),
            cert_fingerprint: [0xCC; 32],
        };
        let sock = TcpStream::connect(addr).unwrap();
        let ingress = PrevalidatedIngress::new(sock, IngressEvidence { observed_at: 2 });
        let k_mesh = TestKMesh(initiator_key);
        let initiator_session = run_initiator_handshake(
            ingress,
            &expected,
            &initiator_identity,
            &fixed_checkpoint(),
            ConnectionIntentDigest::from_bytes([0x11; 32]),
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
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
                let ingress = PrevalidatedIngress::new(sock, IngressEvidence { observed_at: 1 });
                run_responder_handshake(
                    ingress,
                    &responder_identity,
                    &checkpoint,
                    &DelegationPolicy::test(u64::MAX / 2),
                    &crate::delegation::NoVerifierConfigured,
                    &k_mesh,
                    RekeyThreshold::new(3).unwrap(),
                )
            }
        });

        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_identity = identity(
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            sample_delegation(0, u64::MAX / 2),
        );
        let expected = ExpectedResponder {
            hh_id: "hh-1".to_string(),
            m_id: "responder-1".to_string(),
            cert_fingerprint: [0xCC; 32],
        };
        let sock = TcpStream::connect(addr).unwrap();
        let ingress = PrevalidatedIngress::new(sock, IngressEvidence { observed_at: 2 });
        let k_mesh = TestKMesh(initiator_key);
        let initiator_result = run_initiator_handshake(
            ingress,
            &expected,
            &initiator_identity,
            &fixed_checkpoint(),
            ConnectionIntentDigest::from_bytes([0x11; 32]),
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
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
        initiator.commit_outgoing_rekey(marker_permit);

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
        initiator.commit_outgoing_rekey(marker_permit);

        // ...simultaneously with responder driving ITS OWN tx (opposite
        // direction) to a rekey, real coupling on both.
        let p1 = responder.before_send_non_marker().unwrap();
        responder.after_send_non_marker(p1).unwrap();
        let p2 = responder.before_send_non_marker().unwrap();
        responder.after_send_non_marker(p2).unwrap();
        let responder_marker_permit = responder.before_outgoing_rekey().unwrap();
        let rx_next_generation = responder_marker_permit.next_generation();
        responder.commit_outgoing_rekey(responder_marker_permit);

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
