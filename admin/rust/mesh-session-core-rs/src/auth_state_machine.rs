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
use std::time::{Duration, Instant};

use snow::TransportState;
use zeroize::Zeroizing;

use crate::auth_frames::{
    self, Activate, ActivateAck, AuthFrame, ConnectionIntentDigest, FinalConfirm,
    MeshSessionFrameSigner, ProofI, ProofR,
};
use crate::delegation::{
    DelegationPolicy, DelegationSignatureVerifier, MeshSessionDelegation, PartialBindingInputs,
};
use crate::error::{AuthFrameError, NoiseSetupError, PostActiveError};
use crate::ingress::{CeremonyDeadline, IngressEvidence, PrevalidatedIngress};
use crate::intent::D1Pending;
use crate::noise::{self, Role};
use crate::post_active::{self, PostActiveRecord};
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
///
/// `pub` (2026-08-04, @kiana, WIP audit, seam-visibility correction):
/// appears in [`crate::intent::D1AdmissionKey::channel`]'s return type, a
/// `pub` accessor a real, different-crate `D1Admission` adapter must be
/// able to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpectedChannel {
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
#[allow(clippy::too_many_arguments)]
fn pass_delegation_gate<Ver: DelegationSignatureVerifier>(
    delegation: &MeshSessionDelegation,
    policy: &DelegationPolicy,
    verifier: &Ver,
    ctx: &PartialBindingInputs,
    expected_channel: ExpectedChannel,
    deadline: &CeremonyDeadline,
) -> Result<(), AuthFrameError> {
    policy.validate(delegation)?;
    delegation
        .verify_signature(verifier, deadline)
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

/// `effective_expires_at = min(checkpoint.not_after, local_delegation.not_after,
/// peer_delegation.not_after, lease_expires_at, ingress_expiry)` — B-SESSAO
/// v6 §7 (2026-08-04, @kiana, WIP audit point A; self-hash verified
/// against `daisy-bsessao-v6.7343d0752d21b1487e387e74fcd4aa4d28d44bea6b7d3264f7d8a08e0619ac67.md`,
/// §7). D9 carrier-B adds `intent.not_after` as an additional cap on top
/// of the v6 §5 components. Distinct from [`check_ceremony_deadline`]'s
/// monotonic anti-slow-loris `CeremonyDeadline` — this uses the SAME
/// wall-clock `u64` domain as every other TTL/`not_after` check in this
/// crate (a `Clock` reading, never `Instant`), consistent with "wall
/// clock/now u64 continua SEPARADO... nunca para anti-slow-loris."
///
/// **Split into compute + check (2026-08-04, @kiana, WIP audit, v6 §10):**
/// v6 §10 requires `expires_at` stored on the Active wrapper itself —
/// expiration is auth-off before EVERY DATA operation, not just a
/// point-in-time check during the handshake. The computed value is
/// returned so the caller can carry it into `ActiveMeshSession`, not just
/// discarded once this one check passes.
#[allow(clippy::too_many_arguments)]
fn effective_expires_at(
    checkpoint_not_after: u64,
    local_delegation_not_after: u64,
    peer_delegation_not_after: u64,
    lease_expires_at: u64,
    ingress_expiry: u64,
    intent_not_after: u64,
) -> u64 {
    [
        checkpoint_not_after,
        local_delegation_not_after,
        peer_delegation_not_after,
        lease_expires_at,
        ingress_expiry,
        intent_not_after,
    ]
    .into_iter()
    .min()
    .expect("literal array is non-empty")
}

/// Half-open: `now < expires_at`; equality means already expired (v6 §7:
/// "Em equality: auth-off antes de DATA").
fn check_effective_expiry(now: u64, expires_at: u64) -> Result<(), AuthFrameError> {
    if now < expires_at {
        Ok(())
    } else {
        Err(crate::error::IntentError::TtlInvalid.into())
    }
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
/// tuple-return formulation:** [`D1Pending::commit_after_ack`](crate::intent::D1Pending::commit_after_ack)
/// (name current as of the runtime-facade audit `3cbbfb37…` GAT
/// redesign — this note previously named the superseded
/// `D1Admission::activate_if_authorized`) still returns the opaque gate,
/// but the handshake function that constructs a session moves it
/// directly into this private field in the same expression — the gate is
/// never a separate value a caller could receive and then drop, hold, or
/// move independently of the session that depends on it. There is no
/// accessor: nothing in this crate, and nothing an external caller could
/// write, can extract `gate` while retaining a usable `ActiveMeshSession`.
///
/// **This crate makes NO claim about what happens to `G` on drop
/// (2026-08-04, @kiana, WIP audit, correction of an earlier, wrong claim
/// here):** an earlier version of this note asserted that dropping the
/// session "runs whatever unregister/revoke semantics `G`'s own `Drop`
/// impl gives it" — verified against the real household-rs
/// `SessionGate` type and found false: `SessionGate` is `#[derive(Clone)]`
/// with no `Drop` impl at all; its actual revocation model is a shared
/// `Arc`-backed atomic/sync state that every clone reads fresh on each
/// `try_authorize_forwarding()` call, not a drop-triggered side effect.
/// This crate embeds `G` honestly as an opaque, generic value — it is
/// carried for exactly as long as the session lives and never
/// independently extractable, but this crate neither knows nor asserts
/// *what* embedding/dropping it does; that is entirely the real
/// `D1::ActiveGate` implementation's own contract, undocumented here.
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
///
/// **2026-08-04, @kiana, WIP audit point E:** the rekey-advancing methods
/// (`before_send_non_marker`, `after_send_non_marker`,
/// `before_outgoing_rekey`, `commit_outgoing_rekey`,
/// `observe_incoming_non_marker`, `commit_incoming_rekey`) are
/// `pub(crate)`, not `pub` — no external crate can reach any of them, even
/// though the type itself is nameable:
///
/// ```compile_fail
/// use mesh_session_core_rs::auth_state_machine::ActiveMeshSession;
/// fn advance_rekey<T, G>(mut session: ActiveMeshSession<T, G>) {
///     let _ = session.observe_incoming_non_marker(); // pub(crate) — does not compile
/// }
/// ```
///
/// **2026-08-04, @kiana, WIP audit point A:** `expires_at` is likewise
/// `pub(crate)`-accessor-only and field-private — no external crate can
/// read or extract it, even via destructuring:
///
/// ```compile_fail
/// use mesh_session_core_rs::auth_state_machine::ActiveMeshSession;
/// fn read_expiry<T, G>(session: &ActiveMeshSession<T, G>) -> u64 {
///     session.expires_at // field is private — does not compile
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
    // never read by this crate — carried for exactly as long as the
    // session lives, never independently extractable; see the struct doc
    // for why this crate makes no claim about what embedding/dropping it
    // does (that is the real D1::ActiveGate implementation's own
    // contract).
    gate: G,
    /// `effective_expires_at` (2026-08-04, @kiana, WIP audit point A, v6
    /// §10) — computed once during the ceremony (see
    /// [`effective_expires_at`]) and carried here because v6 §10 requires
    /// expiry to be auth-off before EVERY DATA operation, not just a
    /// point-in-time check during the handshake. `pub(crate)` accessor
    /// only: DATA itself is still out of this module's scope (see the
    /// module doc), so nothing here enforces `now < expires_at` on any
    /// operation yet — a future guarded DATA path is structurally
    /// obligated to check this alongside its gate before any syscall, but
    /// that check does not exist in this crate today. May already be in
    /// the past by the time this field is read — see `run_responder_handshake`'s/
    /// `run_initiator_handshake`'s own doc on why the ceremony deliberately
    /// does not re-fail if the terminal Ack write races past it.
    expires_at: u64,
    /// Local terminal flag (2026-08-04, @kiana, post-Active wire addendum
    /// `b14fcf95…` + erratum1 `4be4cd3d…`, §7). Set the instant local
    /// authority is withdrawn — before any CLOSE/REVOKE_NOTICE write is
    /// even attempted, and before any received CLOSE/REVOKE_NOTICE or
    /// post-Active error is exposed to the caller — never after. Once
    /// `true`, every guarded post-Active operation below fails closed
    /// immediately with [`PostActiveError::Closed`] without touching the
    /// stream again; repetition/EOF cannot resurrect state (addendum §7).
    closed: bool,
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
    /// `pub(crate)` (2026-08-04, @kiana, WIP audit point A, v6 §10) —
    /// see the field's own doc. Not `pub`: no external, DATA-capable
    /// caller exists yet to consult this against a trusted clock.
    pub(crate) fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// **`pub(crate)` (2026-08-04, @kiana, WIP audit point E, minimal fix):**
    /// these 6 methods advance real protocol state (the rekey
    /// counter/generation *and* the coupled `snow::TransportState`
    /// rekey), with no gate consulted before doing so — `ActiveGate`
    /// being embedded and un-droppable-separately (definitive A) stops a
    /// caller from *extracting* the gate, but nothing here stops a caller
    /// who already holds an `&mut ActiveMeshSession` from calling these
    /// directly regardless of whatever forwarding authorization state a
    /// real D1 registry might have moved to (e.g. a concurrent revoke).
    /// DATA/CLOSE/REKEY wire is out of this module's stated scope (see
    /// the module doc) — inventing a per-operation `ActiveAuthorization`
    /// guard now would mean designing that surface without a frozen wire
    /// format to design it against. The minimal, honest fix available
    /// today is downgrading these to `pub(crate)`: nothing outside this
    /// crate can reach them at all (verified below), so there is no
    /// external bypass surface until a real guarded DATA path exists to
    /// replace this with atomic guard-acquiring operations.
    pub(crate) fn before_send_non_marker(
        &mut self,
    ) -> Result<rekey::SendNonMarkerPermit, crate::error::RekeyError> {
        self.rekey.tx().before_send_non_marker()
    }
    pub(crate) fn after_send_non_marker(
        &mut self,
        permit: rekey::SendNonMarkerPermit,
    ) -> Result<(), crate::error::RekeyError> {
        self.rekey.tx().after_send_non_marker(permit)
    }
    pub(crate) fn before_outgoing_rekey(
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
    pub(crate) fn commit_outgoing_rekey(
        &mut self,
        permit: rekey::SendMarkerPermit,
    ) -> Result<(), crate::error::RekeyError> {
        self.rekey.tx().validate_marker_permit(&permit)?;
        self.transport.rekey_outgoing();
        self.rekey.tx().after_send_marker(permit)
    }
    pub(crate) fn observe_incoming_non_marker(&mut self) -> Result<(), crate::error::RekeyError> {
        self.rekey.rx().on_receive(rekey::IncomingRecord::NonMarker)
    }
    /// Couples the rx counter transition to the real
    /// `TransportState::rekey_incoming()` — validated first, and the real
    /// rekey only happens if validation succeeds.
    pub(crate) fn commit_incoming_rekey(
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

/// A single post-Active operation's own bounded budget (2026-08-04,
/// @kiana, post-Active wire addendum `b14fcf95…` §5: "cada operação de
/// I/O recebe deadline monotônico bounded"). Deliberately NOT
/// [`CeremonyDeadline`]: that type's only constructors are
/// ingress-admission-scoped by design — see its own doc ("the only ways
/// to obtain a value of this type are `PrevalidatedIngress::admit_at_accept`
/// ... or the `#[cfg(test)]`-only constructors"). Reusing it here would
/// blur "this proves the stream was validly ingress-admitted" with an
/// unrelated, session-lifetime-spanning per-operation timeout that has
/// nothing to do with ingress. Same mechanics (monotonic `Instant`,
/// rechecked fresh, never cached) via [`wire::BoundedDeadline`] — the
/// generic-ized bounded I/O loops in `wire.rs` accept either type
/// identically; `wire::DeadlineBoundedIo::arm_io_deadline`'s own doc
/// already anticipated this exact seam ("Every future Active-side I/O
/// operation ... is required to call `arm_io_deadline` again, with its
/// own budget").
#[derive(Debug, Clone, Copy)]
pub struct OperationDeadline {
    started: Instant,
    budget: Duration,
}

impl OperationDeadline {
    /// `None` on a zero budget — same fail-closed posture as
    /// `CeremonyBudget::new` (a zero-duration deadline that never lets any
    /// syscall run is not meaningfully different from refusing to start).
    pub fn new(budget: Duration) -> Option<Self> {
        if budget.is_zero() {
            return None;
        }
        Some(Self {
            started: Instant::now(),
            budget,
        })
    }

    #[cfg(test)]
    pub(crate) fn already_expired_for_test() -> Self {
        Self {
            started: Instant::now() - Duration::from_secs(3600),
            budget: Duration::from_secs(1),
        }
    }
}

impl wire::BoundedDeadline for OperationDeadline {
    fn remaining(&self) -> Duration {
        self.budget.saturating_sub(self.started.elapsed())
    }
    fn is_expired(&self) -> bool {
        self.remaining().is_zero()
    }
}

/// What a real `D1::Active<'a>` gate must provide for `ActiveMeshSession`
/// to check live, per-operation forwarding authorization (2026-08-04,
/// @kiana, post-Active wire addendum `b14fcf95…` §5). Mirrors the real
/// household `SessionGate::try_authorize_forwarding(&self) -> Option<ForwardingGuard<'_>>`
/// exactly (verified directly against that type earlier this engagement —
/// see `intent::D1Admission`'s own doc) — a real adapter implements this
/// by forwarding to that method. `None` means "not authorized right
/// now": revoked, registry poisoned/unavailable, or a stale generation —
/// this crate treats every one of those identically, fail-closed, and
/// never distinguishes among them (a real D1 registry is the only thing
/// that could, and this crate does not second-guess it).
pub trait ActiveGateAuthorization {
    type Guard<'a>
    where
        Self: 'a;
    fn try_authorize(&self) -> Option<Self::Guard<'_>>;
}

/// Post-Active guarded operations (2026-08-04, @kiana, post-Active wire
/// addendum `b14fcf9520222ad3ab3ac3443ae4b0e7ba219411f41e3389751c92a402b64d8a.md`
/// and its provenance-only erratum1
/// `4be4cd3d0963cbc145b4aeb1f5450e5753e84f1b65e94e84af9ecd29832bf203.md`,
/// both self-hash verified before this code was written). A separate,
/// `G: ActiveGateAuthorization`-bounded `impl` block — the unconstrained
/// one above is untouched, so an adapter whose `Active<'a>` does not (yet)
/// implement the gate trait still gets everything it already had.
///
/// **No `TransportState`/raw stream ever returned to the caller**
/// (addendum's own implicit requirement, restated by this task): every
/// method here takes/returns only scalars, `&[u8]`/`&mut [u8]`, and typed
/// errors. `self.stream`/`self.transport` never leave this `impl` block.
///
/// **Gate per operation, not a static session property** (addendum §5):
/// `send_data` acquires the guard and holds it for the entire write;
/// `receive_data` acquires it only for the final, CPU-local copy into the
/// caller's buffer, after decrypt — never around the blocking read/decrypt
/// itself. `REKEY`/`CLOSE`/`REVOKE_NOTICE` are control-plane (addendum
/// §7) and never acquire the gate at all — see [`Self::send_outgoing_rekey_marker`]/
/// [`Self::close_gracefully`]/[`Self::notify_revoked_and_close`].
///
/// `#[allow(private_bounds)]`: `wire::DeadlineBoundedIo` is deliberately
/// `pub(crate)` (sealed against a no-op external implementation defeating
/// the whole deadline discipline — see its own doc) — no external crate
/// could satisfy this bound regardless, exactly like every existing
/// `pub(crate)` handshake function already bounded on it. The methods
/// below are reachable in principle (the struct/methods are `pub`) but
/// callable in practice only from this crate's own test suite today,
/// same posture as `run_responder_handshake`/`run_initiator_handshake`
/// pending a real external facade.
#[allow(private_bounds)]
impl<T: Read + Write + wire::DeadlineBoundedIo, G: ActiveGateAuthorization>
    ActiveMeshSession<T, G>
{
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// addendum §6: control-plane, no D1 guard. Bound to the exact
    /// `SendMarkerPermit` `before_send_marker` issued — commits via the
    /// already-existing, already-audited `commit_outgoing_rekey` (couples
    /// the counter transition to the real `TransportState::rekey_outgoing()`,
    /// validated before that irreversible call, same as it always has).
    fn send_outgoing_rekey_marker(&mut self, budget: Duration) -> Result<(), PostActiveError> {
        let permit = self.rekey.tx().before_send_marker()?;
        let next_generation = permit.next_generation();
        let deadline = OperationDeadline::new(budget).ok_or(PostActiveError::Expired)?;
        let record = Zeroizing::new(post_active::encode_rekey_record(next_generation)?);
        let mut ciphertext = Zeroizing::new(vec![0u8; record.len() + 16]);
        let ct_len = self
            .transport
            .write_message(&record, &mut ciphertext)
            .map_err(NoiseSetupError::from)?;
        wire::write_transport_record(&mut self.stream, &ciphertext[..ct_len], &deadline)?;
        self.commit_outgoing_rekey(permit)?;
        Ok(())
    }

    /// addendum §3.1/§5/§6. Sends the required `REKEY` marker first if one
    /// is due (`ExpectedRekeyMarker`), then the `DATA` record itself,
    /// holding the D1 forwarding guard for the entire write. Any failure —
    /// including a marker write failure, a denied guard, or expiry —
    /// closes the session; there is no partial/retryable state.
    pub fn send_data(
        &mut self,
        payload: &[u8],
        budget: Duration,
        now: u64,
    ) -> Result<(), PostActiveError> {
        if self.closed {
            return Err(PostActiveError::Closed);
        }
        let result = self.send_data_inner(payload, budget, now);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn send_data_inner(
        &mut self,
        payload: &[u8],
        budget: Duration,
        now: u64,
    ) -> Result<(), PostActiveError> {
        let permit = match self.rekey.tx().before_send_non_marker() {
            Ok(permit) => permit,
            Err(crate::error::RekeyError::ExpectedRekeyMarker) => {
                self.send_outgoing_rekey_marker(budget)?;
                self.rekey.tx().before_send_non_marker()?
            }
            Err(e) => return Err(e.into()),
        };
        let guard = self
            .gate
            .try_authorize()
            .ok_or(PostActiveError::NotAuthorized)?;
        if now >= self.expires_at {
            return Err(PostActiveError::Expired);
        }
        let deadline = OperationDeadline::new(budget).ok_or(PostActiveError::Expired)?;
        let record = Zeroizing::new(post_active::encode_data_record(payload)?);
        let mut ciphertext = Zeroizing::new(vec![0u8; record.len() + 16]);
        let ct_len = self
            .transport
            .write_message(&record, &mut ciphertext)
            .map_err(NoiseSetupError::from)?;
        wire::write_transport_record(&mut self.stream, &ciphertext[..ct_len], &deadline)?;
        drop(guard);
        self.rekey.tx().after_send_non_marker(permit)?;
        Ok(())
    }

    /// addendum §3.1/§5/§6. Reads and decrypts without a guard; transparently
    /// consumes `REKEY` markers (coupling the rx counter to the real
    /// `TransportState::rekey_incoming()`); closes on `CLOSE`/`REVOKE_NOTICE`
    /// (addendum §7: withdraw locally before exposing any new effect);
    /// for `DATA`, acquires the D1 guard only for the final copy into
    /// `buffer`, releasing it before returning — never around the
    /// blocking read/decrypt, and never via a caller-supplied callback
    /// (2026-08-04, @kiana catch: no callback/sink/closure under the
    /// guard, ever). `buffer` too small to hold the delivered payload
    /// closes the session and copies zero bytes (addendum §5: "Se o guard
    /// falha ou o buffer é pequeno, nenhum byte é copiado; descartar e
    /// fechar").
    pub fn receive_data(
        &mut self,
        buffer: &mut [u8],
        budget: Duration,
        now: u64,
    ) -> Result<usize, PostActiveError> {
        if self.closed {
            return Err(PostActiveError::Closed);
        }
        let result = self.receive_data_inner(buffer, budget, now);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn receive_data_inner(
        &mut self,
        buffer: &mut [u8],
        budget: Duration,
        now: u64,
    ) -> Result<usize, PostActiveError> {
        loop {
            let deadline = OperationDeadline::new(budget).ok_or(PostActiveError::Expired)?;
            let ciphertext = wire::read_transport_record(&mut self.stream, &deadline)?;
            let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
            let pt_len = self
                .transport
                .read_message(&ciphertext, &mut plaintext)
                .map_err(NoiseSetupError::from)?;
            let record = post_active::decode_post_active_record(&plaintext[..pt_len])?;
            match record {
                PostActiveRecord::Rekey { next_generation } => {
                    self.commit_incoming_rekey(next_generation)?;
                    continue;
                }
                PostActiveRecord::Close => {
                    self.rekey
                        .rx()
                        .on_receive(rekey::IncomingRecord::NonMarker)?;
                    return Err(PostActiveError::PeerClosed);
                }
                PostActiveRecord::RevokeNotice => {
                    self.rekey
                        .rx()
                        .on_receive(rekey::IncomingRecord::NonMarker)?;
                    return Err(PostActiveError::PeerRevoked);
                }
                PostActiveRecord::Data(payload) => {
                    self.rekey
                        .rx()
                        .on_receive(rekey::IncomingRecord::NonMarker)?;
                    let guard = self
                        .gate
                        .try_authorize()
                        .ok_or(PostActiveError::NotAuthorized)?;
                    if now >= self.expires_at {
                        return Err(PostActiveError::Expired);
                    }
                    if payload.len() > buffer.len() {
                        return Err(PostActiveError::ReceiveBufferTooSmall {
                            buffer_len: buffer.len(),
                            payload_len: payload.len(),
                        });
                    }
                    buffer[..payload.len()].copy_from_slice(&payload);
                    drop(guard);
                    return Ok(payload.len());
                }
            }
        }
    }

    /// addendum §6/§7: graceful, local-initiated close. Withdraws
    /// authority FIRST (before any write is attempted), then — if a
    /// `REKEY` marker is due — emits it and commits the real
    /// `rekey_outgoing()` transition, THEN sends `CLOSE` under the new
    /// key. Idempotent: a second call is a no-op `Ok(())`. Best-effort
    /// from here on — a write failure at any step still leaves the
    /// session closed (never un-withdraws authority), and is reported
    /// back rather than silently discarded so a caller can notice a
    /// non-graceful teardown, but does not change the terminal outcome.
    pub fn close_gracefully(&mut self, budget: Duration) -> Result<(), PostActiveError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let permit = match self.rekey.tx().before_send_non_marker() {
            Ok(permit) => permit,
            Err(crate::error::RekeyError::ExpectedRekeyMarker) => {
                self.send_outgoing_rekey_marker(budget)?;
                self.rekey.tx().before_send_non_marker()?
            }
            Err(e) => return Err(e.into()),
        };
        let deadline = OperationDeadline::new(budget).ok_or(PostActiveError::Expired)?;
        let record = Zeroizing::new(post_active::encode_close_record());
        let mut ciphertext = Zeroizing::new(vec![0u8; record.len() + 16]);
        let ct_len = self
            .transport
            .write_message(&record, &mut ciphertext)
            .map_err(NoiseSetupError::from)?;
        wire::write_transport_record(&mut self.stream, &ciphertext[..ct_len], &deadline)?;
        self.rekey.tx().after_send_non_marker(permit)?;
        Ok(())
    }

    /// addendum §6/§7: best-effort `REVOKE_NOTICE` after local authority
    /// withdrawal. Deliberately does NOT force a `REKEY` marker cycle the
    /// way [`Self::close_gracefully`] does — addendum §6: "se não puder
    /// ser enviado imediatamente (inclusive porque um marker seria
    /// obrigatório), omitir e fechar é correto." If a marker is due, the
    /// notice is simply omitted; the session still closes. Never mutates
    /// any roster — closing/retiring the local session is the only
    /// effect (addendum §3.2).
    pub fn notify_revoked_and_close(&mut self, budget: Duration) -> Result<(), PostActiveError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let permit = match self.rekey.tx().before_send_non_marker() {
            Ok(permit) => permit,
            Err(_) => return Ok(()), // marker would be required — omit the notice, still closed
        };
        let Some(deadline) = OperationDeadline::new(budget) else {
            return Ok(());
        };
        let record = Zeroizing::new(post_active::encode_revoke_notice_record());
        let mut ciphertext = Zeroizing::new(vec![0u8; record.len() + 16]);
        let ct_len = match self.transport.write_message(&record, &mut ciphertext) {
            Ok(n) => n,
            Err(_) => return Ok(()),
        };
        let _ = wire::write_transport_record(&mut self.stream, &ciphertext[..ct_len], &deadline);
        let _ = self.rekey.tx().after_send_non_marker(permit);
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
    checkpoint: &LocalCheckpoint,
    lease_expires_at: u64,
    ingress_expiry: u64,
    now: u64,
) -> Result<(crate::intent::IntentNonceKey, u64), AuthFrameError> {
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

    // Item 8, D9 addendum §4.8 (2026-08-04, @kiana, WIP audit BLOCKER —
    // restored: the `effective_expires_at = min(...)` check below does
    // NOT imply this. Example that makes the gap concrete: intent.not_after
    // = 10_000, peer delegation.not_after = 1_000, now = 500 — `now <
    // min(...)` passes (500 < 1_000), but the intent still claims an
    // authority window (10_000) wider than what the delegation actually
    // grants (1_000). That is an authority-scoping violation independent
    // of whether `now` currently happens to fall inside every window —
    // the min-based half-open check only asks "is `now` still within
    // every relevant window", never "does the intent's OWN claim
    // overstate what was actually delegated". Both must hold.
    if intent_record.not_after() > proof_i.delegation().not_after() {
        return Err(crate::error::IntentError::TtlInvalid.into());
    }

    // Item 8, B-SESSAO v6 §7 (2026-08-04, @kiana, WIP audit point A,
    // definitive; self-hash verified against
    // `daisy-bsessao-v6.7343d0752d21b1487e387e74fcd4aa4d28d44bea6b7d3264f7d8a08e0619ac67.md`,
    // §7): `effective_expires_at = min(checkpoint.not_after,
    // local_delegation.not_after, peer_delegation.not_after,
    // lease_expires_at, ingress_expiry)`, D9 carrier adding
    // `intent.not_after` as one more cap — a SEPARATE, complementary check
    // from the authority-scoping inequality above, not a replacement for
    // it. Half-open: `now < effective_expires_at`; equality is already
    // expired. Computed once here and returned (v6 §10) so the caller can
    // both re-check it later (immediately before the reversible
    // reserve/Ack point) and carry it into the Active session itself.
    let expires_at = effective_expires_at(
        checkpoint.not_after,
        local.delegation.not_after(),
        proof_i.delegation().not_after(),
        lease_expires_at,
        ingress_expiry,
        intent_record.not_after(),
    );
    check_effective_expiry(now, expires_at)?;

    // 2026-08-04, @kiana, erratum1 E2: the nonce key deliberately excludes
    // both channel and intent_digest — see IntentNonceKey's own doc.
    let nonce: [u8; 32] = intent_record
        .nonce()
        .try_into()
        .map_err(|_| crate::error::IntentError::ShapeMismatch)?;
    Ok((
        crate::intent::IntentNonceKey::new(
            intent_record.hh_id().to_string(),
            intent_record.initiator_m_id().to_string(),
            intent_record.delegated_key_id().to_string(),
            nonce,
        ),
        expires_at,
    ))
}

/// Drive the responder side: Idle → Handshaking → SendingProofR →
/// AwaitingIntent → AwaitingProofI → SendingFinalConfirm →
/// AwaitingActivate → Active. `ingress` is consumed internally — its
/// stream and evidence are never handed back to the caller separately
/// (hardened 2026-08-04). See the module doc for why this is
/// `pub(crate)`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_responder_handshake<'d1, S, Sig, Ver, Ledger, D1, C, Res>(
    ingress: PrevalidatedIngress<S>,
    local: &LocalIdentity,
    checkpoint: &LocalCheckpoint,
    expected_channel: ExpectedChannel,
    policy: &DelegationPolicy,
    delegation_verifier: &Ver,
    k_mesh: &Sig,
    nonce_ledger: &Ledger,
    d1_admission: &'d1 D1,
    clock: &C,
    resolver: &Res,
    // 2026-08-04, @kiana, WIP audit point A, v6 §7: one of the
    // `effective_expires_at` components this crate does not itself
    // measure — the caller's own live lease bound, wall-clock `u64`,
    // required rather than defaulted to unbounded.
    lease_expires_at: u64,
    rekey_threshold: RekeyThreshold,
) -> Result<ActiveMeshSession<S, D1::Active<'d1>>, AuthFrameError>
where
    S: Read + Write + wire::DeadlineBoundedIo,
    Sig: MeshSessionFrameSigner,
    Ver: DelegationSignatureVerifier,
    Ledger: crate::intent::IntentNonceLedger,
    D1: crate::intent::D1Admission,
    C: crate::intent::Clock,
    Res: crate::intent::RetainedGenerationResolver,
{
    check_signer_matches_delegation(k_mesh, &local.delegation)?;
    check_local_delegation_channel(&local.delegation, expected_channel)?;

    let (mut stream, ingress_evidence, deadline) = ingress.consume();
    // 2026-08-04, @kiana, definitive B: `deadline` is the opaque,
    // monotonic `CeremonyDeadline` born at admission (`admit_at_accept`),
    // not a separately-suppliable parameter this function's caller could
    // pick independently. Expiry checked before the first Noise byte too,
    // not only after — an already-expired admission never even attempts
    // the handshake.
    check_ceremony_deadline(&deadline)?;

    // 2026-08-04, @kiana, round 4 + runtime-facade audit `3cbbfb37…` P1-1
    // (reordered — supersedes minting this before `deadline` even
    // existed): still before any I/O at all, long before ActivateAck is
    // ever written, but now also after the FIRST deadline check has run —
    // an already-expired admission never even mints rekey state. See the
    // hardening note on ActiveMeshSession's construction below for why
    // minting stays this early relative to I/O.
    let rekey = SessionRekeyState::new(rekey_threshold)?;

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
    let proof_r = auth_frames::sign_frame(proof_r, k_mesh, &deadline)?;
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
        &deadline,
    )?;

    // 2026-08-04, @kiana, runtime-facade audit `3cbbfb37…` P0-5/item 5
    // (definitive — supersedes building `initiator_verifier` directly
    // from `proof_i.delegation().delegated_pub()`): that was
    // self-consistency only — proof the frame matches a key the PEER
    // itself embeds, never that D4 still authorizes that key for this
    // exact `(hh_id, initiator_m_id, channel, delegated_key_id)` tuple.
    // Resolve the actually-authorized key BEFORE building any verifier
    // from it, and BEFORE nonce consumption (erratum1 E4 ordering) —
    // deadline checked immediately before this seam, same discipline as
    // every other potentially-blocking pre-seam step (item 6).
    check_ceremony_deadline(&deadline)?;
    let resolved = resolver.resolve(
        proof_i.hh_id(),
        proof_i.self_m_id(),
        expected_channel,
        proof_i.delegation().delegated_key_id(),
        &deadline,
    )?;
    // D4's own record ties a generation's `not_after` to its delegation's
    // `not_after` (`RecordDelegationNotAfterDrift`,
    // zain-mesh-session-signer-d4-v11.cbb757f8…, §7) — a resolver whose
    // returned generation has drifted from what this delegation itself
    // claims is rejected here, before it is ever trusted for anything.
    if resolved.not_after() != proof_i.delegation().not_after() {
        return Err(crate::error::IntentError::ResolvedGenerationNotAfterMismatch.into());
    }
    let initiator_verifier = auth_frames::verifier_from_delegated_pub(resolved.delegated_pub())?;
    // Verified against the RESOLVED key, never the peer-claimed one — a
    // resolver that (correctly) returns a different key than whatever the
    // peer embedded makes this fail here, not silently pass on
    // self-consistency alone.
    auth_frames::verify_frame(&proof_i, &sig_array(proof_i.sig())?, &initiator_verifier)?;

    let initiator_m_id = proof_i.self_m_id().to_string();
    let initiator_cert_fingerprint = proof_i.self_cert_fingerprint().to_vec();
    let initiator_hh_id = proof_i.hh_id().to_string();
    // Not read by anything else in this crate yet — assembled here as the
    // D4 half of the old combined key, so a future facade has a single,
    // already-validated value to consume rather than re-deriving one from
    // scratch (2026-08-04, @kiana, item 4). Same "carried, not dead"
    // posture as `ActiveMeshSession.gate`/`.stream`.
    let _signer_binding = crate::intent::IntentSignerBinding::new(
        initiator_hh_id.clone(),
        initiator_m_id.clone(),
        expected_channel,
        proof_i.delegation().delegated_key_id().to_string(),
        &resolved,
        proof_i.delegation().serial(),
    );

    // --- Combined intent check (D9 carrier-B addendum §4), then the
    // single nonce-consumption call site (addendum §5) ---
    let now = clock.now().map_err(AuthFrameError::from)?;
    let (nonce_key, expires_at) = run_combined_intent_check(
        &intent_record,
        &received_intent_digest,
        &proof_i,
        &initiator_verifier,
        local,
        checkpoint,
        lease_expires_at,
        ingress_evidence.ingress_expiry,
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
        expected_channel,
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
    let final_confirm = auth_frames::sign_frame(final_confirm, k_mesh, &deadline)?;
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
    let activate_ack = auth_frames::sign_frame(activate_ack, k_mesh, &deadline)?;

    // 2026-08-04, @kiana, WIP audit point A, terminal-expiry refinement:
    // revalidate `now < expires_at` once more, right before the reversible
    // reserve/Ack point — the ceremony may have consumed real time since
    // the first check (right after Proof-I/nonce). Deliberately NOT
    // repeated again after this: once the Ack write completes, that is
    // the same irreversible-transmission boundary as everywhere else in
    // this crate (see `write_all_with_deadline`'s doc) — if expiry crosses
    // during the final write syscall itself, the physical Ack wins the
    // race, the session is born already past `expires_at`, and the first
    // future authorization/DATA check (once one exists) denies it; this
    // preserves linearization without inventing a new fallible check
    // between Ack-complete and activation.
    let now = clock.now().map_err(AuthFrameError::from)?;
    check_effective_expiry(now, expires_at)?;

    // 2026-08-04, @kiana, erratum1 E4 + C.4 + runtime-facade audit
    // `3cbbfb37…` item 4 (definitive): reserve the D1 Pending permit
    // BEFORE the Ack write, against the AUTHENTICATED peer-membership
    // binding — this ceremony's own session_id (h_final), the
    // AUTHENTICATED initiator fingerprint (verified above via
    // pass_delegation_gate/verify_frame, not a bare claim), and the live
    // checkpoint this ceremony actually ran against. D4 signer authority
    // (delegated_key_id/delegated_pub/channel/generation) is a SEPARATE
    // concern — see `_signer_binding` above — D1 membership has no way to
    // verify it and the real registry's own binding type carries none of
    // it either. A real D1 implementation must verify this exact full
    // binding HERE, in `reserve_pending` — not merely by `peer_m_id` alone
    // — and carry it forward into the returned permit: `commit_after_ack`
    // (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…` CFX-2,
    // correction) performs no recheck of any kind, by design, once this
    // call has reserved the permit.
    let d1_key = crate::intent::D1MembershipKey::new(
        h_final.clone(),
        initiator_hh_id.clone(),
        initiator_m_id.clone(),
        initiator_cert_fingerprint.clone(),
        checkpoint.hash.clone(),
        checkpoint.sequence,
    );
    let pending = d1_admission.reserve_pending(&d1_key, &deadline)?;

    // 3. write_all (write_transport_record uses write_all internally).
    // 2026-08-04, @kiana, round 4: `rekey` was minted at the top of this
    // function, before any I/O — nothing fallible runs between here and
    // the D1 outcome below except the D1 terminal call itself.
    //
    // 2026-08-04, @kiana, runtime-facade audit `3cbbfb37…` P0-1/P0-2/P0-3/
    // P0-4 (definitive — supersedes the earlier fallible-`Result`
    // `activate_if_authorized` shape): `commit_after_ack` is infallible
    // and takes no deadline (see `D1Pending`'s own doc for why that is
    // safe) — reaching this write's `Ok(())` arm now commits directly,
    // with nothing fallible or external between the write's success and
    // the commit call. `gate` is embedded directly into the session
    // (2026-08-04, @kiana, definitive A — never returned separately,
    // never droppable while the session lives). A partial/failed write
    // cancels the just-reserved permit and folds the (never discarded)
    // `D1CancelOutcome` into the propagated error alongside the original
    // write failure — the write failure is why this attempt failed; the
    // cancel outcome is what happened to the D1 permit as a result
    // (2026-08-04, @kiana, WIP audit item (b) + P0-3, no more `let _ =`).
    match send_frame(
        &mut stream,
        &mut transport,
        &AuthFrame::ActivateAck(activate_ack),
        &deadline,
    ) {
        Ok(()) => {}
        Err(e) => {
            let cancel_outcome = pending.cancel_before_ack();
            return Err(AuthFrameError::AckExchangeFailedWithCancelOutcome {
                source: Box::new(e),
                cancel_outcome,
            });
        }
    }
    let gate = pending.commit_after_ack();

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
        expires_at,
        closed: false,
    })
}

/// Drive the initiator side: Idle → Handshaking → AwaitingProofR →
/// SendingProofI → AwaitingFinalConfirm → SendingActivate →
/// AwaitingActivateAck → Active. See the module doc for why this is
/// `pub(crate)`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_initiator_handshake<'d1, S, Sig, Ver, D1, C>(
    ingress: PrevalidatedIngress<S>,
    pending_intent: crate::intent::PendingIntent,
    local: &LocalIdentity,
    checkpoint: &LocalCheckpoint,
    expected_channel: ExpectedChannel,
    policy: &DelegationPolicy,
    delegation_verifier: &Ver,
    k_mesh: &Sig,
    d1_admission: &'d1 D1,
    // 2026-08-04, @kiana, WIP audit point A: now used — the initiator's
    // own `effective_expires_at` check (v6 §7) needs a live `now` reading
    // once `proof_r`'s delegation is verified, the same requirement the
    // responder side already had via the combined intent check.
    clock: &C,
    // See the identical parameter on `run_responder_handshake`.
    lease_expires_at: u64,
    rekey_threshold: RekeyThreshold,
) -> Result<ActiveMeshSession<S, D1::Active<'d1>>, AuthFrameError>
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

    let (mut stream, ingress_evidence, deadline) = ingress.consume();
    // 2026-08-04, @kiana, definitive B: opaque monotonic deadline born at
    // admission, same as the responder side — checked before the first
    // Noise byte too.
    check_ceremony_deadline(&deadline)?;

    // 2026-08-04, @kiana, round 4 + runtime-facade audit `3cbbfb37…` P1-1
    // (reordered — supersedes minting this before `deadline` even
    // existed): still before Proof-I, before Activate, before anything is
    // sent at all — if the mint fails, this side sends literally nothing —
    // but now also after the FIRST deadline check has run.
    let rekey = SessionRekeyState::new(rekey_threshold)?;

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
        &deadline,
    )?;
    let responder_verifier =
        auth_frames::verifier_from_delegated_pub(proof_r.delegation().delegated_pub())?;
    auth_frames::verify_frame(&proof_r, &sig_array(proof_r.sig())?, &responder_verifier)?;

    // 2026-08-04, @kiana, WIP audit point A, v6 §7/§10 (definitive;
    // self-hash verified against
    // `daisy-bsessao-v6.7343d0752d21b1487e387e74fcd4aa4d28d44bea6b7d3264f7d8a08e0619ac67.md`,
    // §7): the initiator's own `effective_expires_at` check, now that
    // `proof_r`'s delegation (the peer's) is fully verified — the
    // symmetric counterpart of the responder side's combined intent
    // check's item 8. Computed once and captured (`expires_at`) so it can
    // be re-checked later and carried into the Active session (v6 §10).
    let now = clock.now().map_err(AuthFrameError::from)?;
    let expires_at = effective_expires_at(
        checkpoint.not_after,
        local.delegation.not_after(),
        proof_r.delegation().not_after(),
        lease_expires_at,
        ingress_evidence.ingress_expiry,
        pending_intent.intent().not_after(),
    );
    check_effective_expiry(now, expires_at)?;

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
    let proof_i = auth_frames::sign_frame(proof_i, k_mesh, &deadline)?;
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
    let activate = auth_frames::sign_frame(activate, k_mesh, &deadline)?;

    // 2026-08-04, @kiana, WIP audit point A, terminal-expiry refinement —
    // see the identical note in run_responder_handshake: revalidate once
    // more right before the reversible reserve/Activate-send point:
    // nothing fallible is added after Activate is sent/ActivateAck is
    // verified — that boundary already has its own atomic
    // cancel-or-activate discipline (erratum1 E4), unrelated to this
    // wall-clock check.
    let now = clock.now().map_err(AuthFrameError::from)?;
    check_effective_expiry(now, expires_at)?;

    // 2026-08-04, @kiana, erratum1 E4 closing paragraph + C.4 + runtime-
    // facade audit `3cbbfb37…` item 4 (definitive): the initiator applies
    // the SAME local discipline while awaiting ActivateAck, against the
    // SAME authenticated D1-membership binding as the responder side —
    // Pending/gate closed before Activate is sent, commit immediately on
    // a valid Ack, cancel on any error/timeout in between. `peer_*` is
    // the responder here (role-neutral naming, unchanged from before the
    // split). D4 signer authority for the LOCAL delegation
    // (`local.delegation.delegated_pub()`/`serial()`) is deliberately NOT
    // assembled into an `IntentSignerBinding` on this side yet — doing so
    // would mean either fabricating a D4 `generation` this crate has no
    // resolver for on the initiator side, or silently reusing a
    // placeholder value; item 5 scopes the initiator-side seam to a
    // future facade's `load_exact` for the LOCAL signer (already modeled
    // by the existing `Sig: MeshSessionFrameSigner` bound this function
    // takes), not to resolving the PEER's generation the way the
    // responder now does.
    let d1_key = crate::intent::D1MembershipKey::new(
        h_final.clone(),
        local.hh_id.clone(),
        expected.m_id.clone(),
        expected.cert_fingerprint.to_vec(),
        checkpoint.hash.clone(),
        checkpoint.sequence,
    );
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
        // 2026-08-04, @kiana, WIP audit point (3), terminal-expiry
        // symmetry (definitive — this check REMOVED, not added):
        // reaching this point means a genuinely valid ActivateAck was
        // received — by construction, the responder already wrote that
        // Ack and (per this crate's own atomic-linearization discipline)
        // immediately called its own `commit_after_ack` right after
        // (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…` CFX-2,
        // name corrected — the superseded `activate_if_authorized` no
        // longer exists), with nothing fallible in between. The responder
        // may therefore already be Active by the time this initiator-side
        // code runs. Rejecting here for `deadline` would cancel this
        // side's own Pending and never reach Active locally, while the
        // peer already did — the exact same split-brain
        // `write_all_with_deadline`'s own doc describes for the writer
        // side, just from the reader's side of the identical exchange.
        // `deadline` still bounds reserve/I/O/cancel; it does not undo an
        // already-fully-verified terminal Ack.
        Ok(activate_ack)
    })();

    let _activate_ack = match ack_result {
        Ok(ack) => ack,
        Err(e) => {
            // 2026-08-04, @kiana, runtime-facade audit `3cbbfb37…` P0-3
            // (definitive — supersedes the earlier `let _ =`):
            // `cancel_before_ack` returns `D1CancelOutcome` directly, and
            // it is folded into the propagated error rather than
            // discarded — same discipline as the responder side's write
            // failure. `e` (the original Ack failure) is still the
            // reported cause.
            let cancel_outcome = pending.cancel_before_ack();
            return Err(AuthFrameError::AckExchangeFailedWithCancelOutcome {
                source: Box::new(e),
                cancel_outcome,
            });
        }
    };

    // Ack valid, verified in full: commit the local Pending immediately,
    // infallibly, with nothing fallible/external between the check above
    // and this call (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…`
    // P0-1/P0-2/P0-4, definitive — supersedes the earlier fallible
    // `activate_if_authorized`). See the identical note in
    // `run_responder_handshake` and `D1Pending::commit_after_ack`'s own
    // doc for why this is safe even though a revoke may have already
    // announced.
    let gate = pending.commit_after_ack();

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
        expires_at,
        closed: false,
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

    /// Test-only stand-in that accepts any delegation, unconditionally —
    /// proves the *state machine's wiring* (order of calls, what gates
    /// what) independent of the still-undecided real preimage/verifier.
    /// Never shipped as part of this crate's real API.
    struct AlwaysAcceptDelegation;
    impl DelegationSignatureVerifier for AlwaysAcceptDelegation {
        fn verify_delegation(
            &self,
            _delegation: &MeshSessionDelegation,
            _deadline: &CeremonyDeadline,
        ) -> Result<(), crate::error::DelegationError> {
            Ok(())
        }
    }

    /// Always-succeeding D1Admission double: `Pending<'a>`/`Active<'a>` are
    /// just `()`. Used by tests where D1 admission's own mechanism isn't
    /// under test — the dedicated D1 REDs (and the GAT/Drop-lock-free
    /// proofs in `intent.rs`'s own test module) inject their own,
    /// genuinely borrowed doubles.
    impl crate::intent::D1Pending<()> for () {
        fn commit_after_ack(self) {}
        fn cancel_before_ack(self) -> crate::intent::D1CancelOutcome {
            crate::intent::D1CancelOutcome::CancelledAndRemoved
        }
    }

    struct AlwaysAdmitD1;
    impl crate::intent::D1Admission for AlwaysAdmitD1 {
        type Pending<'a> = ();
        type Active<'a> = ();
        fn reserve_pending(
            &self,
            _key: &crate::intent::D1MembershipKey,
            _deadline: &CeremonyDeadline,
        ) -> Result<(), crate::error::IntentError> {
            Ok(())
        }
    }

    /// D4 resolver double pre-configured with a fixed, independently-known
    /// authority — NOT derived from whatever a peer's frame claims
    /// (2026-08-04, item 5). Every call site builds one from the SAME
    /// values it independently used to construct the initiator's own
    /// `LocalIdentity`/delegation, so this stays a genuine (if simplified)
    /// resolver double rather than routing the peer's claim back through
    /// itself — the dedicated resolver REDs additionally inject one
    /// configured to return a deliberately MISMATCHED key/generation.
    struct FixedResolver {
        delegated_pub: Vec<u8>,
        generation: u64,
        not_after: u64,
    }
    impl crate::intent::RetainedGenerationResolver for FixedResolver {
        fn resolve(
            &self,
            _hh_id: &str,
            _initiator_m_id: &str,
            _channel: ExpectedChannel,
            _delegated_key_id: &str,
            _deadline: &CeremonyDeadline,
        ) -> Result<crate::intent::ResolvedSignerAuthority, crate::error::IntentError> {
            Ok(crate::intent::ResolvedSignerAuthority::new(
                self.delegated_pub.clone(),
                self.generation,
                self.not_after,
            ))
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
            _channel: ExpectedChannel,
            _deadline: &CeremonyDeadline,
        ) -> Result<crate::intent::NonceConsumeOutcome, crate::error::IntentError> {
            let mut set = self.consumed.lock().unwrap();
            if !set.insert(key.clone()) {
                return Ok(crate::intent::NonceConsumeOutcome::AlreadyConsumed);
            }
            Ok(crate::intent::NonceConsumeOutcome::Committed)
        }
    }

    /// Panics if `consume` is ever called — proves a rejection happened
    /// strictly BEFORE the single nonce-consumption call site (D9
    /// addendum §5), the same "zero X before Y" discipline `PanicsOnIo`
    /// already applies to I/O elsewhere in this test suite.
    struct PanicsIfConsumed;
    impl crate::intent::IntentNonceLedger for PanicsIfConsumed {
        fn consume(
            &self,
            _key: &crate::intent::IntentNonceKey,
            _not_after: u64,
            _digest: &[u8; 32],
            _channel: ExpectedChannel,
            _deadline: &CeremonyDeadline,
        ) -> Result<crate::intent::NonceConsumeOutcome, crate::error::IntentError> {
            panic!(
                "nonce was consumed before the D9 addendum SS4.8 authority-scoping check rejected"
            );
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

        let initiator_resolver = FixedResolver {
            delegated_pub: initiator_verifying
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            generation: 1,
            not_after: u64::MAX / 2,
        };

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence {
                        observed_at: 1,
                        ingress_expiry: u64::MAX / 2,
                    },
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
                    &initiator_resolver,
                    u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 2,
                ingress_expiry: u64::MAX / 2,
            },
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
            u64::MAX / 2,
            RekeyThreshold::new(3).unwrap(),
        )
        .unwrap();

        let responder_session = responder.join().unwrap();
        (initiator_session, responder_session)
    }

    /// item 5 RED (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…`
    /// P0-5): a `RetainedGenerationResolver` that returns a genuinely
    /// DIFFERENT key than the one the initiator actually signed with must
    /// cause rejection — proving `initiator_verifier` is built from the
    /// RESOLVED key, not `proof_i.delegation().delegated_pub()` (the
    /// peer's own embedded, self-consistency-only claim). If this crate
    /// regressed to building the verifier from the peer's claim again,
    /// this test would incorrectly pass (Active) instead of failing.
    #[test]
    fn red_responder_resolver_returning_a_different_key_than_signed_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let responder_key = SigningKey::random(&mut OsRng);
        let responder_verifying = VerifyingKey::from(&responder_key);
        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_verifying = VerifyingKey::from(&initiator_key);
        // A THIRD, unrelated key — never used to sign anything — is what
        // the resolver (wrongly, deliberately for this test) returns.
        let wrong_key = SigningKey::random(&mut OsRng);
        let wrong_verifying = VerifyingKey::from(&wrong_key);
        assert_ne!(
            initiator_verifying.to_encoded_point(true).as_bytes(),
            wrong_verifying.to_encoded_point(true).as_bytes(),
            "test fixture bug: wrong_key must differ from the real initiator key"
        );

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
        let resolver_returning_wrong_key = FixedResolver {
            delegated_pub: wrong_verifying.to_encoded_point(true).as_bytes().to_vec(),
            generation: 1,
            not_after: u64::MAX / 2,
        };

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence {
                        observed_at: 1,
                        ingress_expiry: u64::MAX / 2,
                    },
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
                    &resolver_returning_wrong_key,
                    u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 2,
                ingress_expiry: u64::MAX / 2,
            },
            far_future_budget(),
        );
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &initiator_identity,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0x81; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );
        // The initiator genuinely signs with its real key — the responder
        // will reject not because the initiator misbehaved, but because
        // the (misconfigured, for this test) resolver disagrees.
        let _initiator_result = run_initiator_handshake(
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
            u64::MAX / 2,
            RekeyThreshold::new(3).unwrap(),
        );

        let responder_result = responder.join().unwrap();
        match responder_result {
            Err(AuthFrameError::BadSignature) => {}
            Err(other) => {
                panic!("expected BadSignature (resolver's wrong key rejected), got {other:?}")
            }
            Ok(_) => panic!(
                "expected the responder to reject Proof-I's signature against the \
                 resolver's (wrong) key, but it reached Active"
            ),
        }
    }

    #[test]
    fn full_handshake_reaches_active_on_both_sides_with_matching_h_final() {
        let (initiator, responder) = full_handshake();
        assert_eq!(initiator.h_final(), responder.h_final());
        assert_eq!(initiator.peer_m_id(), "responder-1");
        assert_eq!(responder.peer_m_id(), "initiator-1");
        assert_eq!(initiator.ingress_evidence().observed_at, 2);
        assert_eq!(responder.ingress_evidence().observed_at, 1);
        // WIP audit point A, v6 §10: both sides carry the SAME computed
        // expires_at. `full_handshake`'s fixtures use `u64::MAX / 2` for
        // local/peer delegation, lease, ingress_expiry, and the intent's
        // own not_after — but `fixed_checkpoint().not_after` is
        // `1_000_000`, strictly the smallest of the 6, so the true
        // minimum (and therefore the stored value) must be exactly
        // `1_000_000`, not `u64::MAX / 2` — proving `effective_expires_at`
        // actually picked the checkpoint component, not just echoed
        // whichever component happens to be listed first/last.
        assert_eq!(initiator.expires_at(), 1_000_000);
        assert_eq!(responder.expires_at(), 1_000_000);
    }

    /// WIP audit point A unit tests: `effective_expires_at` genuinely
    /// picks the minimum across all 6 components (not just the first/last
    /// one), and `check_effective_expiry`'s half-open boundary is exact —
    /// `expires_at - 1` accepted, `== expires_at` rejected.
    #[test]
    fn effective_expires_at_picks_the_true_minimum_from_any_position() {
        // Each of the 6 positions gets a turn being the unique minimum.
        let base = 1_000_000u64;
        let components = |min_at: usize| -> [u64; 6] {
            let mut c = [base; 6];
            c[min_at] = 500;
            c
        };
        for pos in 0..6 {
            let c = components(pos);
            let got = effective_expires_at(c[0], c[1], c[2], c[3], c[4], c[5]);
            assert_eq!(got, 500, "position {pos} should have been the minimum");
        }
    }

    #[test]
    fn red_check_effective_expiry_boundary_expires_at_minus_one_accepted_equality_rejected() {
        let expires_at = 1_000u64;
        assert!(check_effective_expiry(expires_at - 1, expires_at).is_ok());
        assert!(matches!(
            check_effective_expiry(expires_at, expires_at),
            Err(AuthFrameError::Intent(
                crate::error::IntentError::TtlInvalid
            ))
        ));
    }

    /// D9 addendum SS4.8 RED (2026-08-04, @kiana, blocker): a real,
    /// validly-signed intent whose OWN `not_after` (2_000) exceeds the
    /// initiator delegation's `not_after` (1_000) — an authority-scoping
    /// violation the `effective_expires_at = min(...)` composite alone
    /// does NOT catch, since `now` (0, via `FixedClock(0)`) is still
    /// below both values. `PanicsIfConsumed` proves the rejection happens
    /// strictly before the single nonce-consume call site. Hand-crafted
    /// (bypassing `run_initiator_handshake`, whose own
    /// `PendingIntent::verify_binds_to` preflight would otherwise reject
    /// this before any byte is sent) to exercise the RESPONDER's
    /// independent, defense-in-depth check on what a peer actually sent
    /// — same pattern as `red_proof_i_checkpoint_mutant_rejected_by_responder`.
    #[test]
    fn red_intent_not_after_exceeding_delegation_not_after_rejected_before_nonce_consume() {
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

        // Initiator delegation authorizes only up to not_after = 1_000 —
        // strictly less than the intent's own claimed not_after below.
        // `now` (FixedClock(0)) stays below both, so the min-based
        // composite alone would incorrectly accept this. Generated before
        // the responder thread spawns so the resolver double can be
        // pre-configured with the real key/expiry, same as every other
        // call site.
        const DELEGATION_NOT_AFTER: u64 = 1_000;
        const INTENT_NOT_AFTER: u64 = 2_000;
        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_verifying = VerifyingKey::from(&initiator_key);
        let initiator_resolver = FixedResolver {
            delegated_pub: initiator_verifying
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            generation: 1,
            not_after: DELEGATION_NOT_AFTER,
        };

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence {
                        observed_at: 1,
                        ingress_expiry: u64::MAX / 2,
                    },
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
                    &PanicsIfConsumed,
                    &AlwaysAdmitD1,
                    &FixedClock(0),
                    &initiator_resolver,
                    u64::MAX / 2,
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

        let initiator_delegation = delegation_for_key(
            &initiator_verifying,
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            0,
            DELEGATION_NOT_AFTER,
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
            [0x85; 32],
            INTENT_NOT_AFTER,
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
        let checkpoint = fixed_checkpoint();
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
            initiator_delegation,
            connection_intent_digest,
            vec![0u8; 64],
        )
        .unwrap();
        let proof_i = auth_frames::sign_frame(proof_i, &k_mesh, &far_future_deadline()).unwrap();
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
            Err(AuthFrameError::Intent(
                crate::error::IntentError::TtlInvalid
            ))
        ));
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
        let initiator_resolver = FixedResolver {
            delegated_pub: initiator_verifying
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            generation: 1,
            not_after: u64::MAX / 2,
        };

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence {
                        observed_at: 1,
                        ingress_expiry: u64::MAX / 2,
                    },
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
                    &initiator_resolver,
                    u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 2,
                ingress_expiry: u64::MAX / 2,
            },
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
            u64::MAX / 2,
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

        // Generated before the responder thread spawns (this test never
        // reaches the resolver — it rejects on ExpectedPeerMismatch first
        // — but every call site pre-configures a real one regardless).
        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_verifying = VerifyingKey::from(&initiator_key);
        let initiator_resolver = FixedResolver {
            delegated_pub: initiator_verifying
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            generation: 1,
            not_after: u64::MAX / 2,
        };

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence {
                        observed_at: 1,
                        ingress_expiry: u64::MAX / 2,
                    },
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
                    &initiator_resolver,
                    u64::MAX / 2,
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

        let initiator_delegation = delegation_for_key(
            &initiator_verifying,
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
        let proof_i = auth_frames::sign_frame(proof_i, &k_mesh, &far_future_deadline()).unwrap();
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
        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_verifying = VerifyingKey::from(&initiator_key);
        let initiator_resolver = FixedResolver {
            delegated_pub: initiator_verifying
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            generation: 1,
            not_after: u64::MAX / 2,
        };

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence {
                        observed_at: 1,
                        ingress_expiry: u64::MAX / 2,
                    },
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
                    &initiator_resolver,
                    u64::MAX / 2,
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

        let initiator_delegation = delegation_for_key(
            &initiator_verifying,
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
        let proof_i = auth_frames::sign_frame(proof_i, &k_mesh, &far_future_deadline()).unwrap();
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
            panic!("stream deadline was armed before rejection");
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
            IngressEvidence {
                observed_at: 1,
                ingress_expiry: u64::MAX / 2,
            },
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
            // Never reached — rejection happens before the first Noise
            // byte, let alone the resolver seam.
            &FixedResolver {
                delegated_pub: vec![],
                generation: 0,
                not_after: 0,
            },
            u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 1,
                ingress_expiry: u64::MAX / 2,
            },
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
            u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 1,
                ingress_expiry: u64::MAX / 2,
            },
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
            u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 1,
                ingress_expiry: u64::MAX / 2,
            },
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
            // Never reached — the deadline is already expired before any
            // I/O, let alone the resolver seam.
            &FixedResolver {
                delegated_pub: vec![],
                generation: 0,
                not_after: 0,
            },
            u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 1,
                ingress_expiry: u64::MAX / 2,
            },
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
            // Never reached — the rekey mint fails before any I/O, let
            // alone the resolver seam.
            &FixedResolver {
                delegated_pub: vec![],
                generation: 0,
                not_after: 0,
            },
            u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 1,
                ingress_expiry: u64::MAX / 2,
            },
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
            u64::MAX / 2,
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

    /// Reads `deadline` itself and fails if already expired — proves the
    /// SAME token `pass_delegation_gate` receives genuinely reaches a
    /// real verifier's own check, not a fresh/independently-resettable
    /// one a real implementation could use to extend its own budget past
    /// what the ceremony allows (2026-08-04, @kiana, WIP audit, E3 seam).
    struct DeadlineAwareVerifier;
    impl DelegationSignatureVerifier for DeadlineAwareVerifier {
        fn verify_delegation(
            &self,
            _delegation: &MeshSessionDelegation,
            deadline: &CeremonyDeadline,
        ) -> Result<(), crate::error::DelegationError> {
            if deadline.is_expired() {
                return Err(crate::error::DelegationError::DeadlineExceeded);
            }
            Ok(())
        }
    }

    #[test]
    fn red_pass_delegation_gate_propagates_the_official_ceremony_deadline_to_the_verifier() {
        let delegation = delegation_for_key(
            &VerifyingKey::from(&SigningKey::random(&mut OsRng)),
            "hh-1",
            "someone-1",
            vec![0xCC; 32],
            0,
            u64::MAX / 2,
        );
        let expired = CeremonyDeadline::already_expired_for_test();
        let result = pass_delegation_gate(
            &delegation,
            &DelegationPolicy::test(u64::MAX / 2),
            &DeadlineAwareVerifier,
            &gate_ctx(),
            ExpectedChannel::Dev,
            &expired,
        );
        assert!(matches!(result, Err(AuthFrameError::DelegationGate)));
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
            &far_future_deadline(),
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
            &far_future_deadline(),
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
            &far_future_deadline(),
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
            &far_future_deadline(),
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
            &far_future_deadline(),
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
            &far_future_deadline(),
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
            &far_future_deadline(),
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
                    IngressEvidence {
                        observed_at: 1,
                        ingress_expiry: u64::MAX / 2,
                    },
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
                    // Never reached — the missing-role delegation is
                    // rejected by pass_delegation_gate, before the
                    // resolver seam.
                    &FixedResolver {
                        delegated_pub: vec![],
                        generation: 0,
                        not_after: 0,
                    },
                    u64::MAX / 2,
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
        let proof_i = auth_frames::sign_frame(proof_i, &k_mesh, &far_future_deadline()).unwrap();
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
            let proof_r =
                auth_frames::sign_frame(proof_r, &k_mesh, &far_future_deadline()).unwrap();
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
            IngressEvidence {
                observed_at: 2,
                ingress_expiry: u64::MAX / 2,
            },
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
            u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 1,
                ingress_expiry: u64::MAX / 2,
            },
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
            // Never reached — the local channel mismatch is rejected
            // before any I/O, let alone the resolver seam.
            &FixedResolver {
                delegated_pub: vec![],
                generation: 0,
                not_after: 0,
            },
            u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 1,
                ingress_expiry: u64::MAX / 2,
            },
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
            u64::MAX / 2,
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
                    IngressEvidence {
                        observed_at: 1,
                        ingress_expiry: u64::MAX / 2,
                    },
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
                    // Never reached — NoVerifierConfigured always fails
                    // pass_delegation_gate, before the resolver seam.
                    &FixedResolver {
                        delegated_pub: vec![],
                        generation: 0,
                        not_after: 0,
                    },
                    u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 2,
                ingress_expiry: u64::MAX / 2,
            },
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
            u64::MAX / 2,
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

    /// A D1 double that records whether `cancel_before_ack` ran and always
    /// reports a specific, injected [`crate::intent::D1CancelOutcome`] —
    /// used by the two integration REDs below to prove the outcome is
    /// actually threaded into the propagated error, not merely that SOME
    /// error came back (2026-08-04, @kiana, runtime-facade audit
    /// `3cbbfb37…` item 7c).
    struct RecordingD1 {
        cancel_called: std::sync::Arc<std::sync::atomic::AtomicBool>,
        outcome: crate::intent::D1CancelOutcome,
    }
    struct RecordingPending {
        cancel_called: std::sync::Arc<std::sync::atomic::AtomicBool>,
        outcome: crate::intent::D1CancelOutcome,
    }
    impl crate::intent::D1Pending<()> for RecordingPending {
        fn commit_after_ack(self) {}
        fn cancel_before_ack(self) -> crate::intent::D1CancelOutcome {
            self.cancel_called
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.outcome
        }
    }
    impl crate::intent::D1Admission for RecordingD1 {
        type Pending<'a> = RecordingPending;
        type Active<'a> = ();
        fn reserve_pending<'a>(
            &'a self,
            _key: &crate::intent::D1MembershipKey,
            _deadline: &CeremonyDeadline,
        ) -> Result<Self::Pending<'a>, crate::error::IntentError> {
            Ok(RecordingPending {
                cancel_called: std::sync::Arc::clone(&self.cancel_called),
                outcome: self.outcome,
            })
        }
    }

    /// Wraps a real `TcpStream`, letting the first `fail_from - 1` top-level
    /// `.write()` calls through untouched and failing every call from
    /// `fail_from` on. Small buffers over a healthy loopback socket
    /// complete in exactly one `.write()` syscall per
    /// `write_all_with_deadline` frame (the same assumption this crate's
    /// own wire-level tests already rely on), so `fail_from` reliably
    /// targets one specific top-level frame — here, the responder's third
    /// and final write, `ActivateAck`.
    struct FailWriteFromCall {
        inner: TcpStream,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        fail_from: usize,
    }
    impl Read for FailWriteFromCall {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }
    impl Write for FailWriteFromCall {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let call_number = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if call_number >= self.fail_from {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "test-injected write failure",
                ));
            }
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }
    impl wire::DeadlineBoundedIo for FailWriteFromCall {
        fn arm_io_deadline(&mut self, remaining: Duration) -> std::io::Result<()> {
            self.inner.arm_io_deadline(remaining)
        }
    }

    /// item 7c RED, responder side: the `ActivateAck` write itself fails
    /// (partial/broken-pipe) — `cancel_before_ack` must run and its
    /// specific `D1CancelOutcome` must be threaded into the propagated
    /// error (`AckExchangeFailedWithCancelOutcome`), never discarded via
    /// `let _ =`, and the session must never reach `Active`.
    #[test]
    fn red_responder_ack_write_failure_cancels_pending_and_surfaces_cancel_outcome() {
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
        let initiator_resolver = FixedResolver {
            delegated_pub: initiator_verifying
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            generation: 1,
            not_after: u64::MAX / 2,
        };

        let cancel_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d1 = RecordingD1 {
            cancel_called: std::sync::Arc::clone(&cancel_called),
            outcome: crate::intent::D1CancelOutcome::BarrierReleasedBookkeepingDeferred,
        };
        let write_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            let write_calls = std::sync::Arc::clone(&write_calls);
            move || {
                let (sock, _) = listener.accept().unwrap();
                let wrapped = FailWriteFromCall {
                    inner: sock,
                    calls: write_calls,
                    // Each logical frame is 2 raw `.write()` calls
                    // (length-prefix, then body — `write_length_prefixed_frame`).
                    // Noise handshake message 2 (calls 1-2), ProofR (3-4),
                    // FinalConfirm (5-6) succeed; ActivateAck's own
                    // length-prefix write (7) fails first, so zero
                    // ActivateAck bytes ever reach the peer.
                    fail_from: 7,
                };
                let ingress = PrevalidatedIngress::admit_at_accept(
                    wrapped,
                    IngressEvidence {
                        observed_at: 1,
                        ingress_expiry: u64::MAX / 2,
                    },
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
                    &d1,
                    &FixedClock(0),
                    &initiator_resolver,
                    u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 2,
                ingress_expiry: u64::MAX / 2,
            },
            far_future_budget(),
        );
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &initiator_identity,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0x83; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );
        // The initiator side will fail too (the Ack it's waiting for never
        // arrives, and the responder's socket closes when its thread
        // returns) — its own result isn't the point of this test.
        let _initiator_result = run_initiator_handshake(
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
            u64::MAX / 2,
            RekeyThreshold::new(3).unwrap(),
        );

        let responder_result = responder.join().unwrap();
        match responder_result {
            Err(AuthFrameError::AckExchangeFailedWithCancelOutcome { cancel_outcome, .. }) => {
                assert_eq!(
                    cancel_outcome,
                    crate::intent::D1CancelOutcome::BarrierReleasedBookkeepingDeferred
                );
            }
            Err(other) => panic!("expected AckExchangeFailedWithCancelOutcome, got {other:?}"),
            Ok(_) => panic!("expected the responder to fail, but it reached Active"),
        }
        assert!(
            cancel_called.load(std::sync::atomic::Ordering::SeqCst),
            "cancel_before_ack was never called on ActivateAck write failure"
        );
    }

    /// item 7c RED, initiator side: a COMPLETE but cryptographically
    /// INVALID `ActivateAck` (correct shape/digest, wrong signature) —
    /// `cancel_before_ack` must run and its outcome must be threaded into
    /// the propagated error, and the initiator must never reach `Active`.
    /// Hand-crafted-attacker pattern (bypasses `run_responder_handshake`,
    /// which would never produce an invalid signature) so this is a
    /// genuine defense-in-depth proof, not merely redundant with a
    /// well-behaved responder.
    #[test]
    fn red_initiator_invalid_activate_ack_cancels_pending_and_surfaces_cancel_outcome() {
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
        let expected_fp = vec![0xCCu8; 32];

        let cancel_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let d1 = RecordingD1 {
            cancel_called: std::sync::Arc::clone(&cancel_called),
            outcome: crate::intent::D1CancelOutcome::RegistryUnavailable,
        };

        // Fake responder thread: real Noise + real ProofR/FinalConfirm, but
        // the final ActivateAck is signed with a DIFFERENT key than the
        // one Proof-R/FinalConfirm used — a complete, well-shaped frame
        // that fails signature verification, not a truncated one.
        let responder_handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let handshake =
                noise::run_xx_handshake(&mut sock, Role::Responder, &far_future_deadline())
                    .unwrap();
            let mut transport = handshake.transport;
            let h_final = handshake.handshake_hash;
            let k_mesh = TestKMesh(responder_key);
            let checkpoint = fixed_checkpoint();

            let proof_r = ProofR::new(
                h_final.clone(),
                "hh-1".to_string(),
                "responder-1".to_string(),
                expected_fp.clone(),
                checkpoint.hash.clone(),
                checkpoint.sequence,
                checkpoint.event_head.clone(),
                checkpoint.not_after,
                responder_delegation.clone(),
                vec![0u8; 64],
            )
            .unwrap();
            let proof_r =
                auth_frames::sign_frame(proof_r, &k_mesh, &far_future_deadline()).unwrap();
            send_frame(
                &mut sock,
                &mut transport,
                &AuthFrame::ProofR(proof_r),
                &far_future_deadline(),
            )
            .unwrap();

            let _intent =
                recv_intent_record(&mut sock, &mut transport, &far_future_deadline()).unwrap();
            let proof_i =
                match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
                    AuthFrame::ProofI(f) => f,
                    _ => panic!("expected ProofI"),
                };

            let final_confirm = FinalConfirm::new(
                h_final.clone(),
                proof_i.self_m_id().to_string(),
                proof_i.self_cert_fingerprint().to_vec(),
                "responder-1".to_string(),
                vec![0u8; 64],
            )
            .unwrap();
            let final_confirm =
                auth_frames::sign_frame(final_confirm, &k_mesh, &far_future_deadline()).unwrap();
            send_frame(
                &mut sock,
                &mut transport,
                &AuthFrame::FinalConfirm(final_confirm.clone()),
                &far_future_deadline(),
            )
            .unwrap();

            let activate =
                match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
                    AuthFrame::Activate(f) => f,
                    _ => panic!("expected Activate"),
                };
            let activate_digest = auth_frames::frame_digest(&activate).unwrap();

            // Complete, well-shaped ActivateAck — but signed with a
            // DIFFERENT key than proof_r/final_confirm, so it fails
            // signature verification despite arriving intact.
            let wrong_k_mesh = TestKMesh(SigningKey::random(&mut OsRng));
            let activate_ack = ActivateAck::new(
                h_final.clone(),
                "responder-1".to_string(),
                activate_digest.to_vec(),
                vec![0u8; 64],
            )
            .unwrap();
            let activate_ack =
                auth_frames::sign_frame(activate_ack, &wrong_k_mesh, &far_future_deadline())
                    .unwrap();
            send_frame(
                &mut sock,
                &mut transport,
                &AuthFrame::ActivateAck(activate_ack),
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
            IngressEvidence {
                observed_at: 2,
                ingress_expiry: u64::MAX / 2,
            },
            far_future_budget(),
        );
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &initiator_identity,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0x87; 32],
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
            &d1,
            &FixedClock(0),
            u64::MAX / 2,
            RekeyThreshold::new(3).unwrap(),
        );
        responder_handle.join().unwrap();

        match initiator_result {
            Err(AuthFrameError::AckExchangeFailedWithCancelOutcome { cancel_outcome, .. }) => {
                assert_eq!(
                    cancel_outcome,
                    crate::intent::D1CancelOutcome::RegistryUnavailable
                );
            }
            Err(other) => panic!("expected AckExchangeFailedWithCancelOutcome, got {other:?}"),
            Ok(_) => panic!("expected the initiator to fail, but it reached Active"),
        }
        assert!(
            cancel_called.load(std::sync::atomic::Ordering::SeqCst),
            "cancel_before_ack was never called on an invalid ActivateAck"
        );
    }

    /// A `IntentNonceLedger` double whose `consume` blocks on a 2-party
    /// `Barrier` as its very first action, before touching the shared
    /// `HashSet` — forces two genuinely concurrent real ceremonies to
    /// both arrive at the check-and-set before either one's `insert` can
    /// run, so this is a forced interleaving, not scheduling luck
    /// (2026-08-04, @kiana, runtime-facade audit `3cbbfb37…`, CFX-1 on
    /// `018aed57`).
    struct SyncedSharedLedger {
        consumed: std::sync::Mutex<std::collections::HashSet<crate::intent::IntentNonceKey>>,
        barrier: std::sync::Barrier,
    }
    impl crate::intent::IntentNonceLedger for SyncedSharedLedger {
        fn consume(
            &self,
            key: &crate::intent::IntentNonceKey,
            _not_after: u64,
            _digest: &[u8; 32],
            _channel: ExpectedChannel,
            _deadline: &CeremonyDeadline,
        ) -> Result<crate::intent::NonceConsumeOutcome, crate::error::IntentError> {
            self.barrier.wait();
            let mut set = self.consumed.lock().unwrap();
            if !set.insert(key.clone()) {
                return Ok(crate::intent::NonceConsumeOutcome::AlreadyConsumed);
            }
            Ok(crate::intent::NonceConsumeOutcome::Committed)
        }
    }

    /// A D1 double that counts `reserve_pending` calls via a shared
    /// counter and always succeeds — used to prove the LOSING ceremony
    /// never reserves at all (nonce consume runs strictly before D1
    /// reservation in both handshake functions, so a nonce rejection
    /// structurally prevents `reserve_pending` from ever being called for
    /// that attempt; this double makes that observable instead of merely
    /// inferred from reading the source).
    struct CountingD1 {
        reserve_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    struct CountingPending;
    impl crate::intent::D1Pending<()> for CountingPending {
        fn commit_after_ack(self) {}
        fn cancel_before_ack(self) -> crate::intent::D1CancelOutcome {
            crate::intent::D1CancelOutcome::CancelledAndRemoved
        }
    }
    impl crate::intent::D1Admission for CountingD1 {
        type Pending<'a> = CountingPending;
        type Active<'a> = ();
        fn reserve_pending<'a>(
            &'a self,
            _key: &crate::intent::D1MembershipKey,
            _deadline: &CeremonyDeadline,
        ) -> Result<Self::Pending<'a>, crate::error::IntentError> {
            self.reserve_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(CountingPending)
        }
    }

    /// item 7d RED, entrypoint-level closure (2026-08-04, @kiana,
    /// runtime-facade audit `3cbbfb37…`, CFX-1 on `018aed57` — the
    /// unit-level `intent::tests::two_concurrent_attempts_at_the_same_nonce_yield_exactly_one_winner`
    /// alone did not close item 7d; this does). TWO real, independent
    /// Noise handshakes/responder ceremonies, driven by hand-crafted
    /// initiator threads that both replay the IDENTICAL signed 0x06
    /// intent (same nonce — this genuinely IS a nonce-replay attack, the
    /// exact scenario the ledger exists to stop), racing the SAME
    /// `SyncedSharedLedger` and counted by the SAME `CountingD1`.
    ///
    /// A byte-for-byte `ProofI` cannot be replayed across the two
    /// connections — its signature covers `h_final`, which is unique per
    /// Noise handshake — so each attacker thread signs its OWN fresh
    /// `ProofI` bound to its own connection's real `h_final`, but both
    /// reference the SAME `connection_intent_digest` (computed from the
    /// SAME replayed intent bytes), exactly as a real replay would need
    /// to.
    #[test]
    fn red_two_real_responder_ceremonies_racing_the_same_nonce_exactly_one_reaches_active() {
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

        let initiator_key = SigningKey::random(&mut OsRng);
        let initiator_verifying = VerifyingKey::from(&initiator_key);
        let initiator_delegation = delegation_for_key(
            &initiator_verifying,
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            0,
            u64::MAX / 2,
        );
        let initiator_identity = identity(
            "hh-1",
            "initiator-1",
            vec![0xEE; 32],
            initiator_delegation.clone(),
        );
        let initiator_resolver = FixedResolver {
            delegated_pub: initiator_verifying
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            generation: 1,
            not_after: u64::MAX / 2,
        };
        let k_mesh = TestKMesh(initiator_key);

        // The SAME nonce, replayed on both connections.
        let pending_intent = pending_intent_for(
            &k_mesh,
            &initiator_identity,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0xA5; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );
        let shared_intent = pending_intent.intent().clone();
        let connection_intent_digest = ConnectionIntentDigest::from_bytes(
            crate::intent::intent_digest(&shared_intent).unwrap(),
        );

        let ledger = std::sync::Arc::new(SyncedSharedLedger {
            consumed: std::sync::Mutex::new(std::collections::HashSet::new()),
            barrier: std::sync::Barrier::new(2),
        });
        let reserve_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Attacker threads spawn FIRST: `TcpStream::connect` completes once
        // the OS-level listen backlog accepts the SYN, independent of when
        // this process calls `listener.accept()` — spawning them before
        // the two `accept()` calls below avoids a connect-before-listener-
        // is-ready deadlock without needing a separate acceptor thread.
        let attacker_threads: Vec<_> = (0..2)
            .map(|_| {
                let shared_intent = shared_intent.clone();
                let connection_intent_digest = connection_intent_digest.clone();
                let initiator_identity_hh_id = initiator_identity.hh_id.clone();
                let initiator_identity_m_id = initiator_identity.m_id.clone();
                let initiator_cert_fingerprint = initiator_identity.cert_fingerprint.clone();
                let initiator_delegation = initiator_delegation.clone();
                let k_mesh = TestKMesh(k_mesh.0.clone());
                thread::spawn(move || {
                    let mut sock = TcpStream::connect(addr).unwrap();
                    let handshake =
                        noise::run_xx_handshake(&mut sock, Role::Initiator, &far_future_deadline())
                            .unwrap();
                    let mut transport = handshake.transport;
                    let h_final = handshake.handshake_hash;
                    match recv_frame(&mut sock, &mut transport, &far_future_deadline()).unwrap() {
                        AuthFrame::ProofR(_) => {}
                        _ => panic!("expected ProofR"),
                    }
                    send_intent_record(
                        &mut sock,
                        &mut transport,
                        &shared_intent,
                        &far_future_deadline(),
                    )
                    .unwrap();
                    let checkpoint = fixed_checkpoint();
                    let proof_i = ProofI::new(
                        h_final.clone(),
                        initiator_identity_hh_id,
                        initiator_identity_m_id,
                        "responder-1".to_string(),
                        initiator_cert_fingerprint,
                        vec![0xCC; 32],
                        checkpoint.hash.clone(),
                        checkpoint.sequence,
                        checkpoint.event_head.clone(),
                        checkpoint.not_after,
                        initiator_delegation,
                        connection_intent_digest,
                        vec![0u8; 64],
                    )
                    .unwrap();
                    let proof_i =
                        auth_frames::sign_frame(proof_i, &k_mesh, &far_future_deadline()).unwrap();
                    send_frame(
                        &mut sock,
                        &mut transport,
                        &AuthFrame::ProofI(proof_i),
                        &far_future_deadline(),
                    )
                    .unwrap();
                    // Only the nonce winner ever receives a real FinalConfirm
                    // — the loser's responder returns Err(NonceAlreadyConsumed)
                    // and closes its socket without sending anything more.
                    // Both attacker threads are prepared to complete the full
                    // flight regardless, since neither knows in advance which
                    // one will win.
                    let final_confirm =
                        match recv_frame(&mut sock, &mut transport, &far_future_deadline()) {
                            Ok(AuthFrame::FinalConfirm(f)) => f,
                            _ => return, // lost the race — connection closed/errored
                        };
                    let final_confirm_digest = auth_frames::frame_digest(&final_confirm).unwrap();
                    let activate = Activate::new(
                        h_final.clone(),
                        "responder-1".to_string(),
                        final_confirm_digest.to_vec(),
                        vec![0u8; 64],
                    )
                    .unwrap();
                    let activate =
                        auth_frames::sign_frame(activate, &k_mesh, &far_future_deadline()).unwrap();
                    send_frame(
                        &mut sock,
                        &mut transport,
                        &AuthFrame::Activate(activate),
                        &far_future_deadline(),
                    )
                    .unwrap();
                    let _ = recv_frame(&mut sock, &mut transport, &far_future_deadline());
                })
            })
            .collect();

        // Accept both connections and spawn a real responder ceremony for
        // each, sharing the same ledger/D1 counter.
        let responder_threads: Vec<_> = (0..2)
            .map(|_| {
                let (sock, _) = listener.accept().unwrap();
                let checkpoint = fixed_checkpoint();
                let k_mesh = TestKMesh(responder_key.clone());
                let responder_identity = identity(
                    "hh-1",
                    "responder-1",
                    vec![0xCC; 32],
                    responder_delegation.clone(),
                );
                let ledger = std::sync::Arc::clone(&ledger);
                let d1 = CountingD1 {
                    reserve_count: std::sync::Arc::clone(&reserve_count),
                };
                let initiator_resolver = FixedResolver {
                    delegated_pub: initiator_resolver.delegated_pub.clone(),
                    generation: initiator_resolver.generation,
                    not_after: initiator_resolver.not_after,
                };
                thread::spawn(move || {
                    let ingress = PrevalidatedIngress::admit_at_accept(
                        sock,
                        IngressEvidence {
                            observed_at: 1,
                            ingress_expiry: u64::MAX / 2,
                        },
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
                        ledger.as_ref(),
                        &d1,
                        &FixedClock(0),
                        &initiator_resolver,
                        u64::MAX / 2,
                        RekeyThreshold::new(3).unwrap(),
                    )
                })
            })
            .collect();

        for h in attacker_threads {
            let _ = h.join();
        }
        let responder_results: Vec<_> = responder_threads
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        let active_count = responder_results.iter().filter(|r| r.is_ok()).count();
        let already_consumed_count = responder_results
            .iter()
            .filter(|r| {
                matches!(
                    r,
                    Err(AuthFrameError::Intent(
                        crate::error::IntentError::NonceAlreadyConsumed
                    ))
                )
            })
            .count();

        assert_eq!(
            active_count, 1,
            "expected exactly one responder ceremony to reach Active"
        );
        assert_eq!(
            already_consumed_count, 1,
            "expected exactly one responder ceremony to be rejected with NonceAlreadyConsumed"
        );
        assert_eq!(
            reserve_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "D1::reserve_pending must have been called exactly once — the losing \
             ceremony's nonce rejection must happen strictly before D1 reservation, \
             so it must never reserve at all"
        );
    }

    // ---- post-Active wire addendum (b14fcf95…/erratum1 4be4cd3d…) tests ----

    /// A `D1::Active<'a>` gate double whose authorization can be flipped
    /// externally by the test, shared via `Arc` so both the session and
    /// the test hold a handle to the SAME underlying flag.
    struct TestGate {
        authorized: std::sync::atomic::AtomicBool,
    }
    impl TestGate {
        fn new() -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                authorized: std::sync::atomic::AtomicBool::new(true),
            })
        }
        fn revoke(&self) {
            self.authorized
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl ActiveGateAuthorization for std::sync::Arc<TestGate> {
        type Guard<'a> = ();
        fn try_authorize(&self) -> Option<()> {
            if self.authorized.load(std::sync::atomic::Ordering::SeqCst) {
                Some(())
            } else {
                None
            }
        }
    }

    struct GatedD1 {
        gate: std::sync::Arc<TestGate>,
    }
    struct GatedPending {
        gate: std::sync::Arc<TestGate>,
    }
    impl crate::intent::D1Pending<std::sync::Arc<TestGate>> for GatedPending {
        fn commit_after_ack(self) -> std::sync::Arc<TestGate> {
            self.gate
        }
        fn cancel_before_ack(self) -> crate::intent::D1CancelOutcome {
            crate::intent::D1CancelOutcome::CancelledAndRemoved
        }
    }
    impl crate::intent::D1Admission for GatedD1 {
        type Pending<'a> = GatedPending;
        type Active<'a> = std::sync::Arc<TestGate>;
        fn reserve_pending<'a>(
            &'a self,
            _key: &crate::intent::D1MembershipKey,
            _deadline: &CeremonyDeadline,
        ) -> Result<Self::Pending<'a>, crate::error::IntentError> {
            Ok(GatedPending {
                gate: std::sync::Arc::clone(&self.gate),
            })
        }
    }

    type GatedSession = ActiveMeshSession<TcpStream, std::sync::Arc<TestGate>>;

    /// Same shape as `full_handshake()`, but with a `GatedD1` double whose
    /// gate the test can flip after the ceremony completes — needed for
    /// every post-Active RED that depends on live D1 authorization, which
    /// `AlwaysAdmitD1`'s `()` gate cannot express at all.
    fn full_handshake_with_gate() -> (
        GatedSession,
        GatedSession,
        std::sync::Arc<TestGate>,
        std::sync::Arc<TestGate>,
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

        let initiator_resolver = FixedResolver {
            delegated_pub: initiator_verifying
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            generation: 1,
            not_after: u64::MAX / 2,
        };
        let responder_gate = TestGate::new();
        let initiator_gate = TestGate::new();

        let responder = thread::spawn({
            let checkpoint = fixed_checkpoint();
            let k_mesh = TestKMesh(responder_key);
            let d1 = GatedD1 {
                gate: std::sync::Arc::clone(&responder_gate),
            };
            move || {
                let (sock, _) = listener.accept().unwrap();
                let ingress = PrevalidatedIngress::admit_at_accept(
                    sock,
                    IngressEvidence {
                        observed_at: 1,
                        ingress_expiry: u64::MAX / 2,
                    },
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
                    &d1,
                    &FixedClock(0),
                    &initiator_resolver,
                    u64::MAX / 2,
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
            IngressEvidence {
                observed_at: 2,
                ingress_expiry: u64::MAX / 2,
            },
            far_future_budget(),
        );
        let k_mesh = TestKMesh(initiator_key);
        let pending_intent = pending_intent_for(
            &k_mesh,
            &initiator_identity,
            &fixed_checkpoint(),
            "responder-1",
            vec![0xCC; 32],
            [0xB7; 32],
            u64::MAX / 2,
            ExpectedChannel::Dev,
        );
        let initiator_d1 = GatedD1 {
            gate: std::sync::Arc::clone(&initiator_gate),
        };
        let initiator_session = run_initiator_handshake(
            ingress,
            pending_intent,
            &initiator_identity,
            &fixed_checkpoint(),
            ExpectedChannel::Dev,
            &DelegationPolicy::test(u64::MAX / 2),
            &AlwaysAcceptDelegation,
            &k_mesh,
            &initiator_d1,
            &FixedClock(0),
            u64::MAX / 2,
            RekeyThreshold::new(3).unwrap(),
        )
        .unwrap();

        let responder_session = responder.join().unwrap();
        (
            initiator_session,
            responder_session,
            initiator_gate,
            responder_gate,
        )
    }

    const FAR_FUTURE_NOW: u64 = 0;
    const OP_BUDGET: Duration = Duration::from_secs(5);

    /// POS-5-equivalent, addendum §8 item 5: N=3, `DATA, DATA, marker,
    /// DATA, DATA` in EACH direction, real Snow transport, real socket —
    /// proves `send_data` auto-emits the required marker and
    /// `receive_data` transparently consumes it, end to end, in both
    /// directions independently.
    #[test]
    fn post_active_n3_data_data_marker_data_data_each_direction_real_snow() {
        let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
        let mut buf = [0u8; 64];

        for i in 0..4u8 {
            let payload = [i; 4];
            initiator
                .send_data(&payload, OP_BUDGET, FAR_FUTURE_NOW)
                .unwrap();
            let n = responder
                .receive_data(&mut buf, OP_BUDGET, FAR_FUTURE_NOW)
                .unwrap();
            assert_eq!(&buf[..n], &payload);
        }
        assert_eq!(initiator.rekey.tx().generation(), 1);
        assert_eq!(responder.rekey.rx().generation(), 1);

        for i in 0..4u8 {
            let payload = [0x80 + i; 4];
            responder
                .send_data(&payload, OP_BUDGET, FAR_FUTURE_NOW)
                .unwrap();
            let n = initiator
                .receive_data(&mut buf, OP_BUDGET, FAR_FUTURE_NOW)
                .unwrap();
            assert_eq!(&buf[..n], &payload);
        }
        assert_eq!(responder.rekey.tx().generation(), 1);
        assert_eq!(initiator.rekey.rx().generation(), 1);

        assert!(!initiator.is_closed());
        assert!(!responder.is_closed());
    }

    /// addendum §5/§8 item 7: a D1 gate rejection on `send_data` closes
    /// the session — no bytes are ever written for that attempt.
    #[test]
    fn red_send_data_rejected_when_gate_denies_and_closes_session() {
        let (mut initiator, _responder, initiator_gate, _rg) = full_handshake_with_gate();
        initiator_gate.revoke();
        let err = initiator
            .send_data(b"hello", OP_BUDGET, FAR_FUTURE_NOW)
            .unwrap_err();
        assert!(matches!(err, PostActiveError::NotAuthorized));
        assert!(initiator.is_closed());
        // Idempotent: a second call fails closed without touching the gate again.
        let err2 = initiator
            .send_data(b"hello", OP_BUDGET, FAR_FUTURE_NOW)
            .unwrap_err();
        assert!(matches!(err2, PostActiveError::Closed));
    }

    /// addendum §5/§8 item 9: `now >= expires_at` closes `send_data`
    /// (equality is already-expired, half-open, same convention as the
    /// handshake's own `check_effective_expiry`).
    #[test]
    fn red_send_data_expired_at_equality_closes_session() {
        let (mut initiator, _responder, _ig, _rg) = full_handshake_with_gate();
        let expires_at = initiator.expires_at();
        let err = initiator
            .send_data(b"hello", OP_BUDGET, expires_at)
            .unwrap_err();
        assert!(matches!(err, PostActiveError::Expired));
        assert!(initiator.is_closed());
    }

    /// addendum §8 item 9, positive half: `now == expires_at - 1` still
    /// delivers — proves the boundary is exclusive on the expired side
    /// only, not off-by-one in the other direction.
    #[test]
    fn expiry_minus_one_still_delivers() {
        let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
        let expires_at = initiator.expires_at();
        initiator
            .send_data(b"hi", OP_BUDGET, expires_at - 1)
            .unwrap();
        let mut buf = [0u8; 8];
        let n = responder
            .receive_data(&mut buf, OP_BUDGET, expires_at - 1)
            .unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert!(!initiator.is_closed());
        assert!(!responder.is_closed());
    }

    #[test]
    fn close_gracefully_is_idempotent() {
        let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
        initiator.close_gracefully(OP_BUDGET).unwrap();
        assert!(initiator.is_closed());
        initiator.close_gracefully(OP_BUDGET).unwrap(); // no-op, does not error or reopen
        assert!(initiator.is_closed());

        let mut buf = [0u8; 8];
        let err = responder
            .receive_data(&mut buf, OP_BUDGET, FAR_FUTURE_NOW)
            .unwrap_err();
        assert!(matches!(err, PostActiveError::PeerClosed));
        assert!(responder.is_closed());
    }

    #[test]
    fn red_receive_data_after_local_close_fails_without_touching_stream() {
        let (mut initiator, _responder, _ig, _rg) = full_handshake_with_gate();
        initiator.close_gracefully(OP_BUDGET).unwrap();
        let mut buf = [0u8; 8];
        let err = initiator
            .receive_data(&mut buf, OP_BUDGET, FAR_FUTURE_NOW)
            .unwrap_err();
        assert!(matches!(err, PostActiveError::Closed));
    }

    #[test]
    fn notify_revoked_and_close_delivers_peer_revoked() {
        let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
        initiator.notify_revoked_and_close(OP_BUDGET).unwrap();
        assert!(initiator.is_closed());

        let mut buf = [0u8; 8];
        let err = responder
            .receive_data(&mut buf, OP_BUDGET, FAR_FUTURE_NOW)
            .unwrap_err();
        assert!(matches!(err, PostActiveError::PeerRevoked));
        assert!(responder.is_closed());
    }

    /// addendum §5: "Se ... o buffer é pequeno, nenhum byte é copiado;
    /// descartar e fechar" — a too-small receive buffer closes the
    /// session and leaves the buffer untouched.
    #[test]
    fn red_receive_data_buffer_too_small_closes_and_copies_nothing() {
        let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
        initiator
            .send_data(b"0123456789", OP_BUDGET, FAR_FUTURE_NOW)
            .unwrap();
        let mut tiny = [0xAAu8; 4];
        let err = responder
            .receive_data(&mut tiny, OP_BUDGET, FAR_FUTURE_NOW)
            .unwrap_err();
        assert!(matches!(
            err,
            PostActiveError::ReceiveBufferTooSmall {
                buffer_len: 4,
                payload_len: 10
            }
        ));
        assert!(responder.is_closed());
        assert_eq!(tiny, [0xAAu8; 4], "buffer must be untouched on rejection");
    }

    /// addendum §6/§8 item 6: a non-marker record arriving when the
    /// sender's own policy_count already reached `threshold - 1` (i.e. a
    /// marker was required and never sent) is rejected by the receiver's
    /// own rekey bookkeeping — hand-crafted attacker path, bypassing
    /// `send_data`'s auto-marker-emission, to prove the RECEIVER's own
    /// check is real, not merely never exercised because the well-behaved
    /// sender never triggers it.
    #[test]
    fn red_non_marker_at_threshold_minus_one_without_marker_rejected_by_receiver() {
        let (mut initiator, mut responder, _ig, _rg) = full_handshake_with_gate();
        // Drive N-1 = 2 ordinary DATA records the normal way first.
        for i in 0..2u8 {
            initiator
                .send_data(&[i], OP_BUDGET, FAR_FUTURE_NOW)
                .unwrap();
            let mut buf = [0u8; 8];
            responder
                .receive_data(&mut buf, OP_BUDGET, FAR_FUTURE_NOW)
                .unwrap();
        }
        // Now policy_count == threshold-1 == 2 on both sides. Hand-craft
        // a THIRD DATA record directly onto the wire, bypassing
        // send_data's auto-marker-emission entirely.
        let record = post_active::encode_data_record(b"late").unwrap();
        let mut ciphertext = vec![0u8; record.len() + 16];
        let ct_len = initiator
            .transport
            .write_message(&record, &mut ciphertext)
            .unwrap();
        wire::write_transport_record(
            &mut initiator.stream,
            &ciphertext[..ct_len],
            &OperationDeadline::new(OP_BUDGET).unwrap(),
        )
        .unwrap();

        let mut buf = [0u8; 8];
        let err = responder
            .receive_data(&mut buf, OP_BUDGET, FAR_FUTURE_NOW)
            .unwrap_err();
        assert!(matches!(
            err,
            PostActiveError::Rekey(crate::error::RekeyError::ExpectedRekeyMarker)
        ));
        assert!(responder.is_closed());
    }
}
