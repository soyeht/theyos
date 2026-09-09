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
    /// point-in-time check during the handshake. **This check now exists**
    /// (2026-08-04, post-Active wire addendum `b14fcf95…` §5, hardened
    /// against @khai audit `d7e45e10…`'s BLOCKER): [`ActiveMeshSession::send_data`]/
    /// [`ActiveMeshSession::receive_data`] both compare this field against
    /// a freshly re-sampled [`crate::intent::Clock`] reading — taken after
    /// the D1 guard is acquired, immediately before the write/copy, never
    /// a caller-supplied scalar — before any DATA syscall. `pub(crate)`
    /// accessor only: still no external, DATA-capable caller exists to
    /// read it directly. May already be in the past by the time this
    /// field is read at handshake completion — see `run_responder_handshake`'s/
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
    /// `#[cfg(test)]`-only synchronization seam (2026-08-04, post-Active
    /// wire addendum §8 item 8). Lets a test force a deterministic pause
    /// strictly CPU-local, inside the D1-guarded copy in
    /// `receive_data_inner`'s `Data` arm — AFTER the guard is acquired,
    /// AFTER the buffer-size check, immediately BEFORE `copy_from_slice`
    /// — so a concurrent `revoke_and_wait_for_drain`-style call can be
    /// proven to block until this guard actually drops. This field and
    /// its call site do not exist in a production build at all (`cfg`
    /// strips them entirely, not merely guards them at runtime); the
    /// production `receive_data`/`send_data` signatures never accept a
    /// callback, sink, or closure of any kind — see
    /// `red_receive_data_and_send_data_signatures_have_no_callback_parameter`
    /// for a dedicated structural proof of that claim.
    #[cfg(test)]
    receive_before_copy_hook: Option<Box<dyn FnMut() + Send>>,
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
    /// see the field's own doc: [`ActiveMeshSession::send_data`]/
    /// [`ActiveMeshSession::receive_data`] consult this against a freshly
    /// re-sampled [`crate::intent::Clock`] reading. Not `pub`: no
    /// external caller exists yet outside this crate.
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

    /// `#[cfg(test)]`-only — see [`Self`]'s `receive_before_copy_hook`
    /// field doc. Not reachable from any production build.
    #[cfg(test)]
    pub(crate) fn set_receive_before_copy_hook<F: FnMut() + Send + 'static>(&mut self, hook: F) {
        self.receive_before_copy_hook = Some(Box::new(hook));
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
    ///
    /// **`clock` is re-sampled, never a caller scalar (2026-08-04, @khai
    /// audit `d7e45e10…`, BLOCKER):** an earlier revision of this method
    /// took `now: u64` — a value the caller necessarily sampled *before*
    /// this call, including before the marker's own blocking write when
    /// one is due. That let the expiry decision use a reading taken before
    /// a real network write, exactly the staleness addendum §5's
    /// "reamostrar" (re-sample) wording forbids. `clock.now()` is now
    /// called fresh, *after* the marker (if any) and *after* the guard is
    /// acquired, immediately before the write — matching `Clock`'s own
    /// contract of "never cached, called again at each checkpoint"
    /// (`intent.rs`).
    pub fn send_data<C: crate::intent::Clock>(
        &mut self,
        payload: &[u8],
        budget: Duration,
        clock: &C,
    ) -> Result<(), PostActiveError> {
        if self.closed {
            return Err(PostActiveError::Closed);
        }
        let result = self.send_data_inner(payload, budget, clock);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn send_data_inner<C: crate::intent::Clock>(
        &mut self,
        payload: &[u8],
        budget: Duration,
        clock: &C,
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
        let now = clock.now()?;
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
    ///
    /// **`clock` is re-sampled, never a caller scalar** — see
    /// [`Self::send_data`]'s doc for the full rationale (@khai audit
    /// `d7e45e10…`). Here the fresh `clock.now()` call happens *after* the
    /// blocking read/decrypt and *after* the guard is acquired, immediately
    /// before the copy into `buffer` — never before either.
    pub fn receive_data<C: crate::intent::Clock>(
        &mut self,
        buffer: &mut [u8],
        budget: Duration,
        clock: &C,
    ) -> Result<usize, PostActiveError> {
        if self.closed {
            return Err(PostActiveError::Closed);
        }
        let result = self.receive_data_inner(buffer, budget, clock);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn receive_data_inner<C: crate::intent::Clock>(
        &mut self,
        buffer: &mut [u8],
        budget: Duration,
        clock: &C,
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
                    let now = clock.now()?;
                    if now >= self.expires_at {
                        return Err(PostActiveError::Expired);
                    }
                    if payload.len() > buffer.len() {
                        return Err(PostActiveError::ReceiveBufferTooSmall {
                            buffer_len: buffer.len(),
                            payload_len: payload.len(),
                        });
                    }
                    #[cfg(test)]
                    if let Some(hook) = self.receive_before_copy_hook.as_mut() {
                        hook();
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
        #[cfg(test)]
        receive_before_copy_hook: None,
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
        #[cfg(test)]
        receive_before_copy_hook: None,
    })
}

#[cfg(test)]
mod tests;
