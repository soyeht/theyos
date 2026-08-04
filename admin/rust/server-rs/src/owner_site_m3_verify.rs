//! S2 M3 verification core (increment 3a-5): the server-side check of the
//! A2 `ClientProof`, computing every transcript from the SERVER'S OWN
//! session state — never from the wire.
//!
//! ## The criterion that closes S2
//!
//! `t1` and `device_static` are the chain's legitimate END: values of the
//! Noise layer itself (the transport transcript and the peer's static key
//! learned by the handshake). They enter here ONLY as
//! [`M3SessionTranscript`], which the caller builds from the live Noise
//! session state (`self.t1`, `handshake.get_remote_static()`) — never from
//! the M3 message. The closing RED injects valid-in-form but DIFFERENT
//! `t1`/`device_static` than the live session's and requires refusal: if
//! the attacker could choose the origin, everything downstream would derive
//! "correctly" from it, and 3a-1..3a-4 would be worth nothing.
//!
//! The binding's keys come from exact roster resolution
//! ([`OwnerSiteResolvedBinding`]); the signatures are verified against the
//! hashes computed HERE, with the same shared functions the peer uses.

use crate::owner_site_a2_wire::{ClientHelloCore, ServerHello};
use crate::owner_site_authority::{OwnerSiteAuthorityError, OwnerSiteResolvedBinding};
use crate::owner_site_binding_glue::ChannelBindingPre;

/// The server-held session transcript values — the chain's legitimate end.
/// Built by the caller from the live Noise session, never from wire bytes.
///
/// Fields are PRIVATE so `from_noise_session` is the only way in: the audit
/// of "did these come from the live handshake?" collapses to the single
/// call site that builds this value — and that call site must read them
/// from the live handshake object in the same function, never from a
/// parsed intermediate.
pub(crate) struct M3SessionTranscript {
    /// The server-computed Noise transcript hash (T1).
    t1: [u8; 32],
    /// The peer's static key as learned by the handshake
    /// (`handshake.get_remote_static()`), never as sent in any message.
    device_static: [u8; 32],
}

impl M3SessionTranscript {
    #[allow(dead_code)] // constructed by the M3 server session (3a-5 wiring)
    pub(crate) fn from_noise_session(t1: [u8; 32], device_static: [u8; 32]) -> Self {
        Self { t1, device_static }
    }

    fn binding_pre(&self) -> Result<ChannelBindingPre, OwnerSiteAuthorityError> {
        crate::owner_site_binding_glue::pop_binding_pre(self.t1, self.device_static)
    }
}

/// Verify the A2 `ClientProof` against the exact resolved binding, with
/// every transcript value computed from the SERVER's session state.
///
/// Two proofs must hold: the device-auth signature over the device-auth
/// hash, and the action-PoP signature over the owner-action hash. Any
/// mismatch fails closed — the caller drops the session; nothing the proof
/// would have authorized survives.
///
/// # Errors
/// [`OwnerSiteAuthorityError::ChannelProofMismatch`] on any signature or
/// transcript mismatch; [`OwnerSiteAuthorityError::CborEncode`] if a
/// transcript preimage cannot be encoded.
#[allow(dead_code)] // wired by the M3 server session (3a-5 wiring)
pub(crate) fn verify_client_proof(
    session: &M3SessionTranscript,
    m2: &ServerHello,
    c1_core: &ClientHelloCore,
    resolved: &OwnerSiteResolvedBinding,
    device_signature: &[u8],
    action_pop: &[u8],
    intent_wire: &[u8],
) -> Result<(), OwnerSiteAuthorityError> {
    let binding_pre = session.binding_pre()?;

    let d_auth = crate::owner_site_binding_glue::device_auth_hash(
        &binding_pre,
        &resolved.binding_id(),
        &resolved.binding_digest(),
        resolved.participant_npub(),
        resolved.channel_auth_key().key_id(),
    )?;
    let device_sig = household_rs::P256Signature::from_bytes(device_signature)
        .map_err(|_| OwnerSiteAuthorityError::ChannelProofMismatch)?;
    household_rs::keys::verify_signature(
        resolved.channel_auth_key().verifying_key(),
        d_auth.as_bytes(),
        &device_sig,
    )
    .map_err(|_| OwnerSiteAuthorityError::ChannelProofMismatch)?;

    let action = crate::owner_site_binding_glue::owner_action_hash(
        &binding_pre,
        m2,
        c1_core,
        &resolved.binding_id(),
        &resolved.binding_digest(),
        resolved.participant_npub(),
        intent_wire,
    )?;
    let action_sig = household_rs::P256Signature::from_bytes(action_pop)
        .map_err(|_| OwnerSiteAuthorityError::ChannelProofMismatch)?;
    household_rs::keys::verify_signature(
        resolved.action_pop_key().verifying_key(),
        action.as_bytes(),
        &action_sig,
    )
    .map_err(|_| OwnerSiteAuthorityError::ChannelProofMismatch)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner_site_a2_wire::CanonicalIntent;
    use crate::owner_site_authority::{
        OwnerSiteActionPopKey, OwnerSiteBindingDigest, OwnerSiteBindingId, OwnerSiteChannelAuthKey,
    };
    use household_rs::keys::{IdentityKey, P256Keypair};

    const T1: [u8; 32] = [0xA1; 32];
    const STATIC: [u8; 32] = [0xC3; 32];

    struct Fx {
        session: M3SessionTranscript,
        m2: ServerHello,
        c1: ClientHelloCore,
        resolved: OwnerSiteResolvedBinding,
        channel_signer: P256Keypair,
        action_signer: P256Keypair,
        intent_wire: Vec<u8>,
    }

    fn fixture() -> Fx {
        let channel_signer = P256Keypair::generate();
        let action_signer = P256Keypair::generate();
        let resolved = OwnerSiteResolvedBinding::injected_for_harness(
            OwnerSiteBindingId::injected_for_harness([0x01; 32]).unwrap(),
            OwnerSiteBindingDigest::injected_for_harness([0x51; 32]).unwrap(),
            "npub1a",
            OwnerSiteChannelAuthKey::injected_for_harness("ch-a", channel_signer.public()).unwrap(),
            OwnerSiteActionPopKey::injected_for_harness("pop-a", action_signer.public()).unwrap(),
        )
        .unwrap();
        let m2 = ServerHello {
            engine_machine_certificate: vec![0x11; 64],
            engine_key_id: "engine-key".into(),
            channel_id: vec![0x22; 32],
            channel_epoch: 1,
            challenge_id: vec![0x33; 32],
            challenge_secret: vec![0x44; 32],
            authz_epoch: 1,
            roster_digest: vec![0x55; 32],
            fresh_until: 1_060,
            engine_signature: vec![0x66; 64],
        };
        let c1 = ClientHelloCore {
            domain: "soyeht/owner-site/a2/v1".into(),
            version: 1,
            household_id: "hh-a".into(),
            network_id: "net-a".into(),
            route: "/api/v1/household/claws/claw-a/owner-site".into(),
            resource: "claw-a".into(),
            intent: CanonicalIntent {
                method: "GET".into(),
                target: "/api/v1/household/claws/claw-a/owner-site".into(),
                body_hash: vec![0x77; 32],
            },
            claimed_binding_id: vec![0x01; 32],
        };
        Fx {
            session: M3SessionTranscript::from_noise_session(T1, STATIC),
            m2,
            c1,
            resolved,
            channel_signer,
            action_signer,
            intent_wire: b"intent-wire".to_vec(),
        }
    }

    fn sign_both(fx: &Fx, session: &M3SessionTranscript) -> (Vec<u8>, Vec<u8>) {
        let pre = session.binding_pre().expect("pre computes");
        let d_auth = crate::owner_site_binding_glue::device_auth_hash(
            &pre,
            &fx.resolved.binding_id(),
            &fx.resolved.binding_digest(),
            fx.resolved.participant_npub(),
            fx.resolved.channel_auth_key().key_id(),
        )
        .expect("d_auth");
        let action = crate::owner_site_binding_glue::owner_action_hash(
            &pre,
            &fx.m2,
            &fx.c1,
            &fx.resolved.binding_id(),
            &fx.resolved.binding_digest(),
            fx.resolved.participant_npub(),
            &fx.intent_wire,
        )
        .expect("action");
        (
            fx.channel_signer
                .sign(d_auth.as_bytes())
                .unwrap()
                .as_bytes()
                .to_vec(),
            fx.action_signer
                .sign(action.as_bytes())
                .unwrap()
                .as_bytes()
                .to_vec(),
        )
    }

    #[test]
    fn a_proof_signed_over_the_live_session_transcript_is_accepted() {
        let fx = fixture();
        let (device_sig, action_sig) = sign_both(&fx, &fx.session);
        verify_client_proof(
            &fx.session,
            &fx.m2,
            &fx.c1,
            &fx.resolved,
            &device_sig,
            &action_sig,
            &fx.intent_wire,
        )
        .expect("the honest proof must verify");
    }

    /// THE CLOSING RED: a `t1` that is valid in form but is NOT the live
    /// session's must make the handshake REFUSE. The attacker chose the
    /// origin; everything derived "correctly" from it — and it still fails,
    /// because the server computes from ITS OWN session state.
    #[test]
    fn a_proof_is_refused_when_the_server_session_t1_differs() {
        let fx = fixture();
        // The attacker signs over THEIR chosen t1...
        let attacker_session = M3SessionTranscript::from_noise_session([0xEE; 32], STATIC);
        let (device_sig, action_sig) = sign_both(&fx, &attacker_session);
        // ...and the server verifies against ITS OWN session state.
        let err = verify_client_proof(
            &fx.session,
            &fx.m2,
            &fx.c1,
            &fx.resolved,
            &device_sig,
            &action_sig,
            &fx.intent_wire,
        )
        .expect_err("a t1 that is not the session's must refuse");
        assert_eq!(err, OwnerSiteAuthorityError::ChannelProofMismatch);
    }

    /// The mirror image: a device_static that is valid in form but is not
    /// the one the handshake learned must refuse identically.
    #[test]
    fn a_proof_is_refused_when_the_server_session_device_static_differs() {
        let fx = fixture();
        let attacker_session = M3SessionTranscript::from_noise_session(T1, [0xEF; 32]);
        let (device_sig, action_sig) = sign_both(&fx, &attacker_session);
        let err = verify_client_proof(
            &fx.session,
            &fx.m2,
            &fx.c1,
            &fx.resolved,
            &device_sig,
            &action_sig,
            &fx.intent_wire,
        )
        .expect_err("a device_static that is not the session's must refuse");
        assert_eq!(err, OwnerSiteAuthorityError::ChannelProofMismatch);
    }
}
