//! S2 production A2 responder (increment: `begin_m1`). One WebSocket, one
//! session, one challenge — assembled entirely from server-held state:
//! the engine's machine identity, the roster observation (freshness-checked
//! at admission, upstream), and fresh per-channel Noise material.
//!
//! ## Where every input comes from (the chain's discipline)
//!
//! - `t1` ← `server_auth_t1` computed HERE from the M1 the server just read
//!   and the server's own ephemeral — never from the wire as a hash;
//! - `device_static` for the later M3 ← `handshake.get_remote_static()` in
//!   `accept_m3` (3a-5 core), never from any message;
//! - `generation`/`fresh_until` ← the roster observation produced by the
//!   adapter (floor-less digest, like-to-like);
//! - challenge material ← CSPRNG via the promoted table (one-shot, TTL 60s,
//!   authority-lease check);
//! - `engine_signature` ← the machine key from the loaded household identity.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::Digest as _;
use zeroize::{Zeroize, Zeroizing};

use crate::owner_site_a2_noise::{self, A2_VERSION, MAX_A2_FRAME_BYTES};
use crate::owner_site_a2_wire::{
    AkeFrame, AkeMessageKind, ClientHello, ClientHelloCore, ServerHello,
};
use crate::owner_site_authority::{
    OwnerSiteAuthorityGeneration, OwnerSiteAuthorityObservation, OwnerSiteBindingId,
};
use crate::owner_site_capability::{OwnerSitePreAuthIntent, OwnerSiteResource};
use crate::owner_site_challenge::{
    OwnerSiteChallengeIssueScope, OwnerSiteChallengeTable, OwnerSiteChannelEpoch,
    OwnerSiteChannelId, OwnerSiteEngineIdentityCommitment, OwnerSiteTranscriptT1,
    OwnerSiteWebSocketInstance,
};

/// Rejection for the responder: one opaque variant on purpose — the wire
/// learns nothing about which check failed, because a discriminating error
/// is an oracle, and an oracle turns brute force into binary search.
///
/// THE ASYMMETRY IS DELIBERATE: the SERVER knows exactly which check failed
/// (every rejection logs its reason at debug level), the WIRE does not.
/// Without the server-side record, field diagnosis becomes impossible and
/// the pressure to leak to the wire becomes irresistible — that is how this
/// property dies in a well-meaning future PR. Pinned by the opacity RED in
/// this module: two failures with DIFFERENT causes produce the SAME wire
/// value, byte for byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteA2Rejection;

fn reject<T>(reason: &'static str) -> Result<T, OwnerSiteA2Rejection> {
    tracing::debug!(stage = "owner_site_ake.reject", reason, "A2 rejection");
    Err(OwnerSiteA2Rejection)
}

fn encode_canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, OwnerSiteA2Rejection> {
    household_rs::cbor::to_canonical_vec(value).map_err(|_| OwnerSiteA2Rejection)
}

fn decode_canonical<T: serde::de::DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
) -> Result<T, OwnerSiteA2Rejection> {
    household_rs::cbor::from_canonical_slice(bytes).map_err(|_| OwnerSiteA2Rejection)
}

fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes
}

/// The production A2 responder: engine identity + the one-shot challenge
/// table + the channel epoch counter. One per engine (the table and the
/// counter are engine-wide state).
pub(crate) struct OwnerSiteA2Responder {
    engine_machine_certificate: Vec<u8>,
    engine_key_id: String,
    engine_signer: Arc<dyn household_rs::keys::IdentityKey>,
    challenges: OwnerSiteChallengeTable,
    next_channel_epoch: AtomicU64,
}

/// One accepted M1 → one session. Holds exactly what `accept_m3` needs and
/// nothing more.
#[allow(dead_code)] // consumed by accept_m3 (next increment)
pub(crate) struct OwnerSiteA2ResponderSession {
    handshake: snow::HandshakeState,
    c1: ClientHello,
    m2: ServerHello,
    t1: [u8; 32],
    issue: OwnerSiteChallengeIssueScope,
    issued: crate::owner_site_challenge::OwnerSiteIssuedChallenge,
    claimed_binding_id: OwnerSiteBindingId,
    generation: OwnerSiteAuthorityGeneration,
}

impl OwnerSiteA2Responder {
    #[allow(dead_code)] // installed by the household wiring (next increment)
    pub(crate) fn new(
        engine_machine_certificate: Vec<u8>,
        engine_key_id: String,
        engine_signer: Arc<dyn household_rs::keys::IdentityKey>,
    ) -> Self {
        Self {
            engine_machine_certificate,
            engine_key_id,
            engine_signer,
            challenges: OwnerSiteChallengeTable::new(),
            next_channel_epoch: AtomicU64::new(1),
        }
    }

    /// Accept one M1: build the session, sign T1, issue the one-shot
    /// challenge, and return the M2 frame. Any failure rejects with the
    /// single opaque variant and leaves NO challenge behind.
    #[allow(dead_code)]
    pub(crate) fn begin_m1(
        &self,
        intent: &OwnerSitePreAuthIntent,
        resource: &OwnerSiteResource,
        observation: &OwnerSiteAuthorityObservation,
        bytes: &[u8],
    ) -> Result<(OwnerSiteA2ResponderSession, Vec<u8>), OwnerSiteA2Rejection> {
        if intent.resource() != resource {
            return reject("resource_mismatch");
        }
        let frame: AkeFrame = decode_canonical(bytes)?;
        if frame.version != A2_VERSION
            || AkeMessageKind::from_wire(frame.kind) != Some(AkeMessageKind::M1)
            || frame.noise.is_empty()
            || frame.noise.len() > MAX_A2_FRAME_BYTES
        {
            return reject("m1_frame_shape");
        }
        let device_ephemeral = owner_site_a2_noise::noise_public_prefix(&frame.noise)
            .map_err(|_| reject::<()>("ephemeral_prefix").unwrap_err())?;

        let (mut static_private, engine_static) =
            owner_site_a2_noise::new_noise_static_keypair()
                .map_err(|_| reject::<()>("noise_keypair").unwrap_err())?;
        let engine_ephemeral_secret = Zeroizing::new(random_32());
        let mut preview = owner_site_a2_noise::responder_with_channel_keys(
            &static_private,
            &engine_ephemeral_secret[..],
        )
        .map_err(|_| reject::<()>("responder_build").unwrap_err())?;
        let mut plaintext = vec![0u8; MAX_A2_FRAME_BYTES];
        let preview_read = preview
            .read_message(&frame.noise, &mut plaintext)
            .map_err(|_| reject::<()>("m1_noise_read").unwrap_err())?;
        plaintext.truncate(preview_read);
        let core: ClientHelloCore =
            decode_canonical(&plaintext).map_err(|_| reject::<()>("c1_decode").unwrap_err())?;
        let c1 = ClientHello {
            core,
            device_ephemeral: device_ephemeral.to_vec(),
        };
        let claimed_binding_id = OwnerSiteBindingId::from_wire(
            owner_site_a2_noise::array_32(&c1.core.claimed_binding_id)
                .map_err(|_| reject::<()>("claimed_binding_shape").unwrap_err())?,
        )
        .map_err(|_| reject::<()>("claimed_binding_zero").unwrap_err())?;
        if !matches_pre_auth(&c1, intent) {
            return reject("pre_auth_mismatch");
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);
        if !observation.is_fresh_at(now) {
            return reject("authority_stale");
        }
        let generation = observation.generation();
        let fresh_until = observation.fresh_until();

        let ws_instance = OwnerSiteWebSocketInstance::generate();
        let channel_id = OwnerSiteChannelId::generate();
        let epoch = self.next_channel_epoch.fetch_add(1, Ordering::SeqCst);
        let channel_epoch = OwnerSiteChannelEpoch::new(epoch)
            .map_err(|_| reject::<()>("channel_epoch_zero").unwrap_err())?;
        let issued = crate::owner_site_challenge::OwnerSiteIssuedChallenge::generate();
        let machine_digest: [u8; 32] =
            sha2::Sha256::digest(&self.engine_machine_certificate).into();
        let mut m2 = ServerHello {
            engine_machine_certificate: self.engine_machine_certificate.clone(),
            engine_key_id: self.engine_key_id.clone(),
            channel_id: channel_id.as_bytes().to_vec(),
            channel_epoch: channel_epoch.get(),
            challenge_id: issued.id().as_bytes().to_vec(),
            challenge_secret: issued.secret().as_bytes().to_vec(),
            authz_epoch: generation.authz_epoch(),
            roster_digest: generation.digest().to_vec(),
            fresh_until,
            engine_signature: Vec::new(),
        };

        let mut noise = vec![0u8; MAX_A2_FRAME_BYTES];
        // The preview reveals only the ephemeral's public half so T1 can be
        // signed before the one real M2 is made; the real responder is then
        // rebuilt with the same one-channel key, never retained or reused.
        let preview_len = preview
            .write_message(&[], &mut noise)
            .map_err(|_| reject::<()>("preview_write").unwrap_err())?;
        let engine_ephemeral = owner_site_a2_noise::noise_public_prefix(&noise[..preview_len])
            .map_err(|_| reject::<()>("ephemeral_prefix_preview").unwrap_err())?;
        let c1_wire = encode_canonical(&c1).map_err(|_| reject::<()>("c1_encode").unwrap_err())?;
        let t1 = owner_site_a2_noise::server_auth_t1(
            &c1_wire,
            engine_ephemeral,
            engine_static,
            machine_digest,
            &self.engine_key_id,
            &m2.channel_id,
            m2.channel_epoch,
            &m2.challenge_id,
            &m2.challenge_secret,
            m2.authz_epoch,
            &m2.roster_digest,
            m2.fresh_until,
        )
        .map_err(|_| reject::<()>("t1_compute").unwrap_err())?;
        let signature = self
            .engine_signer
            .sign(&t1)
            .map_err(|_| reject::<()>("engine_sign").unwrap_err())?;
        m2.engine_signature = signature.as_bytes().to_vec();

        let transcript_t1 = OwnerSiteTranscriptT1::from_computed_t1(t1);
        let issue = OwnerSiteChallengeIssueScope::from_responder(
            intent.clone(),
            claimed_binding_id,
            ws_instance,
            channel_id,
            channel_epoch,
            OwnerSiteEngineIdentityCommitment::from_engine_identity(
                machine_digest,
                &self.engine_key_id,
            )
            .map_err(|_| reject::<()>("engine_commitment").unwrap_err())?,
            transcript_t1,
            generation,
            fresh_until,
        );
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| reject::<()>("clock").unwrap_err())?;
        self.challenges
            .insert_generated(issue.clone(), &issued, now_secs)
            .map_err(|_| reject::<()>("challenge_insert").unwrap_err())?;

        let payload = encode_canonical(&m2).map_err(|_| reject::<()>("m2_encode").unwrap_err())?;
        let mut handshake = owner_site_a2_noise::responder_with_channel_keys(
            &static_private,
            &engine_ephemeral_secret[..],
        )
        .map_err(|_| reject::<()>("responder_rebuild").unwrap_err())?;
        let mut reread = vec![0u8; MAX_A2_FRAME_BYTES];
        let reread_len = handshake
            .read_message(&frame.noise, &mut reread)
            .map_err(|_| reject::<()>("m1_reread").unwrap_err())?;
        if reread[..reread_len] != plaintext {
            return reject("reread_mismatch");
        }
        let len = handshake
            .write_message(&payload, &mut noise)
            .map_err(|_| reject::<()>("m2_noise_write").unwrap_err())?;
        if owner_site_a2_noise::noise_public_prefix(&noise[..len])
            .map_err(|_| reject::<()>("ephemeral_recheck_read").unwrap_err())?
            != engine_ephemeral
        {
            return reject("ephemeral_recheck");
        }
        noise.truncate(len);
        static_private.zeroize();
        let out_frame = encode_canonical(&AkeFrame {
            version: A2_VERSION,
            kind: AkeMessageKind::M2 as u8,
            noise,
        })?;
        Ok((
            OwnerSiteA2ResponderSession {
                handshake,
                c1,
                m2,
                t1,
                issue,
                issued,
                claimed_binding_id,
                generation,
            },
            out_frame,
        ))
    }
}

/// The pre-auth match: the peer's claim must equal the server's expected
/// intent in every field — domain, version, household, network, route,
/// resource, and the canonical request triple. Anything less is Rejected.
fn matches_pre_auth(c1: &ClientHello, intent: &OwnerSitePreAuthIntent) -> bool {
    c1.core.domain == crate::owner_site_binding_glue::A2_DOMAIN
        && c1.core.version == A2_VERSION
        && c1.core.household_id == intent.household_id()
        && c1.core.network_id == intent.network_id()
        && c1.core.route == intent.request().route()
        && c1.core.resource == intent.resource().as_str()
        && c1.core.intent.method == intent.request().method().as_wire()
        && c1.core.intent.target == intent.request().route()
        && c1.core.intent.body_hash == intent.request().body_hash()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pre-auth match is exact: every single-field drift rejects. This is
    /// the gate that keeps a well-formed M1 for the WRONG intent out.
    #[test]
    fn pre_auth_rejects_any_single_field_drift() {
        let request = crate::owner_site_capability::OwnerSiteCanonicalRequest::new(
            crate::owner_site_capability::OwnerSiteRequestMethod::Get,
            "/api/v1/household/claws/claw-a/owner-site/ake",
            [7u8; 32],
        )
        .unwrap();
        let intent = OwnerSitePreAuthIntent::new(
            "hh-a",
            "owner-site-mesh",
            OwnerSiteResource::from_route_claw("claw-a").unwrap(),
            request,
        )
        .unwrap();
        let base = ClientHelloCore {
            domain: crate::owner_site_binding_glue::A2_DOMAIN.to_string(),
            version: A2_VERSION,
            household_id: "hh-a".into(),
            network_id: "owner-site-mesh".into(),
            route: "/api/v1/household/claws/claw-a/owner-site/ake".into(),
            resource: "claw-a".into(),
            intent: crate::owner_site_a2_wire::CanonicalIntent {
                method: "GET".into(),
                target: "/api/v1/household/claws/claw-a/owner-site/ake".into(),
                body_hash: vec![7u8; 32],
            },
            claimed_binding_id: vec![0x01; 32],
        };
        let c1 = ClientHello {
            core: base.clone(),
            device_ephemeral: vec![0x09; 32],
        };
        assert!(matches_pre_auth(&c1, &intent));

        let mut drifted = base.clone();
        drifted.household_id = "hh-b".into();
        assert!(!matches_pre_auth(
            &ClientHello {
                core: drifted,
                device_ephemeral: vec![0x09; 32]
            },
            &intent
        ));

        let mut drifted = base.clone();
        drifted.resource = "claw-b".into();
        assert!(!matches_pre_auth(
            &ClientHello {
                core: drifted,
                device_ephemeral: vec![0x09; 32]
            },
            &intent
        ));

        let mut drifted = base;
        drifted.intent.method = "POST".into();
        assert!(!matches_pre_auth(
            &ClientHello {
                core: drifted,
                device_ephemeral: vec![0x09; 32]
            },
            &intent
        ));
    }
}

impl OwnerSiteA2ResponderSession {
    /// Accept one M3: verify the client proof against the resolved binding
    /// with every transcript computed from the LIVE handshake state, claim
    /// the one-shot challenge, and bind the channel. THE CRAVA: `t1` comes
    /// from `self.t1` (server-computed) and `device_static` from
    /// `self.handshake.get_remote_static()` — the live handshake object, in
    /// this same function, with NO parsing intermediate. A wire-shaped
    /// `device_static` that is not the session's fails the proof, the
    /// challenge is NOT claimed, and nothing the proof would authorize
    /// happens (the effect, not the return).
    #[allow(dead_code)] // wired by the WS serve loop (next increment)
    pub(crate) fn accept_m3(
        &mut self,
        challenges: &OwnerSiteChallengeTable,
        resolved: &crate::owner_site_authority::OwnerSiteResolvedBinding,
        intent: &crate::owner_site_capability::OwnerSiteIntent,
        bytes: &[u8],
    ) -> Result<[u8; 32], OwnerSiteA2Rejection> {
        let frame: AkeFrame =
            decode_canonical(bytes).map_err(|_| reject::<()>("m3_frame_decode").unwrap_err())?;
        if frame.version != A2_VERSION
            || AkeMessageKind::from_wire(frame.kind) != Some(AkeMessageKind::M3)
            || frame.noise.is_empty()
            || frame.noise.len() > MAX_A2_FRAME_BYTES
        {
            return reject("m3_frame_shape");
        }
        let mut plaintext = vec![0u8; MAX_A2_FRAME_BYTES];
        let len = self
            .handshake
            .read_message(&frame.noise, &mut plaintext)
            .map_err(|_| reject::<()>("m3_noise_read").unwrap_err())?;
        plaintext.truncate(len);
        let proof: crate::owner_site_a2_wire::ClientProof =
            decode_canonical(&plaintext).map_err(|_| reject::<()>("proof_decode").unwrap_err())?;

        // THE LIVE HANDSHAKE OBJECT, same function, no parsing intermediate.
        let device_static = self
            .handshake
            .get_remote_static()
            .ok_or(OwnerSiteA2Rejection)
            .and_then(|raw| owner_site_a2_noise::array_32(raw).map_err(|_| OwnerSiteA2Rejection))
            .map_err(|_| reject::<()>("remote_static").unwrap_err())?;
        let session = crate::owner_site_m3_verify::M3SessionTranscript::from_noise_session(
            self.t1,
            device_static,
        );

        let intent_wire = encode_canonical(&self.c1.core.intent)
            .map_err(|_| reject::<()>("intent_encode").unwrap_err())?;
        crate::owner_site_m3_verify::verify_client_proof(
            &session,
            &self.m2,
            &self.c1.core,
            resolved,
            &proof.device_signature,
            &proof.action_pop,
            &intent_wire,
        )
        .map_err(|_| reject::<()>("proof_verify").unwrap_err())?;

        let claim = crate::owner_site_challenge::OwnerSiteChallengeClaimScope::from_session(
            self.issue.clone(),
            intent.clone(),
            resolved.clone(),
        )
        .map_err(|_| reject::<()>("claim_scope").unwrap_err())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| reject::<()>("clock").unwrap_err())?;
        challenges
            .claim_after_verified_pop(self.issued.id(), &claim, now)
            .map_err(|_| reject::<()>("challenge_claim").unwrap_err())?;

        let h_final = owner_site_a2_noise::final_handshake_hash(&self.handshake)
            .map_err(|_| reject::<()>("h_final").unwrap_err())?;
        owner_site_a2_noise::channel_binding(h_final, &self.m2.channel_id, self.m2.channel_epoch)
            .map_err(|_| reject::<()>("channel_binding").unwrap_err())
    }
}

#[cfg(test)]
mod session_closing_tests {
    //! THE CLOSER RED (the test that closes S2): full M1→M2→M3 sessions.
    //! Attack: proof signed over a device_static that is NOT the one the live
    //! handshake learned — refused, and the challenge is NOT consumed (the
    //! effect). Honest: proof over the real session transcript — accepted,
    //! and the challenge is consumed exactly once (non-vacuity).

    use super::*;
    use crate::owner_site_authority::{
        OwnerSiteActionPopKey, OwnerSiteBindingDigest, OwnerSiteChannelAuthKey,
        OwnerSiteResolvedBinding,
    };
    use household_rs::keys::{IdentityKey, P256Keypair};

    fn fixture() -> (
        OwnerSiteA2Responder,
        OwnerSitePreAuthIntent,
        OwnerSiteAuthorityObservation,
    ) {
        let responder = OwnerSiteA2Responder::new(
            vec![0x11; 64],
            "engine-test.v1".into(),
            Arc::new(P256Keypair::generate()),
        );
        let request = crate::owner_site_capability::OwnerSiteCanonicalRequest::new(
            crate::owner_site_capability::OwnerSiteRequestMethod::Get,
            "/api/v1/household/claws/claw-a/owner-site/ake",
            [7u8; 32],
        )
        .unwrap();
        let intent = OwnerSitePreAuthIntent::new(
            "hh-a",
            "owner-site-mesh",
            OwnerSiteResource::from_route_claw("claw-a").unwrap(),
            request,
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let observation = OwnerSiteAuthorityObservation::from_roster_adapter(
            "hh-a".to_string(),
            1,
            [7u8; 32],
            1,
            0,
            [3u8; 33],
            now,
            now + 86_400,
        )
        .unwrap();
        (responder, intent, observation)
    }

    fn resolved_binding() -> (P256Keypair, OwnerSiteResolvedBinding) {
        let device_key = P256Keypair::generate();
        let binding = OwnerSiteResolvedBinding::injected_for_harness(
            OwnerSiteBindingId::injected_for_harness([0x01; 32]).unwrap(),
            OwnerSiteBindingDigest::injected_for_harness([0x51; 32]).unwrap(),
            "npub1a",
            OwnerSiteChannelAuthKey::injected_for_harness("ch-a", device_key.public()).unwrap(),
            OwnerSiteActionPopKey::injected_for_harness("pop-a", device_key.public()).unwrap(),
        )
        .unwrap();
        (device_key, binding)
    }

    fn begin_honest_session(
        responder: &OwnerSiteA2Responder,
        intent: &OwnerSitePreAuthIntent,
        resource: &OwnerSiteResource,
        observation: &OwnerSiteAuthorityObservation,
    ) -> (snow::HandshakeState, [u8; 32], OwnerSiteA2ResponderSession) {
        let (client_hs, client_static) =
            owner_site_a2_noise::new_noise_initiator().expect("initiator");
        let core = ClientHelloCore {
            domain: crate::owner_site_binding_glue::A2_DOMAIN.to_string(),
            version: A2_VERSION,
            household_id: "hh-a".into(),
            network_id: "owner-site-mesh".into(),
            route: "/api/v1/household/claws/claw-a/owner-site/ake".into(),
            resource: "claw-a".into(),
            intent: crate::owner_site_a2_wire::CanonicalIntent {
                method: "GET".into(),
                target: "/api/v1/household/claws/claw-a/owner-site/ake".into(),
                body_hash: vec![7u8; 32],
            },
            claimed_binding_id: vec![0x01; 32],
        };
        let payload = encode_canonical(&core).unwrap();
        let mut client_hs = client_hs;
        let mut m1_noise = vec![0u8; MAX_A2_FRAME_BYTES];
        let m1_len = client_hs.write_message(&payload, &mut m1_noise).unwrap();
        m1_noise.truncate(m1_len);
        let m1_frame = encode_canonical(&AkeFrame {
            version: A2_VERSION,
            kind: AkeMessageKind::M1 as u8,
            noise: m1_noise,
        })
        .unwrap();
        let (session, m2_frame) = responder
            .begin_m1(intent, resource, observation, &m1_frame)
            .expect("honest begin_m1 must succeed");
        let m2: AkeFrame = decode_canonical(&m2_frame).unwrap();
        let mut m2_plain = vec![0u8; MAX_A2_FRAME_BYTES];
        let _ = client_hs.read_message(&m2.noise, &mut m2_plain).unwrap();
        (client_hs, client_static, session)
    }

    fn m3_frame_for(
        client_hs: &mut snow::HandshakeState,
        session: &OwnerSiteA2ResponderSession,
        binding: &OwnerSiteResolvedBinding,
        device_key: &P256Keypair,
        t1: [u8; 32],
        device_static: [u8; 32],
    ) -> Vec<u8> {
        let pre = crate::owner_site_binding_glue::pop_binding_pre(t1, device_static).unwrap();
        let d_auth = crate::owner_site_binding_glue::device_auth_hash(
            &pre,
            &binding.binding_id(),
            &binding.binding_digest(),
            binding.participant_npub(),
            binding.channel_auth_key().key_id(),
        )
        .unwrap();
        let intent_wire = encode_canonical(&session.c1.core.intent).unwrap();
        let action = crate::owner_site_binding_glue::owner_action_hash(
            &pre,
            &session.m2,
            &session.c1.core,
            &binding.binding_id(),
            &binding.binding_digest(),
            binding.participant_npub(),
            &intent_wire,
        )
        .unwrap();
        let proof = crate::owner_site_a2_wire::ClientProof {
            binding_id: binding.binding_id().as_bytes().to_vec(),
            binding_digest: binding.binding_digest().as_bytes().to_vec(),
            participant_npub: binding.participant_npub().to_string(),
            channel_auth_key_id: binding.channel_auth_key().key_id().as_str().to_string(),
            action_pop_key_id: binding.action_pop_key().key_id().as_str().to_string(),
            device_signature: device_key
                .sign(d_auth.as_bytes())
                .unwrap()
                .as_bytes()
                .to_vec(),
            action_pop: device_key
                .sign(action.as_bytes())
                .unwrap()
                .as_bytes()
                .to_vec(),
        };
        let proof_payload = encode_canonical(&proof).unwrap();
        let mut m3_noise = vec![0u8; MAX_A2_FRAME_BYTES];
        let m3_len = client_hs
            .write_message(&proof_payload, &mut m3_noise)
            .unwrap();
        m3_noise.truncate(m3_len);
        encode_canonical(&AkeFrame {
            version: A2_VERSION,
            kind: AkeMessageKind::M3 as u8,
            noise: m3_noise,
        })
        .unwrap()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn m3_signed_over_a_foreign_device_static_is_refused_and_the_challenge_survives() {
        let (responder, intent, observation) = fixture();
        let resource = OwnerSiteResource::from_route_claw("claw-a").unwrap();
        let (mut client_hs, client_static, mut session) =
            begin_honest_session(&responder, &intent, &resource, &observation);
        // ONE key — the same pair the binding holds. The ONLY thing wrong
        // is the device_static the proof is signed over.
        let (device_key, binding) = resolved_binding();
        let foreign_static = [0xEE; 32];
        // PRECONDITION: the foreign static really IS foreign to this session.
        assert_ne!(
            client_static, foreign_static,
            "precondition: the foreign static must differ from the live session's"
        );
        let m3_frame = m3_frame_for(
            &mut client_hs,
            &session,
            &binding,
            &device_key,
            session.t1,
            foreign_static,
        );

        let intent_for_claim = crate::owner_site_capability::OwnerSiteIntent::from_pre_auth(
            intent.clone(),
            "member-a".to_string(),
        );
        let outstanding_before = responder.challenges.outstanding(now_secs()).unwrap();
        assert_eq!(
            outstanding_before, 1,
            "precondition: exactly one challenge outstanding before accept_m3"
        );
        let result = session.accept_m3(
            &responder.challenges,
            &binding,
            &intent_for_claim,
            &m3_frame,
        );
        assert!(
            result.is_err(),
            "a proof over a foreign device_static must be refused"
        );
        let outstanding_after = responder.challenges.outstanding(now_secs()).unwrap();
        assert_eq!(
            outstanding_before, outstanding_after,
            "THE EFFECT: the one-shot challenge must NOT be consumed by a refused proof"
        );
    }

    #[test]
    fn m3_signed_over_the_real_session_transcript_is_accepted_and_consumes() {
        let (responder, intent, observation) = fixture();
        let resource = OwnerSiteResource::from_route_claw("claw-a").unwrap();
        let (mut client_hs, client_static, mut session) =
            begin_honest_session(&responder, &intent, &resource, &observation);
        let (device_key, binding) = resolved_binding();
        let m3_frame = m3_frame_for(
            &mut client_hs,
            &session,
            &binding,
            &device_key,
            session.t1,
            client_static, // the REAL static the handshake learned
        );

        let intent_for_claim = crate::owner_site_capability::OwnerSiteIntent::from_pre_auth(
            intent.clone(),
            "member-a".to_string(),
        );
        let outstanding_before = responder.challenges.outstanding(now_secs()).unwrap();
        assert_eq!(
            outstanding_before, 1,
            "precondition: exactly one challenge outstanding before accept_m3"
        );
        session
            .accept_m3(
                &responder.challenges,
                &binding,
                &intent_for_claim,
                &m3_frame,
            )
            .expect("the honest proof must be accepted");
        let outstanding_after = responder.challenges.outstanding(now_secs()).unwrap();
        assert_eq!(
            outstanding_before - 1,
            outstanding_after,
            "THE EFFECT: the one-shot challenge is consumed exactly once"
        );
    }

    /// TYPED-API OPACITY: two failures with DIFFERENT causes that reach
    /// DIFFERENT code paths in `accept_m3` must return the SAME opaque type
    /// `OwnerSiteA2Rejection` and the SAME public `Debug` form — the caller
    /// cannot discriminate which check failed from the return value alone.
    ///
    /// WIRE-LEVEL OPACITY (same CBOR bytes on the WebSocket for every cause)
    /// is PENDING the WS handler wiring — it does not exist yet and is not
    /// claimed here. When the handler lands, a wire-level test must be added.
    ///
    /// Cause A (proof_verify path): proof signed over a foreign device_static.
    /// Cause B (challenge_claim path): valid proof, but the challenge was
    /// already purged from the table.
    #[test]
    fn two_distinct_causes_return_the_same_opaque_rejection_and_debug_form() {
        let (responder, intent, observation) = fixture();
        let resource = OwnerSiteResource::from_route_claw("claw-a").unwrap();
        let intent_for_claim = crate::owner_site_capability::OwnerSiteIntent::from_pre_auth(
            intent.clone(),
            "member-a".to_string(),
        );

        // ── Cause A: proof_verify path (foreign device_static) ──────────
        let (mut client_hs_a, _client_static_a, mut session_a) =
            begin_honest_session(&responder, &intent, &resource, &observation);
        let (device_key_a, binding_a) = resolved_binding();
        let frame_a = m3_frame_for(
            &mut client_hs_a,
            &session_a,
            &binding_a,
            &device_key_a,
            session_a.t1,
            [0xEE; 32], // foreign static
        );
        let err_a = session_a
            .accept_m3(
                &responder.challenges,
                &binding_a,
                &intent_for_claim,
                &frame_a,
            )
            .expect_err("cause A must reject");

        // ── Cause B: challenge_claim path (valid proof, challenge purged) ─
        let (mut client_hs_b, client_static_b, mut session_b) =
            begin_honest_session(&responder, &intent, &resource, &observation);
        let (device_key_b, binding_b) = resolved_binding();
        let frame_b = m3_frame_for(
            &mut client_hs_b,
            &session_b,
            &binding_b,
            &device_key_b,
            session_b.t1,
            client_static_b, // the REAL static — proof is valid
        );
        let future = now_secs() + 120;
        let _ = responder.challenges.outstanding(future).unwrap();
        let err_b = session_b
            .accept_m3(
                &responder.challenges,
                &binding_b,
                &intent_for_claim,
                &frame_b,
            )
            .expect_err("cause B must reject");

        // ── Both return the same opaque type and identical Debug ────────
        assert_eq!(
            err_a, err_b,
            "two different causes must produce the same opaque rejection value"
        );
        assert_eq!(
            format!("{err_a:?}"),
            format!("{err_b:?}"),
            "the Debug form must not name the cause"
        );
        assert_eq!(format!("{err_a:?}"), "OwnerSiteA2Rejection");
    }
}
