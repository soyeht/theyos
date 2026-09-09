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

use crate::owner_site::a2_noise::{self, A2_VERSION, MAX_A2_FRAME_BYTES};
use crate::owner_site::a2_wire::{
    AkeFrame, AkeMessageKind, ClientHello, ClientHelloCore, ServerHello,
};
use crate::owner_site::authority::{
    OwnerSiteAuthorityGeneration, OwnerSiteAuthorityObservation, OwnerSiteBindingId,
};
use crate::owner_site::capability::{OwnerSitePreAuthIntent, OwnerSiteResource};
use crate::owner_site::challenge::{
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
    issued: crate::owner_site::challenge::OwnerSiteIssuedChallenge,
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
        let device_ephemeral = a2_noise::noise_public_prefix(&frame.noise)
            .map_err(|_| reject::<()>("ephemeral_prefix").unwrap_err())?;

        let (mut static_private, engine_static) = a2_noise::new_noise_static_keypair()
            .map_err(|_| reject::<()>("noise_keypair").unwrap_err())?;
        let engine_ephemeral_secret = Zeroizing::new(random_32());
        let mut preview =
            a2_noise::responder_with_channel_keys(&static_private, &engine_ephemeral_secret[..])
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
            a2_noise::array_32(&c1.core.claimed_binding_id)
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
        let issued = crate::owner_site::challenge::OwnerSiteIssuedChallenge::generate();
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
        let engine_ephemeral = a2_noise::noise_public_prefix(&noise[..preview_len])
            .map_err(|_| reject::<()>("ephemeral_prefix_preview").unwrap_err())?;
        let c1_wire = encode_canonical(&c1).map_err(|_| reject::<()>("c1_encode").unwrap_err())?;
        let t1 = a2_noise::server_auth_t1(
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
        let mut handshake =
            a2_noise::responder_with_channel_keys(&static_private, &engine_ephemeral_secret[..])
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
        if a2_noise::noise_public_prefix(&noise[..len])
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
    c1.core.domain == crate::owner_site::binding_glue::A2_DOMAIN
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
        let request = crate::owner_site::capability::OwnerSiteCanonicalRequest::new(
            crate::owner_site::capability::OwnerSiteRequestMethod::Get,
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
            domain: crate::owner_site::binding_glue::A2_DOMAIN.to_string(),
            version: A2_VERSION,
            household_id: "hh-a".into(),
            network_id: "owner-site-mesh".into(),
            route: "/api/v1/household/claws/claw-a/owner-site/ake".into(),
            resource: "claw-a".into(),
            intent: crate::owner_site::a2_wire::CanonicalIntent {
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
        resolved: &crate::owner_site::authority::OwnerSiteResolvedBinding,
        intent: &crate::owner_site::capability::OwnerSiteIntent,
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
        let proof: crate::owner_site::a2_wire::ClientProof =
            decode_canonical(&plaintext).map_err(|_| reject::<()>("proof_decode").unwrap_err())?;

        // THE LIVE HANDSHAKE OBJECT, same function, no parsing intermediate.
        let device_static = self
            .handshake
            .get_remote_static()
            .ok_or(OwnerSiteA2Rejection)
            .and_then(|raw| a2_noise::array_32(raw).map_err(|_| OwnerSiteA2Rejection))
            .map_err(|_| reject::<()>("remote_static").unwrap_err())?;
        let session = crate::owner_site::m3_verify::M3SessionTranscript::from_noise_session(
            self.t1,
            device_static,
        );

        let intent_wire = encode_canonical(&self.c1.core.intent)
            .map_err(|_| reject::<()>("intent_encode").unwrap_err())?;
        crate::owner_site::m3_verify::verify_client_proof(
            &session,
            &self.m2,
            &self.c1.core,
            resolved,
            &proof.device_signature,
            &proof.action_pop,
            &intent_wire,
        )
        .map_err(|_| reject::<()>("proof_verify").unwrap_err())?;

        let claim = crate::owner_site::challenge::OwnerSiteChallengeClaimScope::from_session(
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

        let h_final = a2_noise::final_handshake_hash(&self.handshake)
            .map_err(|_| reject::<()>("h_final").unwrap_err())?;
        a2_noise::channel_binding(h_final, &self.m2.channel_id, self.m2.channel_epoch)
            .map_err(|_| reject::<()>("channel_binding").unwrap_err())
    }
}

#[cfg(test)]
mod session_closing_tests;
