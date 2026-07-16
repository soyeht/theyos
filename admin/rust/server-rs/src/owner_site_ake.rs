//! Owner-site A2 M1/M2/M3 handshake seam.
//!
//! The route which reaches this module is intentionally fail-closed in a
//! production process: no reviewed machine/roster provider is installed yet.
//! The only admitting provider is a crate-test harness.  That lets this slice
//! exercise the reviewed A2 wire and ordering without turning a socket address,
//! a CIDR, or an HTTP header into a remote principal.
//!
//! This slice stops after a locally observed `validated pending Finished`
//! state.  It does not define S2/C3, an exporter, record AEAD, a
//! `VerifiedMeshPeer`, a backend dial, a proxy, or site bytes.  In particular,
//! it must never substitute a plaintext success response for the missing
//! reviewed Finished/Ack profile.

use std::net::SocketAddr;

use axum::extract::ws::WebSocket;
use futures_util::SinkExt;

use crate::owner_site_capability::OwnerSiteResource;

/// Provider seam for the one-WebSocket A2 handshake.
///
/// There is deliberately no production constructor.  A future reviewed
/// provider must supply a machine identity and a signed, fresh roster without
/// involving `ConnectInfo`, interface names, or address classification.
#[derive(Clone)]
pub(crate) struct OwnerSiteAkeProvider {
    #[cfg(test)]
    harness: Option<std::sync::Arc<OwnerSiteAkeHarness>>,
}

impl OwnerSiteAkeProvider {
    /// Tests are the only current source of an admitting A2 provider.  The
    /// production router never installs this extension.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn injected_for_harness(harness: OwnerSiteAkeHarness) -> Self {
        Self {
            harness: Some(std::sync::Arc::new(harness)),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn harness_for_test(&self) -> Option<std::sync::Arc<OwnerSiteAkeHarness>> {
        self.harness.clone()
    }

    /// Checks the server-owned resource before accepting a WebSocket upgrade.
    #[must_use]
    pub(crate) fn admits_resource(&self, resource: &OwnerSiteResource) -> bool {
        #[cfg(test)]
        {
            self.harness
                .as_ref()
                .is_some_and(|harness| harness.admits_resource(resource))
        }
        #[cfg(not(test))]
        {
            let _ = (self, resource);
            false
        }
    }

    /// Drives only M1/M2/M3 on the accepted WebSocket.
    ///
    /// The post-M3 result is intentionally silent and ephemeral until a later
    /// reviewed S2/C3 record-AEAD profile exists.
    pub(crate) async fn serve(
        &self,
        socket: WebSocket,
        resource: OwnerSiteResource,
        peer: Option<SocketAddr>,
    ) {
        #[cfg(test)]
        {
            if let Some(harness) = &self.harness {
                harness.serve(socket, resource, peer).await;
                return;
            }
        }

        let _ = (resource, peer);
        let mut socket = socket;
        let _ = socket.close().await;
    }
}

/// Test-only A2 authority and protocol harness.
///
/// Its implementation lands with the M1/M2/M3 state machine below.  Keeping
/// the type private to crate tests makes the uninstalled production seam deny
/// by default while still allowing route-real red-team coverage.
#[cfg(test)]
mod harness {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    use axum::extract::ws::{Message, WebSocket};
    use futures_util::{SinkExt, StreamExt};
    use household_rs::machine_cert::SignOptions;
    use household_rs::{
        MachineCert, MemberDeviceBinding, P256PublicKey, P256Signature, Platform,
        derive_household_id,
    };
    use household_rs::{cbor, keys::IdentityKey, keys::P256Keypair, keys::verify_signature};
    use rand::{RngCore, rngs::OsRng};
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use sha2::{Digest, Sha256};
    use snow::{
        Builder, HandshakeState,
        params::{
            BaseChoice, CipherChoice, DHChoice, HandshakeChoice, HandshakeModifierList,
            HandshakePattern, HashChoice, NoiseParams,
        },
    };
    use zeroize::{Zeroize, Zeroizing};

    use super::{OwnerSiteAkeProvider, OwnerSiteResource, SocketAddr};
    use crate::owner_site_authority::{
        OwnerSiteActionPopKey, OwnerSiteActionPopKeyId, OwnerSiteAuthorityGeneration,
        OwnerSiteBindingDigest, OwnerSiteBindingId, OwnerSiteChannelAuthKey,
        OwnerSiteChannelAuthKeyId, OwnerSiteMembershipRole, OwnerSiteRemotePrincipal,
        OwnerSiteResolvedBinding, OwnerSiteRevocationTombstone, OwnerSiteRosterBinding,
        OwnerSiteRosterScope, OwnerSiteRosterSnapshot,
    };
    use crate::owner_site_capability::{
        OwnerSiteCanonicalRequest, OwnerSiteIntent, OwnerSiteRequestMethod,
    };
    use crate::owner_site_challenge::{
        OWNER_SITE_CHALLENGE_BYTES, OwnerSiteChallengeClaimScope, OwnerSiteChallengeIssueScope,
        OwnerSiteChallengeTable, OwnerSiteChannelEpoch, OwnerSiteChannelId,
        OwnerSiteEngineIdentityCommitment, OwnerSiteIssuedChallenge, OwnerSiteTranscriptT1,
        OwnerSiteWebSocketInstance,
    };

    const A2_DOMAIN: &str = "soyeht/owner-site/a2/v1";
    const A2_VERSION: u8 = 1;
    const A2_NOISE_PROTOCOL_NAME: &str = "Noise_XXa2v1_25519_ChaChaPoly_SHA256";
    const A2_NOISE_PROLOGUE_LABEL: &str = "noise-prologue";
    const A2_RECORD_PROFILE: &str = "a2-record-v1";
    const A2_CHANNEL_BINDING_LABEL: &str = "channel-binding";
    const A2_NETWORK_ID: &str = "owner-site-mesh";
    const A2_ENGINE_KEY_ID: &str = "engine:test.v1";
    const A2_NOW: u64 = 1_000;
    const MAX_A2_FRAME_BYTES: usize = 16 * 1024;
    const NOISE_PUBLIC_KEY_BYTES: usize = 32;
    const P256_SIGNATURE_BYTES: usize = 64;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum OwnerSiteAkeFailure {
        Rejected,
    }

    type AkeResult<T> = Result<T, OwnerSiteAkeFailure>;

    #[derive(Default)]
    pub(crate) struct OwnerSiteAkeEffects {
        sessions_started: AtomicUsize,
        challenge_issues: AtomicUsize,
        challenge_claims: AtomicUsize,
        validated_pending_finished: AtomicUsize,
        verified_peers: AtomicUsize,
        mints: AtomicUsize,
        consumes: AtomicUsize,
        proxy_dials: AtomicUsize,
        site_bytes: AtomicUsize,
    }

    #[derive(Debug, Eq, PartialEq)]
    pub(crate) struct OwnerSiteAkeEffectSnapshot {
        pub(crate) sessions_started: usize,
        pub(crate) challenge_issues: usize,
        pub(crate) challenge_claims: usize,
        pub(crate) validated_pending_finished: usize,
        pub(crate) verified_peers: usize,
        pub(crate) mints: usize,
        pub(crate) consumes: usize,
        pub(crate) proxy_dials: usize,
        pub(crate) site_bytes: usize,
    }

    impl OwnerSiteAkeEffects {
        #[must_use]
        pub(crate) fn snapshot(&self) -> OwnerSiteAkeEffectSnapshot {
            OwnerSiteAkeEffectSnapshot {
                sessions_started: self.sessions_started.load(Ordering::SeqCst),
                challenge_issues: self.challenge_issues.load(Ordering::SeqCst),
                challenge_claims: self.challenge_claims.load(Ordering::SeqCst),
                validated_pending_finished: self.validated_pending_finished.load(Ordering::SeqCst),
                verified_peers: self.verified_peers.load(Ordering::SeqCst),
                mints: self.mints.load(Ordering::SeqCst),
                consumes: self.consumes.load(Ordering::SeqCst),
                proxy_dials: self.proxy_dials.load(Ordering::SeqCst),
                site_bytes: self.site_bytes.load(Ordering::SeqCst),
            }
        }
    }

    /// A test-only fixture exposing the client material separately from the
    /// server-only provider.  It is the only positive source in this slice.
    pub(crate) struct OwnerSiteAkeFixture {
        pub(crate) provider: OwnerSiteAkeProvider,
        pub(crate) client: OwnerSiteAkeClient,
        pub(crate) effects: Arc<OwnerSiteAkeEffects>,
    }

    /// Device-side test driver.  It has both distinct P-256 signers but never
    /// sees the server's challenge table or roster resolver.
    pub(crate) struct OwnerSiteAkeClient {
        intent: OwnerSiteIntent,
        binding_id: OwnerSiteBindingId,
        binding_digest: OwnerSiteBindingDigest,
        participant_npub: String,
        channel_auth_key_id: OwnerSiteChannelAuthKeyId,
        action_pop_key_id: OwnerSiteActionPopKeyId,
        channel_auth_signer: Arc<P256Keypair>,
        action_pop_signer: Arc<P256Keypair>,
        expected_machine_certificate: Vec<u8>,
        expected_household_key: P256PublicKey,
        expected_household_id: String,
        expected_machine_key: P256PublicKey,
        expected_engine_key_id: String,
        action_pop_signatures: Arc<AtomicUsize>,
    }

    impl OwnerSiteAkeClient {
        pub(crate) fn start(&self) -> AkeResult<(OwnerSiteAkeClientSession, Vec<u8>)> {
            let core = ClientHelloCore::from_intent(&self.intent, self.binding_id)?;
            self.start_with_core(core)
        }

        fn start_with_core(
            &self,
            core: ClientHelloCore,
        ) -> AkeResult<(OwnerSiteAkeClientSession, Vec<u8>)> {
            let (mut handshake, static_public) = new_noise_initiator()?;
            let c1_payload = encode_canonical(&core)?;
            let mut noise = vec![0u8; MAX_A2_FRAME_BYTES];
            let len = handshake
                .write_message(&c1_payload, &mut noise)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            noise.truncate(len);
            let ephemeral = noise_public_prefix(&noise)?;
            let c1 = ClientHello {
                core,
                device_ephemeral: ephemeral.to_vec(),
            };
            let frame = encode_frame(AkeMessageKind::M1, noise)?;
            Ok((
                OwnerSiteAkeClientSession {
                    handshake,
                    static_public,
                    c1,
                    binding_id: self.binding_id,
                    binding_digest: self.binding_digest,
                    participant_npub: self.participant_npub.clone(),
                    channel_auth_key_id: self.channel_auth_key_id.clone(),
                    action_pop_key_id: self.action_pop_key_id.clone(),
                    channel_auth_signer: Arc::clone(&self.channel_auth_signer),
                    action_pop_signer: Arc::clone(&self.action_pop_signer),
                    expected_machine_certificate: self.expected_machine_certificate.clone(),
                    expected_household_key: self.expected_household_key.clone(),
                    expected_household_id: self.expected_household_id.clone(),
                    expected_machine_key: self.expected_machine_key.clone(),
                    expected_engine_key_id: self.expected_engine_key_id.clone(),
                    action_pop_signatures: Arc::clone(&self.action_pop_signatures),
                    h_final: None,
                    channel_binding: None,
                },
                frame,
            ))
        }

        #[must_use]
        pub(crate) fn action_pop_signature_count(&self) -> usize {
            self.action_pop_signatures.load(Ordering::SeqCst)
        }
    }

    pub(crate) struct OwnerSiteAkeClientSession {
        handshake: HandshakeState,
        static_public: [u8; NOISE_PUBLIC_KEY_BYTES],
        c1: ClientHello,
        binding_id: OwnerSiteBindingId,
        binding_digest: OwnerSiteBindingDigest,
        participant_npub: String,
        channel_auth_key_id: OwnerSiteChannelAuthKeyId,
        action_pop_key_id: OwnerSiteActionPopKeyId,
        channel_auth_signer: Arc<P256Keypair>,
        action_pop_signer: Arc<P256Keypair>,
        expected_machine_certificate: Vec<u8>,
        expected_household_key: P256PublicKey,
        expected_household_id: String,
        expected_machine_key: P256PublicKey,
        expected_engine_key_id: String,
        action_pop_signatures: Arc<AtomicUsize>,
        h_final: Option<[u8; 32]>,
        channel_binding: Option<[u8; 32]>,
    }

    impl OwnerSiteAkeClientSession {
        /// Verifies M2 before signing either device proof, then emits M3.
        pub(crate) fn accept_m2_and_make_m3(&mut self, bytes: &[u8]) -> AkeResult<Vec<u8>> {
            let frame = decode_frame(bytes, AkeMessageKind::M2)?;
            let engine_ephemeral = noise_public_prefix(&frame.noise)?;
            let mut plaintext = vec![0u8; MAX_A2_FRAME_BYTES];
            let plaintext_len = self
                .handshake
                .read_message(&frame.noise, &mut plaintext)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            plaintext.truncate(plaintext_len);
            let m2: ServerHello = decode_canonical(&plaintext)?;
            validate_server_hello_lengths(&m2)?;

            let static_engine = self
                .handshake
                .get_remote_static()
                .ok_or(OwnerSiteAkeFailure::Rejected)
                .and_then(array_32)?;
            let certificate: MachineCert = decode_canonical(&m2.engine_machine_certificate)?;
            if m2.engine_machine_certificate != self.expected_machine_certificate
                || certificate.verify(&self.expected_household_key).is_err()
                || certificate.hh_id.as_str() != self.expected_household_id
                || certificate.m_pub != self.expected_machine_key
                || m2.engine_key_id != self.expected_engine_key_id
            {
                return Err(OwnerSiteAkeFailure::Rejected);
            }

            let machine_digest = sha256(&m2.engine_machine_certificate);
            let t1 = server_auth_t1(
                &self.c1,
                engine_ephemeral,
                static_engine,
                machine_digest,
                &m2,
            )?;
            verify_p256_signature(&certificate.m_pub, &t1, &m2.engine_signature)?;

            let binding_pre = pop_binding_pre(t1, self.static_public)?;
            let signature_d = sign_p256(
                self.channel_auth_signer.as_ref(),
                &device_auth_hash(
                    binding_pre,
                    self.binding_id,
                    self.binding_digest,
                    &self.participant_npub,
                    &self.channel_auth_key_id,
                )?,
            )?;
            let action_hash = owner_action_hash(
                binding_pre,
                &m2,
                &self.c1.core,
                self.binding_id,
                self.binding_digest,
                &self.participant_npub,
            )?;
            let pop_d = sign_p256(self.action_pop_signer.as_ref(), &action_hash)?;
            self.action_pop_signatures.fetch_add(1, Ordering::SeqCst);

            let m3 = ClientProof {
                binding_id: self.binding_id.as_bytes().to_vec(),
                binding_digest: self.binding_digest.as_bytes().to_vec(),
                participant_npub: self.participant_npub.clone(),
                channel_auth_key_id: self.channel_auth_key_id.as_str().to_owned(),
                action_pop_key_id: self.action_pop_key_id.as_str().to_owned(),
                device_signature: signature_d,
                action_pop: pop_d,
            };
            let payload = encode_canonical(&m3)?;
            let mut noise = vec![0u8; MAX_A2_FRAME_BYTES];
            let len = self
                .handshake
                .write_message(&payload, &mut noise)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            noise.truncate(len);
            let h_final = final_handshake_hash(&self.handshake)?;
            let channel_binding = channel_binding(h_final, &m2.channel_id, m2.channel_epoch)?;
            self.h_final = Some(h_final);
            self.channel_binding = Some(channel_binding);
            encode_frame(AkeMessageKind::M3, noise)
        }
    }

    pub(crate) struct OwnerSiteAkeHarness {
        resource: OwnerSiteResource,
        intent: OwnerSiteIntent,
        authority: Mutex<OwnerSiteAkeHarnessAuthority>,
        engine_signer: P256Keypair,
        engine_machine_certificate: Vec<u8>,
        engine_key_id: String,
        challenges: OwnerSiteChallengeTable,
        next_channel_epoch: AtomicU64,
        revoked_roster: OwnerSiteRosterSnapshot,
        effects: Arc<OwnerSiteAkeEffects>,
    }

    struct OwnerSiteAkeHarnessAuthority {
        principal: OwnerSiteRemotePrincipal,
        roster: OwnerSiteRosterSnapshot,
    }

    impl OwnerSiteAkeHarnessAuthority {
        fn resolve(
            &self,
            intent: &OwnerSiteIntent,
            proof: &ClientProof,
            claimed_binding_id: OwnerSiteBindingId,
        ) -> AkeResult<OwnerSiteResolvedBinding> {
            let binding_id = binding_id(&proof.binding_id)?;
            if binding_id != claimed_binding_id {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            let binding_digest = binding_digest(&proof.binding_digest)?;
            let channel_auth_key_id =
                OwnerSiteChannelAuthKeyId::injected_for_harness(&proof.channel_auth_key_id)
                    .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let action_pop_key_id =
                OwnerSiteActionPopKeyId::injected_for_harness(&proof.action_pop_key_id)
                    .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            if proof.participant_npub != self.principal.participant_npub() {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            self.roster
                .resolve_for_ake_harness(
                    intent,
                    &self.principal,
                    binding_id,
                    binding_digest,
                    &channel_auth_key_id,
                    &action_pop_key_id,
                )
                .ok_or(OwnerSiteAkeFailure::Rejected)
        }

        fn is_fresh(&self) -> bool {
            self.roster.is_fresh_for_ake_harness(A2_NOW)
        }
    }

    impl OwnerSiteAkeHarness {
        pub(crate) fn fixture_for_harness(claw_name: &str) -> AkeResult<OwnerSiteAkeFixture> {
            let resource = OwnerSiteResource::from_route_claw(claw_name)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let request = OwnerSiteCanonicalRequest::injected_for_harness(
                OwnerSiteRequestMethod::Get,
                "/api/v1/household/claws/{name}/owner-site/ake",
                sha256(&[]),
            )
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;

            let household_root = P256Keypair::generate();
            let household_id = derive_household_id(&household_root.public());
            let member = P256Keypair::generate();
            let device = P256Keypair::generate();
            let channel_auth_signer = Arc::new(P256Keypair::generate());
            let action_pop_signer = Arc::new(P256Keypair::generate());
            let participant_npub = "npub1owneralpha".to_owned();
            let member_device = MemberDeviceBinding::sign(
                &member,
                device.public(),
                participant_npub.clone(),
                A2_NOW,
            )
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let actor_id = member_device.member_id.clone();
            let intent = OwnerSiteIntent::injected_for_harness_with_request(
                household_id.as_str(),
                A2_NETWORK_ID,
                &actor_id,
                resource.clone(),
                request,
            )
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let scope = OwnerSiteRosterScope::injected_for_harness(
                intent.household_id(),
                intent.network_id(),
            )
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let generation = OwnerSiteAuthorityGeneration::injected_for_harness(1, [0x41; 32])
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let binding_id = OwnerSiteBindingId::injected_for_harness([0x01; 32])
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let binding_digest = OwnerSiteBindingDigest::injected_for_harness([0x51; 32])
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let channel_auth_key = OwnerSiteChannelAuthKey::injected_for_harness(
                "channel-auth-alpha",
                channel_auth_signer.public(),
            )
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let action_pop_key = OwnerSiteActionPopKey::injected_for_harness(
                "action-pop-alpha",
                action_pop_signer.public(),
            )
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let channel_auth_key_id = channel_auth_key.key_id().clone();
            let action_pop_key_id = action_pop_key.key_id().clone();
            let binding = OwnerSiteRosterBinding::injected_for_harness(
                binding_id,
                binding_digest,
                scope.clone(),
                member_device,
                OwnerSiteMembershipRole::Owner,
                resource.clone(),
                channel_auth_key,
                action_pop_key,
                generation,
            )
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let roster = OwnerSiteRosterSnapshot::injected_for_harness(
                scope.clone(),
                generation,
                vec![binding],
                Vec::new(),
                A2_NOW,
                A2_NOW + 120,
                "owner-key-alpha",
                vec![0xa5; P256_SIGNATURE_BYTES],
            )
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let revoked_generation =
                OwnerSiteAuthorityGeneration::injected_for_harness(2, [0x42; 32])
                    .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let revoked_roster = OwnerSiteRosterSnapshot::injected_for_harness(
                scope,
                revoked_generation,
                Vec::new(),
                vec![OwnerSiteRevocationTombstone::injected_for_harness(
                    binding_id,
                    revoked_generation,
                )],
                A2_NOW,
                A2_NOW + 120,
                "owner-key-alpha",
                vec![0xa5; P256_SIGNATURE_BYTES],
            )
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let principal = OwnerSiteRemotePrincipal::injected_for_harness(&participant_npub)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;

            let engine_signer = P256Keypair::generate();
            let certificate = encode_canonical(
                &MachineCert::sign(
                    &household_root,
                    &engine_signer.public(),
                    &SignOptions {
                        hh_id: household_id.clone(),
                        hostname: "macstudio".to_owned(),
                        platform: Platform::Macos,
                        joined_at: A2_NOW,
                    },
                )
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?,
            )?;
            let effects = Arc::new(OwnerSiteAkeEffects::default());
            let harness = Self {
                resource: resource.clone(),
                intent: intent.clone(),
                authority: Mutex::new(OwnerSiteAkeHarnessAuthority { principal, roster }),
                engine_signer,
                engine_machine_certificate: certificate.clone(),
                engine_key_id: A2_ENGINE_KEY_ID.to_owned(),
                challenges: OwnerSiteChallengeTable::new_for_harness(),
                next_channel_epoch: AtomicU64::new(1),
                revoked_roster,
                effects: Arc::clone(&effects),
            };
            let client = OwnerSiteAkeClient {
                intent,
                binding_id,
                binding_digest,
                participant_npub,
                channel_auth_key_id,
                action_pop_key_id,
                channel_auth_signer,
                action_pop_signer,
                expected_machine_certificate: certificate,
                expected_household_key: household_root.public(),
                expected_household_id: household_id.as_str().to_owned(),
                expected_machine_key: harness.engine_signer.public(),
                expected_engine_key_id: harness.engine_key_id.clone(),
                action_pop_signatures: Arc::new(AtomicUsize::new(0)),
            };
            Ok(OwnerSiteAkeFixture {
                provider: OwnerSiteAkeProvider::injected_for_harness(harness),
                client,
                effects,
            })
        }

        pub(crate) fn revoke_before_recheck_for_harness(&self) {
            if let Ok(mut authority) = self.authority.lock() {
                authority.roster = self.revoked_roster.clone();
            }
        }

        pub(super) fn admits_resource(&self, resource: &OwnerSiteResource) -> bool {
            self.resource == *resource
                && self
                    .authority
                    .lock()
                    .map(|authority| authority.is_fresh())
                    .unwrap_or(false)
        }

        pub(super) async fn serve(
            &self,
            mut socket: WebSocket,
            resource: OwnerSiteResource,
            peer: Option<SocketAddr>,
        ) {
            self.effects.sessions_started.fetch_add(1, Ordering::SeqCst);
            let Some(Ok(Message::Binary(m1))) = socket.next().await else {
                let _ = socket.close().await;
                return;
            };
            let Ok((mut session, m2)) = self.begin_m1(&resource, &m1) else {
                let _ = socket.close().await;
                return;
            };
            if socket.send(Message::Binary(m2.into())).await.is_err() {
                return;
            }
            let Some(Ok(Message::Binary(m3))) = socket.next().await else {
                let _ = socket.close().await;
                return;
            };
            if session.accept_m3(self, &m3).is_ok()
                && crate::household_listener::post_trust_household_peer_gate(peer)
                    .await
                    .is_ok()
                && self.recheck_after_claim(&session)
            {
                // This state is deliberately server-local and immediately
                // discarded on close.  There is no S2/C3 response in this PR.
                self.effects
                    .validated_pending_finished
                    .fetch_add(1, Ordering::SeqCst);
            }
            let _ = socket.close().await;
        }

        fn begin_m1(
            &self,
            resource: &OwnerSiteResource,
            bytes: &[u8],
        ) -> AkeResult<(OwnerSiteAkeResponderSession, Vec<u8>)> {
            if self.resource != *resource {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            let frame = decode_frame(bytes, AkeMessageKind::M1)?;
            let device_ephemeral = noise_public_prefix(&frame.noise)?;
            let (mut static_private, engine_static) = new_noise_static_keypair()?;
            let mut engine_ephemeral_secret = Zeroizing::new(random_32());
            let mut preview =
                responder_with_channel_keys(&static_private, &*engine_ephemeral_secret)?;
            let mut plaintext = vec![0u8; MAX_A2_FRAME_BYTES];
            let preview_read = preview
                .read_message(&frame.noise, &mut plaintext)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            plaintext.truncate(preview_read);
            let core: ClientHelloCore = decode_canonical(&plaintext)?;
            let c1 = ClientHello {
                core,
                device_ephemeral: device_ephemeral.to_vec(),
            };
            let claimed_binding_id = binding_id(&c1.core.claimed_binding_id)?;
            if !self.matches_pre_auth(&c1) {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            let authority = self
                .authority
                .lock()
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            if !authority.is_fresh() {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            let generation = authority.roster.generation();
            let fresh_until = authority.roster.fresh_until_for_harness();
            drop(authority);

            let ws_instance = OwnerSiteWebSocketInstance::injected_for_harness(random_32());
            let channel_id = OwnerSiteChannelId::injected_for_harness(random_32());
            let epoch = self
                .next_channel_epoch
                .fetch_add(1, Ordering::SeqCst)
                .checked_add(0)
                .filter(|epoch| *epoch != 0)
                .ok_or(OwnerSiteAkeFailure::Rejected)?;
            let channel_epoch = OwnerSiteChannelEpoch::injected_for_harness(epoch)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let issued = OwnerSiteIssuedChallenge::generated_for_ake_harness();
            let machine_digest = sha256(&self.engine_machine_certificate);
            let mut m2 = ServerHello {
                engine_machine_certificate: self.engine_machine_certificate.clone(),
                engine_key_id: self.engine_key_id.clone(),
                channel_id: channel_id.bytes_for_harness().to_vec(),
                channel_epoch: channel_epoch.get(),
                challenge_id: issued.id_for_harness().bytes_for_harness().to_vec(),
                challenge_secret: issued.secret_for_harness().bytes_for_harness().to_vec(),
                authz_epoch: generation.authz_epoch(),
                roster_digest: generation.digest().to_vec(),
                fresh_until,
                engine_signature: Vec::new(),
            };
            let mut noise = vec![0u8; MAX_A2_FRAME_BYTES];
            // The test-only provider supplies a fresh CSPRNG e_E to Snow once
            // per channel.  A local, never-sent preview reveals only its
            // public half so T1 can be signed before the one real M2 is made.
            // The real responder is rebuilt with that same one-channel key;
            // it is never retained or reused for another WebSocket.
            let preview_len = preview
                .write_message(&[], &mut noise)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            let engine_ephemeral = noise_public_prefix(&noise[..preview_len])?;
            let t1 = server_auth_t1(&c1, engine_ephemeral, engine_static, machine_digest, &m2)?;
            m2.engine_signature = sign_p256(&self.engine_signer, &t1)?;
            let transcript_t1 = OwnerSiteTranscriptT1::injected_for_harness(t1);
            let issue = OwnerSiteChallengeIssueScope::injected_for_harness(
                self.intent.pre_auth().clone(),
                claimed_binding_id,
                ws_instance,
                channel_id,
                channel_epoch,
                OwnerSiteEngineIdentityCommitment::injected_for_harness(
                    machine_digest,
                    &self.engine_key_id,
                )
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?,
                transcript_t1,
                generation,
                fresh_until,
            );
            self.challenges
                .insert_generated_for_harness(issue.clone(), &issued, A2_NOW)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            self.effects.challenge_issues.fetch_add(1, Ordering::SeqCst);

            let payload = encode_canonical(&m2)?;
            let mut handshake =
                responder_with_channel_keys(&static_private, &*engine_ephemeral_secret)?;
            let mut reread = vec![0u8; MAX_A2_FRAME_BYTES];
            let reread_len = handshake
                .read_message(&frame.noise, &mut reread)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            if reread[..reread_len] != plaintext {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            let len = handshake
                .write_message(&payload, &mut noise)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            if noise_public_prefix(&noise[..len])? != engine_ephemeral {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            noise.truncate(len);
            static_private.zeroize();
            engine_ephemeral_secret.zeroize();
            let frame = encode_frame(AkeMessageKind::M2, noise)?;
            Ok((
                OwnerSiteAkeResponderSession {
                    handshake,
                    c1,
                    m2,
                    t1,
                    issue,
                    issued,
                    claimed_binding_id,
                    generation,
                    proof: None,
                    h_final: None,
                    channel_binding: None,
                },
                frame,
            ))
        }

        fn matches_pre_auth(&self, c1: &ClientHello) -> bool {
            c1.core.domain == A2_DOMAIN
                && c1.core.version == A2_VERSION
                && c1.core.household_id == self.intent.household_id()
                && c1.core.network_id == self.intent.network_id()
                && c1.core.route == self.intent.request().route()
                && c1.core.resource == self.intent.resource().as_str()
                && c1.core.intent.method == self.intent.request().method().as_wire()
                && c1.core.intent.target == self.intent.request().route()
                && c1.core.intent.body_hash == self.intent.request().body_hash()
                && c1.device_ephemeral.len() == NOISE_PUBLIC_KEY_BYTES
        }

        fn recheck_after_claim(&self, session: &OwnerSiteAkeResponderSession) -> bool {
            let Ok(authority) = self.authority.lock() else {
                return false;
            };
            session.proof.as_ref().is_some_and(|proof| {
                authority.is_fresh()
                    && authority.roster.generation() == session.generation
                    && authority
                        .resolve(&self.intent, proof, session.claimed_binding_id)
                        .is_ok()
            })
        }
    }

    struct OwnerSiteAkeResponderSession {
        handshake: HandshakeState,
        c1: ClientHello,
        m2: ServerHello,
        t1: [u8; 32],
        issue: OwnerSiteChallengeIssueScope,
        issued: OwnerSiteIssuedChallenge,
        claimed_binding_id: OwnerSiteBindingId,
        generation: OwnerSiteAuthorityGeneration,
        proof: Option<ClientProof>,
        h_final: Option<[u8; 32]>,
        channel_binding: Option<[u8; 32]>,
    }

    impl OwnerSiteAkeResponderSession {
        fn accept_m3(&mut self, harness: &OwnerSiteAkeHarness, bytes: &[u8]) -> AkeResult<()> {
            let frame = decode_frame(bytes, AkeMessageKind::M3)?;
            let mut plaintext = vec![0u8; MAX_A2_FRAME_BYTES];
            let len = self
                .handshake
                .read_message(&frame.noise, &mut plaintext)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            plaintext.truncate(len);
            let proof: ClientProof = decode_canonical(&plaintext)?;
            let device_static = self
                .handshake
                .get_remote_static()
                .ok_or(OwnerSiteAkeFailure::Rejected)
                .and_then(array_32)?;
            let authority = harness
                .authority
                .lock()
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            if !authority.is_fresh() {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            let resolved = authority.resolve(&harness.intent, &proof, self.claimed_binding_id)?;
            drop(authority);

            let binding_pre = pop_binding_pre(self.t1, device_static)?;
            let d_auth = device_auth_hash(
                binding_pre,
                resolved.binding_id(),
                resolved.binding_digest(),
                resolved.participant_npub(),
                resolved.channel_auth_key().key_id(),
            )?;
            verify_p256_signature(
                resolved.channel_auth_key().verifying_key(),
                &d_auth,
                &proof.device_signature,
            )?;
            let action = owner_action_hash(
                binding_pre,
                &self.m2,
                &self.c1.core,
                resolved.binding_id(),
                resolved.binding_digest(),
                resolved.participant_npub(),
            )?;
            verify_p256_signature(
                resolved.action_pop_key().verifying_key(),
                &action,
                &proof.action_pop,
            )?;

            let claim = OwnerSiteChallengeClaimScope::injected_for_harness(
                self.issue.clone(),
                harness.intent.clone(),
                resolved,
            )
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            harness
                .challenges
                .claim_after_verified_pop_for_harness(self.issued.id_for_harness(), &claim, A2_NOW)
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            harness
                .effects
                .challenge_claims
                .fetch_add(1, Ordering::SeqCst);
            let h_final = final_handshake_hash(&self.handshake)?;
            let channel_binding =
                channel_binding(h_final, &self.m2.channel_id, self.m2.channel_epoch)?;
            self.proof = Some(proof);
            self.h_final = Some(h_final);
            self.channel_binding = Some(channel_binding);
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u8)]
    enum AkeMessageKind {
        M1 = 1,
        M2 = 2,
        M3 = 3,
    }

    impl AkeMessageKind {
        fn from_wire(value: u8) -> AkeResult<Self> {
            match value {
                1 => Ok(Self::M1),
                2 => Ok(Self::M2),
                3 => Ok(Self::M3),
                _ => Err(OwnerSiteAkeFailure::Rejected),
            }
        }
    }

    #[derive(Deserialize, Serialize)]
    struct AkeFrame {
        version: u8,
        kind: u8,
        #[serde(with = "serde_bytes")]
        noise: Vec<u8>,
    }

    struct DecodedAkeFrame {
        noise: Vec<u8>,
    }

    #[derive(Clone, Deserialize, Serialize)]
    struct ClientHelloCore {
        domain: String,
        version: u8,
        household_id: String,
        network_id: String,
        route: String,
        resource: String,
        intent: CanonicalIntent,
        #[serde(with = "serde_bytes")]
        claimed_binding_id: Vec<u8>,
    }

    impl ClientHelloCore {
        fn from_intent(
            intent: &OwnerSiteIntent,
            binding_id: OwnerSiteBindingId,
        ) -> AkeResult<Self> {
            Ok(Self {
                domain: A2_DOMAIN.to_owned(),
                version: A2_VERSION,
                household_id: intent.household_id().to_owned(),
                network_id: intent.network_id().to_owned(),
                route: intent.request().route().to_owned(),
                resource: intent.resource().as_str().to_owned(),
                intent: CanonicalIntent {
                    method: intent.request().method().as_wire().to_owned(),
                    target: intent.request().route().to_owned(),
                    body_hash: intent.request().body_hash().to_vec(),
                },
                claimed_binding_id: binding_id.as_bytes().to_vec(),
            })
        }
    }

    #[derive(Clone, Deserialize, Serialize)]
    struct ClientHello {
        core: ClientHelloCore,
        #[serde(with = "serde_bytes")]
        device_ephemeral: Vec<u8>,
    }

    #[derive(Clone, Deserialize, Serialize)]
    struct CanonicalIntent {
        method: String,
        target: String,
        #[serde(with = "serde_bytes")]
        body_hash: Vec<u8>,
    }

    #[derive(Clone, Deserialize, Serialize)]
    struct ServerHello {
        #[serde(with = "serde_bytes")]
        engine_machine_certificate: Vec<u8>,
        engine_key_id: String,
        #[serde(with = "serde_bytes")]
        channel_id: Vec<u8>,
        channel_epoch: u64,
        #[serde(with = "serde_bytes")]
        challenge_id: Vec<u8>,
        #[serde(with = "serde_bytes")]
        challenge_secret: Vec<u8>,
        authz_epoch: u64,
        #[serde(with = "serde_bytes")]
        roster_digest: Vec<u8>,
        fresh_until: u64,
        #[serde(with = "serde_bytes")]
        engine_signature: Vec<u8>,
    }

    #[derive(Clone, Deserialize, Serialize)]
    struct ClientProof {
        #[serde(with = "serde_bytes")]
        binding_id: Vec<u8>,
        #[serde(with = "serde_bytes")]
        binding_digest: Vec<u8>,
        participant_npub: String,
        channel_auth_key_id: String,
        action_pop_key_id: String,
        #[serde(with = "serde_bytes")]
        device_signature: Vec<u8>,
        #[serde(with = "serde_bytes")]
        action_pop: Vec<u8>,
    }

    // Every transcript is a fixed-arity CBOR array.  Nested protocol objects
    // enter the array only as bstr(canonical-CBOR(X)); none is structurally
    // re-embedded into a signing hash.
    #[derive(Serialize)]
    struct ServerAuthTranscript<'a>(
        &'a str,
        &'a str,
        #[serde(with = "serde_bytes")] &'a [u8],
        #[serde(with = "serde_bytes")] &'a [u8],
        #[serde(with = "serde_bytes")] &'a [u8],
        #[serde(with = "serde_bytes")] &'a [u8],
        &'a str,
        #[serde(with = "serde_bytes")] &'a [u8],
        u64,
        #[serde(with = "serde_bytes")] &'a [u8],
        #[serde(with = "serde_bytes")] &'a [u8],
        u64,
        #[serde(with = "serde_bytes")] &'a [u8],
        u64,
    );

    #[derive(Serialize)]
    struct PopBindingTranscript<'a>(
        &'a str,
        &'a str,
        #[serde(with = "serde_bytes")] &'a [u8],
        #[serde(with = "serde_bytes")] &'a [u8],
    );

    #[derive(Serialize)]
    struct DeviceAuthTranscript<'a>(
        &'a str,
        &'a str,
        #[serde(with = "serde_bytes")] &'a [u8],
        #[serde(with = "serde_bytes")] &'a [u8],
        #[serde(with = "serde_bytes")] &'a [u8],
        &'a str,
        &'a str,
    );

    #[derive(Serialize)]
    struct OwnerActionTranscript<'a>(
        &'a str,
        &'a str,
        #[serde(with = "serde_bytes")] &'a [u8],
        #[serde(with = "serde_bytes")] &'a [u8],
        u64,
        #[serde(with = "serde_bytes")] &'a [u8],
        #[serde(with = "serde_bytes")] &'a [u8],
        &'a str,
        &'a str,
        &'a str,
        #[serde(with = "serde_bytes")] &'a [u8],
        #[serde(with = "serde_bytes")] &'a [u8],
        &'a str,
        &'a str,
        &'a str,
        #[serde(with = "serde_bytes")] &'a [u8],
        u64,
        #[serde(with = "serde_bytes")] &'a [u8],
        u64,
    );

    #[derive(Serialize)]
    struct ChannelBindingTranscript<'a>(
        &'a str,
        &'a str,
        u8,
        &'a str,
        &'a str,
        #[serde(with = "serde_bytes")] &'a [u8],
        #[serde(with = "serde_bytes")] &'a [u8],
        u64,
    );

    fn encode_frame(kind: AkeMessageKind, noise: Vec<u8>) -> AkeResult<Vec<u8>> {
        if noise.is_empty() || noise.len() > MAX_A2_FRAME_BYTES {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        encode_canonical(&AkeFrame {
            version: A2_VERSION,
            kind: kind as u8,
            noise,
        })
    }

    fn decode_frame(bytes: &[u8], expected: AkeMessageKind) -> AkeResult<DecodedAkeFrame> {
        if bytes.is_empty() || bytes.len() > MAX_A2_FRAME_BYTES {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        let frame: AkeFrame = decode_canonical(bytes)?;
        if frame.version != A2_VERSION
            || AkeMessageKind::from_wire(frame.kind)? != expected
            || frame.noise.is_empty()
            || frame.noise.len() > MAX_A2_FRAME_BYTES
        {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        Ok(DecodedAkeFrame { noise: frame.noise })
    }

    fn encode_canonical<T: Serialize>(value: &T) -> AkeResult<Vec<u8>> {
        cbor::to_canonical_vec(value).map_err(|_| OwnerSiteAkeFailure::Rejected)
    }

    fn decode_canonical<T>(bytes: &[u8]) -> AkeResult<T>
    where
        T: DeserializeOwned + Serialize,
    {
        let decoded =
            cbor::from_canonical_slice(bytes).map_err(|_| OwnerSiteAkeFailure::Rejected)?;
        if encode_canonical(&decoded)? != bytes {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        Ok(decoded)
    }

    fn noise_params() -> AkeResult<NoiseParams> {
        Ok(NoiseParams::new(
            A2_NOISE_PROTOCOL_NAME.to_owned(),
            BaseChoice::Noise,
            HandshakeChoice {
                pattern: HandshakePattern::XX,
                modifiers: HandshakeModifierList { list: Vec::new() },
            },
            DHChoice::Curve25519,
            CipherChoice::ChaChaPoly,
            HashChoice::SHA256,
        ))
    }

    fn a2_noise_prologue() -> AkeResult<Vec<u8>> {
        encode_canonical(&(
            A2_DOMAIN,
            A2_NOISE_PROLOGUE_LABEL,
            A2_VERSION,
            A2_RECORD_PROFILE,
            A2_NOISE_PROTOCOL_NAME,
        ))
    }

    fn a2_noise_builder<'a>(prologue: &'a [u8]) -> AkeResult<Builder<'a>> {
        Builder::new(noise_params()?)
            .prologue(prologue)
            .map_err(|_| OwnerSiteAkeFailure::Rejected)
    }

    fn new_noise_initiator() -> AkeResult<(HandshakeState, [u8; NOISE_PUBLIC_KEY_BYTES])> {
        let prologue = a2_noise_prologue()?;
        let builder = a2_noise_builder(&prologue)?;
        let mut keypair = builder
            .generate_keypair()
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
        let public = array_32(&keypair.public)?;
        let handshake = builder
            .local_private_key(&keypair.private)
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?
            .build_initiator()
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
        keypair.private.zeroize();
        Ok((handshake, public))
    }

    fn new_noise_static_keypair() -> AkeResult<(Zeroizing<Vec<u8>>, [u8; NOISE_PUBLIC_KEY_BYTES])> {
        let builder = Builder::new(noise_params()?);
        let mut keypair = builder
            .generate_keypair()
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
        let public = array_32(&keypair.public)?;
        let private = Zeroizing::new(std::mem::take(&mut keypair.private));
        keypair.private.zeroize();
        Ok((private, public))
    }

    /// This module is compiled only into crate tests while no production A2
    /// provider exists.  The ephemeral private key is generated from `OsRng`
    /// for each channel; Snow owns all XX DH/AEAD processing.
    fn responder_with_channel_keys(
        static_private: &[u8],
        ephemeral_private: &[u8],
    ) -> AkeResult<HandshakeState> {
        let prologue = a2_noise_prologue()?;
        a2_noise_builder(&prologue)?
            .local_private_key(static_private)
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?
            .fixed_ephemeral_key_for_testing_only(ephemeral_private)
            .build_responder()
            .map_err(|_| OwnerSiteAkeFailure::Rejected)
    }

    fn noise_public_prefix(noise: &[u8]) -> AkeResult<[u8; NOISE_PUBLIC_KEY_BYTES]> {
        array_32(
            noise
                .get(..NOISE_PUBLIC_KEY_BYTES)
                .ok_or(OwnerSiteAkeFailure::Rejected)?,
        )
    }

    fn array_32(bytes: &[u8]) -> AkeResult<[u8; 32]> {
        bytes.try_into().map_err(|_| OwnerSiteAkeFailure::Rejected)
    }

    fn binding_id(bytes: &[u8]) -> AkeResult<OwnerSiteBindingId> {
        OwnerSiteBindingId::injected_for_harness(array_32(bytes)?)
            .map_err(|_| OwnerSiteAkeFailure::Rejected)
    }

    fn binding_digest(bytes: &[u8]) -> AkeResult<OwnerSiteBindingDigest> {
        OwnerSiteBindingDigest::injected_for_harness(array_32(bytes)?)
            .map_err(|_| OwnerSiteAkeFailure::Rejected)
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn final_handshake_hash(handshake: &HandshakeState) -> AkeResult<[u8; 32]> {
        if !handshake.is_handshake_finished() {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        array_32(handshake.get_handshake_hash())
    }

    fn channel_binding(
        h_final: [u8; 32],
        channel_id: &[u8],
        channel_epoch: u64,
    ) -> AkeResult<[u8; 32]> {
        if channel_id.len() != OWNER_SITE_CHALLENGE_BYTES || channel_epoch == 0 {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        hash_canonical(&ChannelBindingTranscript(
            A2_DOMAIN,
            A2_CHANNEL_BINDING_LABEL,
            A2_VERSION,
            A2_RECORD_PROFILE,
            A2_NOISE_PROTOCOL_NAME,
            &h_final,
            channel_id,
            channel_epoch,
        ))
    }

    fn random_32() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    fn sign_p256(key: &P256Keypair, digest: &[u8; 32]) -> AkeResult<Vec<u8>> {
        key.sign(digest)
            .map(|signature| signature.as_bytes().to_vec())
            .map_err(|_| OwnerSiteAkeFailure::Rejected)
    }

    fn verify_p256_signature(key: &P256PublicKey, digest: &[u8; 32], raw: &[u8]) -> AkeResult<()> {
        if raw.len() != P256_SIGNATURE_BYTES {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        let signature =
            P256Signature::from_bytes(raw).map_err(|_| OwnerSiteAkeFailure::Rejected)?;
        verify_signature(key, digest, &signature).map_err(|_| OwnerSiteAkeFailure::Rejected)
    }

    fn validate_server_hello_lengths(m2: &ServerHello) -> AkeResult<()> {
        if m2.channel_id.len() != OWNER_SITE_CHALLENGE_BYTES
            || m2.challenge_id.len() != OWNER_SITE_CHALLENGE_BYTES
            || m2.challenge_secret.len() != OWNER_SITE_CHALLENGE_BYTES
            || m2.roster_digest.len() != 32
            || m2.channel_epoch == 0
            || m2.authz_epoch == 0
            || m2.fresh_until <= A2_NOW
        {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        Ok(())
    }

    fn server_auth_t1(
        c1: &ClientHello,
        engine_ephemeral: [u8; 32],
        engine_static: [u8; 32],
        machine_certificate_digest: [u8; 32],
        m2: &ServerHello,
    ) -> AkeResult<[u8; 32]> {
        validate_server_hello_lengths(m2)?;
        let c1_wire = encode_canonical(c1)?;
        hash_canonical(&ServerAuthTranscript(
            A2_DOMAIN,
            "server-auth",
            &c1_wire,
            &engine_ephemeral,
            &engine_static,
            &machine_certificate_digest,
            &m2.engine_key_id,
            &m2.channel_id,
            m2.channel_epoch,
            &m2.challenge_id,
            &m2.challenge_secret,
            m2.authz_epoch,
            &m2.roster_digest,
            m2.fresh_until,
        ))
    }

    fn pop_binding_pre(t1: [u8; 32], device_static: [u8; 32]) -> AkeResult<[u8; 32]> {
        hash_canonical(&PopBindingTranscript(
            A2_DOMAIN,
            "pop-binding",
            &t1,
            &device_static,
        ))
    }

    fn device_auth_hash(
        channel_binding_pre: [u8; 32],
        binding_id: OwnerSiteBindingId,
        binding_digest: OwnerSiteBindingDigest,
        participant_npub: &str,
        channel_auth_key_id: &OwnerSiteChannelAuthKeyId,
    ) -> AkeResult<[u8; 32]> {
        hash_canonical(&DeviceAuthTranscript(
            A2_DOMAIN,
            "D-auth",
            &channel_binding_pre,
            binding_id.as_bytes(),
            binding_digest.as_bytes(),
            participant_npub,
            channel_auth_key_id.as_str(),
        ))
    }

    fn owner_action_hash(
        channel_binding_pre: [u8; 32],
        m2: &ServerHello,
        c1: &ClientHelloCore,
        binding_id: OwnerSiteBindingId,
        binding_digest: OwnerSiteBindingDigest,
        participant_npub: &str,
    ) -> AkeResult<[u8; 32]> {
        let intent_wire = encode_canonical(&c1.intent)?;
        hash_canonical(&OwnerActionTranscript(
            A2_DOMAIN,
            "owner-action",
            &channel_binding_pre,
            &m2.channel_id,
            m2.channel_epoch,
            &m2.challenge_id,
            &m2.challenge_secret,
            &c1.household_id,
            &c1.network_id,
            &m2.engine_key_id,
            binding_id.as_bytes(),
            binding_digest.as_bytes(),
            participant_npub,
            &c1.route,
            &c1.resource,
            &intent_wire,
            m2.authz_epoch,
            &m2.roster_digest,
            m2.fresh_until,
        ))
    }

    fn hash_canonical<T: Serialize>(value: &T) -> AkeResult<[u8; 32]> {
        Ok(sha256(&encode_canonical(value)?))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn fixture() -> OwnerSiteAkeFixture {
            OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("typed A2 fixture")
        }

        #[test]
        fn xx_shaped_m1_m2_m3_validates_only_to_pending_finished() {
            let fixture = fixture();
            let harness = fixture
                .provider
                .harness_for_test()
                .expect("test harness provider");
            let (mut client, m1) = fixture.client.start().expect("M1");
            let (mut server, m2) = harness.begin_m1(&harness.resource, &m1).expect("M2");
            let m3 = client.accept_m2_and_make_m3(&m2).expect("M3");

            assert_eq!(server.accept_m3(&harness, &m3), Ok(()));
            assert!(harness.recheck_after_claim(&server));
            assert_eq!(fixture.client.action_pop_signature_count(), 1);
            assert_eq!(client.h_final, server.h_final);
            assert_eq!(client.channel_binding, server.channel_binding);
            assert!(server.h_final.is_some());
            assert!(server.channel_binding.is_some());
            assert_eq!(
                fixture.effects.snapshot(),
                OwnerSiteAkeEffectSnapshot {
                    sessions_started: 0,
                    challenge_issues: 1,
                    challenge_claims: 1,
                    validated_pending_finished: 0,
                    verified_peers: 0,
                    mints: 0,
                    consumes: 0,
                    proxy_dials: 0,
                    site_bytes: 0,
                }
            );
            assert!(server.handshake.is_handshake_finished());
        }

        #[test]
        fn a2_r1_pretransport_kat_matches_normative_noise_and_binding_bytes() {
            const P_A2_HEX: &str = "8577736f796568742f6f776e65722d736974652f61322f76316e6e6f6973652d70726f6c6f677565016c61322d7265636f72642d763178244e6f6973655f5858613276315f32353531395f436861436861506f6c795f534841323536";
            const M1_NOISE_HEX: &str = "052a50773ac8d91773f2dc9662e12f0defe915e415b8a1c8e20a5a3d6ab2b8438377736f796568742f6f776e65722d736974652f61322f7631016a666978747572652d6d31";
            const M2_NOISE_HEX: &str = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20cba67692feaaaa374507da9dbdc7300a30fc44f6eaa630956e9c8484be9e98f4ddc176bcfbe2234bf522b19a9273392ca5e63e223895bcd36e89a116d98c933030a7d83465e13bea9663c2f834809b69aeabefd469568a7deb99fb95d3af93f8c70c3a2d9b";
            const M3_NOISE_HEX: &str = "a1a85eacaa43f76774868e50e96ee8274a6d396adc86e6bf8f2a107f376d2daea8097fdbaf77e360bbceeaa7a3925a729a964f79e8f37079e8b8407ac849fe5b349774fcac9af8636b66c6f1756ec3e9dc5ea354bd16434650c649c45992dc2f1bdd49b61c";
            const H_FINAL_HEX: &str =
                "eddd205a011fe812db52153cf09ab4bb3c7d607a3ae68008fd453494abf8b722";
            const CHANNEL_BINDING_HEX: &str =
                "5ed521ad95402b2b0ee18f13a8035f1800afe84184d70529e63780fc67cbe13f";
            const PROTOCOL_NAME_HEX: &str =
                "4e6f6973655f5858613276315f32353531395f436861436861506f6c795f534841323536";

            let params = noise_params().expect("fixed A2-R1 Noise parameters");
            assert_eq!(params.name, A2_NOISE_PROTOCOL_NAME);
            assert_eq!(hex::encode(A2_NOISE_PROTOCOL_NAME), PROTOCOL_NAME_HEX);
            let prologue = a2_noise_prologue().expect("canonical P_A2");
            assert_eq!(hex::encode(&prologue), P_A2_HEX);

            let mut device = a2_noise_builder(&prologue)
                .expect("device A2-R1 builder")
                .local_private_key(&[0x11; 32])
                .expect("device static")
                .fixed_ephemeral_key_for_testing_only(&[0x12; 32])
                .build_initiator()
                .expect("device initiator");
            let mut engine = a2_noise_builder(&prologue)
                .expect("engine A2-R1 builder")
                .local_private_key(&[0x21; 32])
                .expect("engine static")
                .fixed_ephemeral_key_for_testing_only(&[0x22; 32])
                .build_responder()
                .expect("engine responder");

            let m1_payload = encode_canonical(&(A2_DOMAIN, A2_VERSION, "fixture-m1"))
                .expect("canonical M1 fixture payload");
            let m2_payload = encode_canonical(&(A2_DOMAIN, A2_VERSION, "fixture-m2"))
                .expect("canonical M2 fixture payload");
            let m3_payload = encode_canonical(&(A2_DOMAIN, A2_VERSION, "fixture-m3"))
                .expect("canonical M3 fixture payload");

            let mut m1 = vec![0u8; MAX_A2_FRAME_BYTES];
            let m1_len = device
                .write_message(&m1_payload, &mut m1)
                .expect("M1 Noise write");
            m1.truncate(m1_len);
            assert_eq!(hex::encode(&m1), M1_NOISE_HEX);
            let mut plaintext = vec![0u8; MAX_A2_FRAME_BYTES];
            let m1_plaintext = engine
                .read_message(&m1, &mut plaintext)
                .expect("M1 Noise read");
            assert_eq!(&plaintext[..m1_plaintext], m1_payload);

            let mut m2 = vec![0u8; MAX_A2_FRAME_BYTES];
            let m2_len = engine
                .write_message(&m2_payload, &mut m2)
                .expect("M2 Noise write");
            m2.truncate(m2_len);
            assert_eq!(hex::encode(&m2), M2_NOISE_HEX);
            let m2_plaintext = device
                .read_message(&m2, &mut plaintext)
                .expect("M2 Noise read");
            assert_eq!(&plaintext[..m2_plaintext], m2_payload);

            let mut m3 = vec![0u8; MAX_A2_FRAME_BYTES];
            let m3_len = device
                .write_message(&m3_payload, &mut m3)
                .expect("M3 Noise write");
            m3.truncate(m3_len);
            assert_eq!(hex::encode(&m3), M3_NOISE_HEX);
            let m3_plaintext = engine
                .read_message(&m3, &mut plaintext)
                .expect("M3 Noise read");
            assert_eq!(&plaintext[..m3_plaintext], m3_payload);

            assert!(device.is_handshake_finished());
            assert!(engine.is_handshake_finished());
            let h_final_device = final_handshake_hash(&device).expect("device H_final");
            let h_final_engine = final_handshake_hash(&engine).expect("engine H_final");
            assert_eq!(h_final_device, h_final_engine);
            assert_eq!(hex::encode(h_final_device), H_FINAL_HEX);
            let channel_binding =
                channel_binding(h_final_engine, &[0x10; 32], 7).expect("A2 channel binding");
            assert_eq!(hex::encode(channel_binding), CHANNEL_BINDING_HEX);
        }

        #[test]
        fn a2_r1_prologue_swap_fails_before_an_authenticated_m3() {
            let prologue = a2_noise_prologue().expect("canonical P_A2");
            let mut altered_prologue = prologue.clone();
            altered_prologue[0] ^= 1;
            let mut device = a2_noise_builder(&prologue)
                .expect("device builder")
                .local_private_key(&[0x11; 32])
                .expect("device static")
                .fixed_ephemeral_key_for_testing_only(&[0x12; 32])
                .build_initiator()
                .expect("device initiator");
            let mut wrong_engine = a2_noise_builder(&altered_prologue)
                .expect("wrong-prologue builder")
                .local_private_key(&[0x21; 32])
                .expect("engine static")
                .fixed_ephemeral_key_for_testing_only(&[0x22; 32])
                .build_responder()
                .expect("engine responder");
            let payload = encode_canonical(&(A2_DOMAIN, A2_VERSION, "fixture-m1"))
                .expect("canonical payload");
            let mut m1 = vec![0u8; MAX_A2_FRAME_BYTES];
            let m1_len = device.write_message(&payload, &mut m1).expect("M1 write");
            m1.truncate(m1_len);
            let mut plaintext = vec![0u8; MAX_A2_FRAME_BYTES];
            assert!(wrong_engine.read_message(&m1, &mut plaintext).is_ok());
            let mut m2 = vec![0u8; MAX_A2_FRAME_BYTES];
            let m2_len = wrong_engine.write_message(&[], &mut m2).expect("M2 write");
            m2.truncate(m2_len);
            assert!(
                device.read_message(&m2, &mut plaintext).is_err(),
                "the fixed P_A2 must be mixed before an authenticated M2"
            );
        }

        #[test]
        fn a2_r1_profile_name_swap_fails_before_an_authenticated_m3() {
            let prologue = a2_noise_prologue().expect("canonical P_A2");
            let mut device = a2_noise_builder(&prologue)
                .expect("device builder")
                .local_private_key(&[0x11; 32])
                .expect("device static")
                .fixed_ephemeral_key_for_testing_only(&[0x12; 32])
                .build_initiator()
                .expect("device initiator");
            let wrong_params = NoiseParams::new(
                "Noise_XXa2v0_25519_ChaChaPoly_SHA256".to_owned(),
                BaseChoice::Noise,
                HandshakeChoice {
                    pattern: HandshakePattern::XX,
                    modifiers: HandshakeModifierList { list: Vec::new() },
                },
                DHChoice::Curve25519,
                CipherChoice::ChaChaPoly,
                HashChoice::SHA256,
            );
            let mut wrong_engine = Builder::new(wrong_params)
                .prologue(&prologue)
                .expect("wrong-profile prologue")
                .local_private_key(&[0x21; 32])
                .expect("engine static")
                .fixed_ephemeral_key_for_testing_only(&[0x22; 32])
                .build_responder()
                .expect("engine responder");
            let payload = encode_canonical(&(A2_DOMAIN, A2_VERSION, "fixture-m1"))
                .expect("canonical payload");
            let mut m1 = vec![0u8; MAX_A2_FRAME_BYTES];
            let m1_len = device.write_message(&payload, &mut m1).expect("M1 write");
            m1.truncate(m1_len);
            let mut plaintext = vec![0u8; MAX_A2_FRAME_BYTES];
            assert!(wrong_engine.read_message(&m1, &mut plaintext).is_ok());
            let mut m2 = vec![0u8; MAX_A2_FRAME_BYTES];
            let m2_len = wrong_engine.write_message(&[], &mut m2).expect("M2 write");
            m2.truncate(m2_len);
            assert!(
                device.read_message(&m2, &mut plaintext).is_err(),
                "the fixed A2-R1 protocol name must be mixed before an authenticated M2"
            );
        }

        #[test]
        fn transcript_swap_and_replay_fail_before_a_second_claim() {
            let first = fixture();
            let first_harness = first.provider.harness_for_test().expect("first harness");
            let (mut first_client, m1) = first.client.start().expect("M1");
            let (mut first_server, m2) = first_harness
                .begin_m1(&first_harness.resource, &m1)
                .expect("M2");
            let m3 = first_client.accept_m2_and_make_m3(&m2).expect("M3");

            let (_second_client, second_m1) = first.client.start().expect("second M1");
            let (mut second_server, _) = first_harness
                .begin_m1(&first_harness.resource, &second_m1)
                .expect("independent M2");
            assert_eq!(
                second_server.accept_m3(&first_harness, &m3),
                Err(OwnerSiteAkeFailure::Rejected),
                "a C2 bound to the first T1 cannot be replayed into another channel"
            );
            assert_eq!(first.effects.snapshot().challenge_claims, 0);

            assert_eq!(first_server.accept_m3(&first_harness, &m3), Ok(()));
            assert_eq!(
                first_server.accept_m3(&first_harness, &m3),
                Err(OwnerSiteAkeFailure::Rejected),
                "the same M3 cannot claim a consumed one-shot challenge twice"
            );
            assert_eq!(first.effects.snapshot().challenge_claims, 1);
        }

        #[test]
        fn wrong_household_anchor_is_rejected_before_device_action_pop() {
            let fixture = fixture();
            let harness = fixture
                .provider
                .harness_for_test()
                .expect("test harness provider");
            let (mut client, m1) = fixture.client.start().expect("M1");
            let (_, m2) = harness.begin_m1(&harness.resource, &m1).expect("M2");
            client.expected_household_key = P256Keypair::generate().public();

            assert_eq!(
                client.accept_m2_and_make_m3(&m2),
                Err(OwnerSiteAkeFailure::Rejected)
            );
            assert_eq!(fixture.client.action_pop_signature_count(), 0);
            assert_eq!(fixture.effects.snapshot().challenge_claims, 0);
        }

        #[test]
        fn route_resource_or_body_swap_is_rejected_before_challenge_issue() {
            let fixture = fixture();
            let harness = fixture
                .provider
                .harness_for_test()
                .expect("test harness provider");

            let mut wrong_route =
                ClientHelloCore::from_intent(&fixture.client.intent, fixture.client.binding_id)
                    .expect("core");
            wrong_route.route = "/api/v1/household/claws/other/owner-site/ake".to_owned();
            let (_, m1) = fixture.client.start_with_core(wrong_route).expect("M1");
            assert!(harness.begin_m1(&harness.resource, &m1).is_err());

            let mut wrong_resource =
                ClientHelloCore::from_intent(&fixture.client.intent, fixture.client.binding_id)
                    .expect("core");
            wrong_resource.resource = "otherclaw".to_owned();
            let (_, m1) = fixture.client.start_with_core(wrong_resource).expect("M1");
            assert!(harness.begin_m1(&harness.resource, &m1).is_err());

            let mut wrong_body =
                ClientHelloCore::from_intent(&fixture.client.intent, fixture.client.binding_id)
                    .expect("core");
            wrong_body.intent.body_hash = vec![0x99; 32];
            let (_, m1) = fixture.client.start_with_core(wrong_body).expect("M1");
            assert!(harness.begin_m1(&harness.resource, &m1).is_err());
            assert_eq!(fixture.effects.snapshot().challenge_issues, 0);
        }

        #[test]
        fn relay_forwarding_splices_only_ake_frames_and_gets_no_success_or_site_bytes() {
            let fixture = fixture();
            let harness = fixture
                .provider
                .harness_for_test()
                .expect("test harness provider");

            // Carrier M forwards the exact three messages but has neither a
            // signing key nor a transport key. M1 necessarily names the
            // requested resource; the M2/M3 payloads are Noise protected.
            let (mut device, m1_from_device) = fixture.client.start().expect("M1");
            let carrier_m1 = m1_from_device.clone();
            let (mut engine, m2_to_carrier) = harness
                .begin_m1(&harness.resource, &carrier_m1)
                .expect("M2 for the same WS");
            assert!(!contains_bytes(&m2_to_carrier, b"npub1owneralpha"));
            assert!(!contains_bytes(&m2_to_carrier, b"challenge_secret"));

            let m3_from_device = device
                .accept_m2_and_make_m3(&m2_to_carrier)
                .expect("M3 only after device accepts E's household certificate");
            let carrier_m3 = m3_from_device.clone();
            assert!(!contains_bytes(&carrier_m3, b"npub1owneralpha"));
            assert!(!contains_bytes(&carrier_m3, b"owner-action"));

            assert_eq!(engine.accept_m3(&harness, &carrier_m3), Ok(()));
            assert!(harness.recheck_after_claim(&engine));

            // There is deliberately no fourth message in this slice: a
            // splicing carrier obtains no plaintext success, credential,
            // verified peer, or site byte before the reviewed record layer.
            let effects = fixture.effects.snapshot();
            assert_eq!(effects.challenge_claims, 1);
            assert_eq!(effects.validated_pending_finished, 0);
            assert_eq!(effects.verified_peers, 0);
            assert_eq!(effects.mints, 0);
            assert_eq!(effects.consumes, 0);
            assert_eq!(effects.proxy_dials, 0);
            assert_eq!(effects.site_bytes, 0);
        }

        #[test]
        fn tombstone_after_consume_burns_challenge_without_a_peer() {
            let fixture = fixture();
            let harness = fixture
                .provider
                .harness_for_test()
                .expect("test harness provider");
            let (mut client, m1) = fixture.client.start().expect("M1");
            let (mut server, m2) = harness.begin_m1(&harness.resource, &m1).expect("M2");
            let m3 = client.accept_m2_and_make_m3(&m2).expect("M3");
            assert_eq!(server.accept_m3(&harness, &m3), Ok(()));
            // Replace the injected authority with a fresh epoch carrying a
            // tombstone for this exact binding between consume and re-read.
            harness.revoke_before_recheck_for_harness();
            assert!(!harness.recheck_after_claim(&server));
            let effects = fixture.effects.snapshot();
            assert_eq!(effects.challenge_claims, 1);
            assert_eq!(effects.validated_pending_finished, 0);
            assert_eq!(effects.verified_peers, 0);
            assert_eq!(effects.mints, 0);
            assert_eq!(effects.consumes, 0);
            assert_eq!(effects.proxy_dials, 0);
            assert_eq!(effects.site_bytes, 0);
        }

        fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
            haystack
                .windows(needle.len())
                .any(|window| window == needle)
        }
    }
}

#[cfg(test)]
pub(crate) use harness::{OwnerSiteAkeEffectSnapshot, OwnerSiteAkeFixture, OwnerSiteAkeHarness};
