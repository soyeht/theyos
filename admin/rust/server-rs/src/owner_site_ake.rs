//! Owner-site A2 handshake and test-only record-confirmation seam.
//!
//! The route which reaches this module is intentionally fail-closed in a
//! production process: no reviewed machine/roster provider is installed yet.
//! The only admitting provider is a crate-test harness.  That lets this slice
//! exercise the reviewed A2 wire and ordering without turning a socket address,
//! a CIDR, or an HTTP header into a remote principal.  The harness can also
//! exercise the A2-R1 S2/C3 record confirmation, but it still closes before
//! any peer, dial, proxy, or site-byte effect exists.
//!
//! Production remains fail-closed because it has no admitting provider.  In
//! particular, this module must never substitute a plaintext success response
//! for A2-R1's encrypted record confirmation, nor manufacture a
//! `VerifiedMeshPeer`, backend dial, proxy, or site bytes.

use std::net::SocketAddr;

use axum::extract::ws::WebSocket;
use futures_util::SinkExt;

use crate::owner_site_capability::OwnerSiteResource;

/// Maximum canonical A2-R1 record envelope accepted by the WebSocket boundary.
///
/// The envelope is `canonical-CBOR([1, ciphertext])`, where ciphertext is at
/// most 16,384 bytes including the Noise `ChaChaPoly` tag.
pub(crate) const OWNER_SITE_AKE_MAX_RECORD_ENVELOPE_BYTES: usize = 16_389;

/// Provider seam for the one-WebSocket A2 handshake.
///
/// S2 PAIR-1 PROMOTION — declaration (counted criterion, 1 of 2 real pairs):
/// * *Before:* `#[cfg(not(test))]` returned `false` unconditionally — a layer
///   that does nothing rejects everything perfectly.
/// * *After:* the `cfg(not(test))` block is **deleted, deliberately** — not
///   as a side effect of lifting test code. Production now evaluates the
///   shared roster arm, and with `roster: None` (nothing installed) that
///   evaluates to `false`: **the old production behavior is preserved
///   exactly until the startup install lands.** The only cfg fork left is
///   the harness early-return, additions-only.
/// * *Why this arm may change:* S2 installs the first production provider
///   (the startup install is its own named increment; this commit lands the
///   arm and the shape, still unreachable from production wiring).
/// * The roster arm holds NO address-derived input: identity facts only —
///   the server-owned resource and the observation produced by
///   `owner_site_roster_adapter` (co-possession authority; see its
///   five-element declaration).
#[derive(Clone)]
pub(crate) struct OwnerSiteAkeProvider {
    #[cfg(test)]
    harness: Option<std::sync::Arc<OwnerSiteAkeHarness>>,
    roster: Option<OwnerSiteRosterArm>,
}

/// The production arm's roster-backed admission state: which resources this
/// provider serves (the admitted claw set, by name), and the latest
/// observation the adapter produced. The observation arrives through a
/// refresh loop (the roster coordinator does blocking file I/O, so it never
/// runs inline in an admission check).
#[derive(Clone)]
pub(crate) struct OwnerSiteRosterArm {
    admitted: std::sync::Arc<std::sync::RwLock<std::collections::BTreeSet<String>>>,
    latest: std::sync::Arc<
        std::sync::RwLock<Option<crate::owner_site_authority::OwnerSiteAuthorityObservation>>,
    >,
}

// Consumed by the refresh loop when the startup install lands (named
// increment); the allows come off then — same pattern as
// OwnerSitePromotionWitness.
#[allow(dead_code)]
impl OwnerSiteRosterArm {
    /// Single-resource arm (the pair-1 shape): a set of one.
    #[must_use]
    pub(crate) fn new(resource: &OwnerSiteResource) -> Self {
        Self::with_admitted([resource.as_str().to_string()])
    }

    /// The admitted set is COARSE gating only — "is this claw served at
    /// all". The EXACT binding check is downstream (pair 2), so a claw name
    /// present here never implies admission of any intent against it.
    #[must_use]
    pub(crate) fn with_admitted(names: impl IntoIterator<Item = String>) -> Self {
        Self {
            admitted: std::sync::Arc::new(std::sync::RwLock::new(names.into_iter().collect())),
            latest: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Handle for the refresh loop: replace the latest observation. The loop
    /// replaces on success and leaves the previous value in place on failure
    /// — a roster that goes dark does NOT clear a previously good
    /// observation; admission freshness lives inside `observe()` itself
    /// (the coordinator rejects stale checkpoints at query time).
    #[must_use]
    pub(crate) fn observation_slot(
        &self,
    ) -> std::sync::Arc<
        std::sync::RwLock<Option<crate::owner_site_authority::OwnerSiteAuthorityObservation>>,
    > {
        std::sync::Arc::clone(&self.latest)
    }

    #[must_use]
    fn admits(&self, resource: &OwnerSiteResource) -> bool {
        let in_set = self
            .admitted
            .read()
            .map(|set| set.contains(resource.as_str()))
            .unwrap_or(false);
        if !in_set {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);
        self.latest
            .read()
            .map(|guard| {
                guard
                    .as_ref()
                    .is_some_and(|observation| observation.is_fresh_at(now))
            })
            .unwrap_or(false)
    }
}

impl OwnerSiteAkeProvider {
    /// Tests are the only current source of an admitting A2 provider.  The
    /// production router never installs this extension.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn injected_for_harness(harness: OwnerSiteAkeHarness) -> Self {
        Self {
            harness: Some(std::sync::Arc::new(harness)),
            roster: None,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn harness_for_test(&self) -> Option<std::sync::Arc<OwnerSiteAkeHarness>> {
        self.harness.clone()
    }

    /// The first production-shaped provider: roster-backed, no address
    /// inputs. Still NOT installed by any production wiring — the startup
    /// install is a separate named increment.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn for_roster(resource: &OwnerSiteResource) -> Self {
        Self {
            #[cfg(test)]
            harness: None,
            roster: Some(OwnerSiteRosterArm::new(resource)),
        }
    }

    /// The production install shape: one provider serving the admitted claw
    /// set (coarse gate; exact binding checks are downstream).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn for_roster_set(names: impl IntoIterator<Item = String>) -> Self {
        Self {
            #[cfg(test)]
            harness: None,
            roster: Some(OwnerSiteRosterArm::with_admitted(names)),
        }
    }

    /// The roster arm, for the refresh loop to feed (and for tests to
    /// observe). `None` for the harness provider.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn roster_arm(&self) -> Option<&OwnerSiteRosterArm> {
        self.roster.as_ref()
    }

    /// Checks the server-owned resource before accepting a WebSocket upgrade.
    #[must_use]
    pub(crate) fn admits_resource(&self, resource: &OwnerSiteResource) -> bool {
        #[cfg(test)]
        {
            if let Some(harness) = &self.harness {
                return harness.admits_resource(resource);
            }
        }
        self.roster.as_ref().is_some_and(|arm| arm.admits(resource))
    }

    /// Drives the test-only A2 handshake and S2/C3 confirmation on one WebSocket.
    ///
    /// The post-C3 result remains intentionally silent and ephemeral until a
    /// later reviewed peer-promotion and dial slice exists.
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

    use crate::owner_site_a2_wire::{
        CanonicalIntent, ClientHello, ClientHelloCore, ClientProof, ServerHello,
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
        Builder, HandshakeState, TransportState,
        params::{
            BaseChoice, CipherChoice, DHChoice, HandshakeChoice, HandshakeModifierList,
            HandshakePattern, HashChoice, NoiseParams,
        },
    };
    use tokio::{
        sync::Notify,
        time::{Duration, Instant, timeout},
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
    const MAX_A2_RECORD_CIPHERTEXT_BYTES: usize = 16_384;
    const MAX_A2_RECORD_PLAINTEXT_BYTES: usize = 16_368;
    const MAX_A2_RECORD_ENVELOPE_BYTES: usize = super::OWNER_SITE_AKE_MAX_RECORD_ENVELOPE_BYTES;
    const A2_RECORD_ENVELOPE_VERSION: u8 = 1;
    const A2_RECORD_KIND_S2: u8 = 1;
    const A2_RECORD_KIND_C3: u8 = 2;
    const A2_DIRECTION_DEVICE_TO_ENGINE: u8 = 0;
    const A2_DIRECTION_ENGINE_TO_DEVICE: u8 = 1;
    const A2_HARNESS_WS_STEP_TIMEOUT: Duration = Duration::from_secs(1);
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
        post_claim_recheck_rejections: AtomicUsize,
        s2_records_emitted: AtomicUsize,
        c3_records_accepted: AtomicUsize,
        post_c3_recheck_rejections: AtomicUsize,
        completed_m3_closures: AtomicUsize,
        verified_peers: AtomicUsize,
        dial_permits_issued: AtomicUsize,
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
        pub(crate) post_claim_recheck_rejections: usize,
        pub(crate) s2_records_emitted: usize,
        pub(crate) c3_records_accepted: usize,
        pub(crate) post_c3_recheck_rejections: usize,
        pub(crate) completed_m3_closures: usize,
        pub(crate) verified_peers: usize,
        pub(crate) dial_permits_issued: usize,
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
                post_claim_recheck_rejections: self
                    .post_claim_recheck_rejections
                    .load(Ordering::SeqCst),
                s2_records_emitted: self.s2_records_emitted.load(Ordering::SeqCst),
                c3_records_accepted: self.c3_records_accepted.load(Ordering::SeqCst),
                post_c3_recheck_rejections: self.post_c3_recheck_rejections.load(Ordering::SeqCst),
                completed_m3_closures: self.completed_m3_closures.load(Ordering::SeqCst),
                verified_peers: self.verified_peers.load(Ordering::SeqCst),
                dial_permits_issued: self.dial_permits_issued.load(Ordering::SeqCst),
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
                    server_hello: None,
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
        server_hello: Option<ServerHello>,
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
                    &binding_pre,
                    self.binding_id,
                    self.binding_digest,
                    &self.participant_npub,
                    &self.channel_auth_key_id,
                )?,
            )?;
            let action_hash = owner_action_hash(
                &binding_pre,
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
            self.server_hello = Some(m2);
            self.h_final = Some(h_final);
            self.channel_binding = Some(channel_binding);
            encode_frame(AkeMessageKind::M3, noise)
        }

        /// Consumes the post-M3 device state, authenticates the exact S2
        /// record, then emits C3 on the same standard Noise `TransportState`.
        /// Consuming `self` makes retrying a failed S2 impossible on this
        /// channel: an error drops the split state rather than resetting it.
        pub(crate) fn accept_s2_and_make_c3(self, s2_wire: &[u8]) -> AkeResult<Vec<u8>> {
            let context = self.record_context()?;
            let mut transport = self
                .handshake
                .into_transport_mode()
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            if !transport.is_initiator() {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            let s2_sequence = transport.receiving_nonce();
            let s2_payload = open_a2_record(&mut transport, s2_wire, s2_sequence)?;
            let s2: A2S2Plain = decode_canonical(&s2_payload)?;
            s2.validate_for(&context, s2_sequence, A2_NOW)?;
            let hs2 = s2_wire_hash(s2_wire)?;

            let c3_sequence = transport.sending_nonce();
            let c3_payload = encode_canonical(&context.c3_plain(c3_sequence, hs2))?;
            seal_a2_record(&mut transport, &c3_payload, c3_sequence)
        }

        fn record_context(&self) -> AkeResult<A2RecordContext> {
            let m2 = self
                .server_hello
                .as_ref()
                .ok_or(OwnerSiteAkeFailure::Rejected)?;
            let context = A2RecordContext {
                channel_id: array_32(&m2.channel_id)?,
                channel_epoch: m2.channel_epoch,
                h_final: self.h_final.ok_or(OwnerSiteAkeFailure::Rejected)?,
                channel_binding: self.channel_binding.ok_or(OwnerSiteAkeFailure::Rejected)?,
                binding_id: *self.binding_id.as_bytes(),
                binding_digest: *self.binding_digest.as_bytes(),
                authz_epoch: m2.authz_epoch,
                roster_digest: array_32(&m2.roster_digest)?,
                fresh_until: m2.fresh_until,
            };
            context.validate_at(A2_NOW)?;
            Ok(context)
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
        after_claim_pause: Mutex<Option<Arc<OwnerSiteAkeHarnessPause>>>,
        after_s2_pause: Mutex<Option<Arc<OwnerSiteAkeHarnessPause>>>,
        effects: Arc<OwnerSiteAkeEffects>,
    }

    /// Test-only synchronization point used to place a deterministic tombstone
    /// at either reviewed authority re-read boundary.  It has no production
    /// equivalent and never grants a deferred transport effect.
    pub(crate) struct OwnerSiteAkeHarnessPause {
        reached: Notify,
        resume: Notify,
    }

    impl OwnerSiteAkeHarnessPause {
        async fn wait_for_resume(&self) {
            self.reached.notify_one();
            self.resume.notified().await;
        }

        pub(crate) async fn wait_until_reached(&self) {
            self.reached.notified().await;
        }

        pub(crate) fn resume(&self) {
            self.resume.notify_one();
        }
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

    /// Receives exactly one A2 application message.  Text/close frames, EOF,
    /// socket errors, or bounded wait expiry are terminal for this single
    /// WebSocket channel; Ping/Pong remains library control traffic and does
    /// not extend the bounded application deadline.
    async fn next_a2_binary(socket: &mut WebSocket) -> Option<Vec<u8>> {
        let deadline = Instant::now() + A2_HARNESS_WS_STEP_TIMEOUT;
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())?;
            match timeout(remaining, socket.next()).await {
                Ok(Some(Ok(Message::Binary(bytes)))) => return Some(bytes.to_vec()),
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {
                    // Library control traffic is never an A2 record and never
                    // extends the deadline for the application message.
                }
                _ => return None,
            }
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
                challenges: OwnerSiteChallengeTable::new(),
                next_channel_epoch: AtomicU64::new(1),
                revoked_roster,
                after_claim_pause: Mutex::new(None),
                after_s2_pause: Mutex::new(None),
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

        /// Arms a route-real test pause after the one-shot challenge has been
        /// claimed and before any live gate or roster re-read. Production has
        /// no equivalent hook and remains fail-closed.
        pub(crate) fn pause_after_claim_for_harness(&self) -> Arc<OwnerSiteAkeHarnessPause> {
            let pause = Arc::new(OwnerSiteAkeHarnessPause {
                reached: Notify::new(),
                resume: Notify::new(),
            });
            if let Ok(mut slot) = self.after_claim_pause.lock() {
                *slot = Some(Arc::clone(&pause));
            }
            pause
        }

        /// Arms a route-real pause after encrypted S2 is sent and before C3
        /// can pass its final exact re-read.  This proves a tombstone in that
        /// interval cannot promote a peer or create any backend effect.
        pub(crate) fn pause_after_s2_for_harness(&self) -> Arc<OwnerSiteAkeHarnessPause> {
            let pause = Arc::new(OwnerSiteAkeHarnessPause {
                reached: Notify::new(),
                resume: Notify::new(),
            });
            if let Ok(mut slot) = self.after_s2_pause.lock() {
                *slot = Some(Arc::clone(&pause));
            }
            pause
        }

        async fn wait_at_after_claim_pause_if_armed(&self) {
            let pause = self
                .after_claim_pause
                .lock()
                .ok()
                .and_then(|slot| slot.clone());
            if let Some(pause) = pause {
                pause.wait_for_resume().await;
            }
        }

        async fn wait_at_after_s2_pause_if_armed(&self) {
            let pause = self
                .after_s2_pause
                .lock()
                .ok()
                .and_then(|slot| slot.clone());
            if let Some(pause) = pause {
                pause.wait_for_resume().await;
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
            let Some(m1) = next_a2_binary(&mut socket).await else {
                let _ = socket.close().await;
                return;
            };
            let Ok((mut session, m2)) = self.begin_m1(&resource, &m1) else {
                let _ = socket.close().await;
                return;
            };
            if socket.send(Message::Binary(m2.into())).await.is_err() {
                let _ = socket.close().await;
                return;
            }
            let Some(m3) = next_a2_binary(&mut socket).await else {
                let _ = socket.close().await;
                return;
            };
            if session.accept_m3(self, &m3).is_err() {
                let _ = socket.close().await;
                return;
            }
            self.wait_at_after_claim_pause_if_armed().await;
            let recheck_context = crate::household_listener::post_trust_household_peer_gate(peer)
                .await
                .ok()
                .and_then(|()| self.rechecked_record_context(&session).ok());
            let Some(context) = recheck_context else {
                self.effects
                    .post_claim_recheck_rejections
                    .fetch_add(1, Ordering::SeqCst);
                self.effects
                    .completed_m3_closures
                    .fetch_add(1, Ordering::SeqCst);
                let _ = socket.close().await;
                return;
            };

            // PendingFinished is server-local, bound to the already claimed
            // challenge/session, and still has no peer/capability/dial effect.
            let Ok(mut pending) = session.into_pending_finished(context) else {
                self.effects
                    .post_claim_recheck_rejections
                    .fetch_add(1, Ordering::SeqCst);
                self.effects
                    .completed_m3_closures
                    .fetch_add(1, Ordering::SeqCst);
                let _ = socket.close().await;
                return;
            };
            let Ok(s2_wire) = pending.emit_s2() else {
                self.effects
                    .completed_m3_closures
                    .fetch_add(1, Ordering::SeqCst);
                let _ = socket.close().await;
                return;
            };
            self.effects
                .validated_pending_finished
                .fetch_add(1, Ordering::SeqCst);
            if socket.send(Message::Binary(s2_wire.into())).await.is_err() {
                let _ = socket.close().await;
                return;
            }
            self.effects
                .s2_records_emitted
                .fetch_add(1, Ordering::SeqCst);
            self.wait_at_after_s2_pause_if_armed().await;

            let c3_accepted = matches!(next_a2_binary(&mut socket).await, Some(c3) if pending.accept_c3(&c3).is_ok());
            let final_recheck_allowed = c3_accepted
                && crate::household_listener::post_trust_household_peer_gate(peer)
                    .await
                    .is_ok()
                && self.recheck_pending_finished(&pending);
            if final_recheck_allowed {
                self.effects
                    .c3_records_accepted
                    .fetch_add(1, Ordering::SeqCst);
            } else if c3_accepted {
                self.effects
                    .post_c3_recheck_rejections
                    .fetch_add(1, Ordering::SeqCst);
            }
            self.effects
                .completed_m3_closures
                .fetch_add(1, Ordering::SeqCst);
            // This transport slice deliberately stops here.  Even a valid C3
            // produces no VerifiedMeshPeer, capability, dial, proxy, or site
            // byte until a separately reviewed post-transport slice exists.
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
                .insert_generated(issue.clone(), &issued, A2_NOW)
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
            self.rechecked_record_context(session).is_ok()
        }

        /// Re-reads the same authority snapshot after the one-shot claim and
        /// returns only an exact server-owned record context.  A changed lease,
        /// generation, digest, or resolved binding fails closed instead of
        /// silently rebinding S2 to a newer snapshot.
        fn rechecked_record_context(
            &self,
            session: &OwnerSiteAkeResponderSession,
        ) -> AkeResult<A2RecordContext> {
            let Ok(authority) = self.authority.lock() else {
                return Err(OwnerSiteAkeFailure::Rejected);
            };
            if !authority.is_fresh() || authority.roster.generation() != session.generation {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            let context = session.record_context()?;
            if authority.roster.generation().authz_epoch() != context.authz_epoch
                || authority.roster.generation().digest() != context.roster_digest
                || authority.roster.fresh_until_for_harness() != context.fresh_until
            {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            let proof = session
                .proof
                .as_ref()
                .ok_or(OwnerSiteAkeFailure::Rejected)?;
            let resolved = authority.resolve(&self.intent, proof, session.claimed_binding_id)?;
            if resolved.binding_id().as_bytes() != &context.binding_id
                || resolved.binding_digest().as_bytes() != &context.binding_digest
            {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            Ok(context)
        }

        /// The post-C3 re-read uses the same exact snapshot proof carried by
        /// `PendingFinished`.  This slice still closes rather than promotes a
        /// peer, but a revoke between S2 and C3 is terminal here already.
        fn recheck_pending_finished(&self, pending: &OwnerSiteAkePendingFinished) -> bool {
            let Ok(authority) = self.authority.lock() else {
                return false;
            };
            if !authority.is_fresh()
                || authority.roster.generation() != pending.generation
                || authority.roster.generation().authz_epoch() != pending.context.authz_epoch
                || authority.roster.generation().digest() != pending.context.roster_digest
                || authority.roster.fresh_until_for_harness() != pending.context.fresh_until
            {
                return false;
            }
            authority
                .resolve(&self.intent, &pending.proof, pending.claimed_binding_id)
                .is_ok_and(|resolved| {
                    resolved.binding_id().as_bytes() == &pending.context.binding_id
                        && resolved.binding_digest().as_bytes() == &pending.context.binding_digest
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
                &binding_pre,
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
                &binding_pre,
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
                .claim_after_verified_pop(self.issued.id_for_harness(), &claim, A2_NOW)
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

        fn record_context(&self) -> AkeResult<A2RecordContext> {
            let proof = self.proof.as_ref().ok_or(OwnerSiteAkeFailure::Rejected)?;
            let context = A2RecordContext {
                channel_id: array_32(&self.m2.channel_id)?,
                channel_epoch: self.m2.channel_epoch,
                h_final: self.h_final.ok_or(OwnerSiteAkeFailure::Rejected)?,
                channel_binding: self.channel_binding.ok_or(OwnerSiteAkeFailure::Rejected)?,
                binding_id: array_32(&proof.binding_id)?,
                binding_digest: array_32(&proof.binding_digest)?,
                authz_epoch: self.m2.authz_epoch,
                roster_digest: array_32(&self.m2.roster_digest)?,
                fresh_until: self.m2.fresh_until,
            };
            context.validate_at(A2_NOW)?;
            Ok(context)
        }

        fn into_pending_finished(
            self,
            context: A2RecordContext,
        ) -> AkeResult<OwnerSiteAkePendingFinished> {
            if self.h_final != Some(context.h_final)
                || self.channel_binding != Some(context.channel_binding)
            {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            let proof = self.proof.ok_or(OwnerSiteAkeFailure::Rejected)?;
            let transport = self
                .handshake
                .into_transport_mode()
                .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
            if transport.is_initiator() {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            Ok(OwnerSiteAkePendingFinished {
                transport,
                context,
                _ws_bound_issue: self.issue,
                claimed_binding_id: self.claimed_binding_id,
                generation: self.generation,
                proof,
                s2_wire: Vec::new(),
                hs2: [0u8; 32],
            })
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

    /// A2-R1 post-M3 WebSocket envelope.  This is deliberately a tuple, so
    /// canonical CBOR encodes exactly `[1, ciphertext]`; no plaintext record
    /// kind, direction, nonce, or authorization is visible outside Noise.
    #[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
    struct A2RecordEnvelope(u8, #[serde(with = "serde_bytes")] Vec<u8>);

    /// Fixed 14-field S2 plaintext.  Tuple representation is intentional:
    /// maps, defaults, optional fields, and unknown fields are not part of
    /// the A2-R1 record language.
    #[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
    struct A2S2Plain(
        String,
        u8,
        u8,
        u8,
        u64,
        #[serde(with = "serde_bytes")] Vec<u8>,
        u64,
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
        u64,
        #[serde(with = "serde_bytes")] Vec<u8>,
        u64,
    );

    /// Fixed 15-field C3 plaintext.  C3 repeats the authenticated S2 context
    /// and adds `HS2`, binding the acknowledgement to the exact S2 wire image.
    #[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
    struct A2C3Plain(
        String,
        u8,
        u8,
        u8,
        u64,
        #[serde(with = "serde_bytes")] Vec<u8>,
        u64,
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
        u64,
        #[serde(with = "serde_bytes")] Vec<u8>,
        u64,
        #[serde(with = "serde_bytes")] Vec<u8>,
    );

    /// Server-owned snapshot that a pending S2/C3 exchange must carry without
    /// reaccepting any of its values from a client header or socket address.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct A2RecordContext {
        channel_id: [u8; 32],
        channel_epoch: u64,
        h_final: [u8; 32],
        channel_binding: [u8; 32],
        binding_id: [u8; 32],
        binding_digest: [u8; 32],
        authz_epoch: u64,
        roster_digest: [u8; 32],
        fresh_until: u64,
    }

    impl A2RecordContext {
        fn validate_at(&self, now: u64) -> AkeResult<()> {
            if self.channel_epoch == 0 || self.authz_epoch == 0 || self.fresh_until <= now {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            Ok(())
        }

        fn s2_plain(&self, sequence: u64) -> A2S2Plain {
            A2S2Plain(
                A2_DOMAIN.to_owned(),
                A2_VERSION,
                A2_RECORD_KIND_S2,
                A2_DIRECTION_ENGINE_TO_DEVICE,
                sequence,
                self.channel_id.to_vec(),
                self.channel_epoch,
                self.h_final.to_vec(),
                self.channel_binding.to_vec(),
                self.binding_id.to_vec(),
                self.binding_digest.to_vec(),
                self.authz_epoch,
                self.roster_digest.to_vec(),
                self.fresh_until,
            )
        }

        fn c3_plain(&self, sequence: u64, hs2: [u8; 32]) -> A2C3Plain {
            A2C3Plain(
                A2_DOMAIN.to_owned(),
                A2_VERSION,
                A2_RECORD_KIND_C3,
                A2_DIRECTION_DEVICE_TO_ENGINE,
                sequence,
                self.channel_id.to_vec(),
                self.channel_epoch,
                self.h_final.to_vec(),
                self.channel_binding.to_vec(),
                self.binding_id.to_vec(),
                self.binding_digest.to_vec(),
                self.authz_epoch,
                self.roster_digest.to_vec(),
                self.fresh_until,
                hs2.to_vec(),
            )
        }
    }

    impl A2S2Plain {
        fn validate_for(
            &self,
            context: &A2RecordContext,
            sequence: u64,
            now: u64,
        ) -> AkeResult<()> {
            context.validate_at(now)?;
            if self.0 != A2_DOMAIN
                || self.1 != A2_VERSION
                || self.2 != A2_RECORD_KIND_S2
                || self.3 != A2_DIRECTION_ENGINE_TO_DEVICE
                || self.4 != sequence
                || self.5.as_slice() != context.channel_id.as_slice()
                || self.6 != context.channel_epoch
                || self.7.as_slice() != context.h_final.as_slice()
                || self.8.as_slice() != context.channel_binding.as_slice()
                || self.9.as_slice() != context.binding_id.as_slice()
                || self.10.as_slice() != context.binding_digest.as_slice()
                || self.11 != context.authz_epoch
                || self.12.as_slice() != context.roster_digest.as_slice()
                || self.13 != context.fresh_until
            {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            Ok(())
        }
    }

    impl A2C3Plain {
        fn validate_for(
            &self,
            context: &A2RecordContext,
            sequence: u64,
            hs2: [u8; 32],
            now: u64,
        ) -> AkeResult<()> {
            context.validate_at(now)?;
            if self.0 != A2_DOMAIN
                || self.1 != A2_VERSION
                || self.2 != A2_RECORD_KIND_C3
                || self.3 != A2_DIRECTION_DEVICE_TO_ENGINE
                || self.4 != sequence
                || self.5.as_slice() != context.channel_id.as_slice()
                || self.6 != context.channel_epoch
                || self.7.as_slice() != context.h_final.as_slice()
                || self.8.as_slice() != context.channel_binding.as_slice()
                || self.9.as_slice() != context.binding_id.as_slice()
                || self.10.as_slice() != context.binding_digest.as_slice()
                || self.11 != context.authz_epoch
                || self.12.as_slice() != context.roster_digest.as_slice()
                || self.13 != context.fresh_until
                || self.14.as_slice() != hs2.as_slice()
            {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            Ok(())
        }
    }

    /// The server-only, ephemeral state after M3 + consume + re-read.  It is
    /// deliberately not a peer, capability, or dial permit; dropping it closes
    /// the only transport state held by this pre-effect test harness.
    struct OwnerSiteAkePendingFinished {
        transport: TransportState,
        context: A2RecordContext,
        _ws_bound_issue: OwnerSiteChallengeIssueScope,
        claimed_binding_id: OwnerSiteBindingId,
        generation: OwnerSiteAuthorityGeneration,
        proof: ClientProof,
        s2_wire: Vec<u8>,
        hs2: [u8; 32],
    }

    impl OwnerSiteAkePendingFinished {
        fn emit_s2(&mut self) -> AkeResult<Vec<u8>> {
            if !self.s2_wire.is_empty() || self.transport.is_initiator() {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            self.context.validate_at(A2_NOW)?;
            let sequence = self.transport.sending_nonce();
            let plaintext = encode_canonical(&self.context.s2_plain(sequence))?;
            let wire = seal_a2_record(&mut self.transport, &plaintext, sequence)?;
            self.hs2 = s2_wire_hash(&wire)?;
            self.s2_wire = wire.clone();
            Ok(wire)
        }

        fn accept_c3(&mut self, c3_wire: &[u8]) -> AkeResult<()> {
            if self.s2_wire.is_empty() || self.transport.is_initiator() {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            if self.hs2 != s2_wire_hash(&self.s2_wire)? {
                return Err(OwnerSiteAkeFailure::Rejected);
            }
            let sequence = self.transport.receiving_nonce();
            let plaintext = open_a2_record(&mut self.transport, c3_wire, sequence)?;
            let c3: A2C3Plain = decode_canonical(&plaintext)?;
            c3.validate_for(&self.context, sequence, self.hs2, A2_NOW)
        }
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

    /// Hash input for `HS2`.  The exact canonical S2 wire is a bstr here,
    /// never re-decoded/re-encoded before the acknowledgement binds it.
    #[derive(Serialize)]
    struct S2WireHashTranscript<'a>(
        &'a str,
        &'a str,
        u8,
        #[serde(with = "serde_bytes")] &'a [u8],
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

    /// Seals one fixed-shape A2-R1 record with Snow's stateful split key.
    /// Snow supplies the mandated empty AD and nonce construction; this helper
    /// only verifies the sequence before handing it to the state machine.
    fn seal_a2_record(
        transport: &mut TransportState,
        plaintext: &[u8],
        expected_sequence: u64,
    ) -> AkeResult<Vec<u8>> {
        if plaintext.is_empty()
            || plaintext.len() > MAX_A2_RECORD_PLAINTEXT_BYTES
            || expected_sequence == u64::MAX
            || transport.sending_nonce() != expected_sequence
        {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let ciphertext_len = transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
        ciphertext.truncate(ciphertext_len);
        if ciphertext.is_empty() || ciphertext.len() > MAX_A2_RECORD_CIPHERTEXT_BYTES {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        let wire = encode_canonical(&A2RecordEnvelope(A2_RECORD_ENVELOPE_VERSION, ciphertext))?;
        if wire.len() > MAX_A2_RECORD_ENVELOPE_BYTES {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        Ok(wire)
    }

    /// Authenticates and opens exactly one canonical A2-R1 record.  It checks
    /// the sequence before decryption and returns plaintext only after Snow
    /// has authenticated the tag under the stateful receiving `CipherState`.
    fn open_a2_record(
        transport: &mut TransportState,
        wire: &[u8],
        expected_sequence: u64,
    ) -> AkeResult<Vec<u8>> {
        if wire.is_empty()
            || wire.len() > MAX_A2_RECORD_ENVELOPE_BYTES
            || expected_sequence == u64::MAX
            || transport.receiving_nonce() != expected_sequence
        {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        let envelope: A2RecordEnvelope = decode_canonical(wire)?;
        if envelope.0 != A2_RECORD_ENVELOPE_VERSION
            || envelope.1.len() < 16
            || envelope.1.len() > MAX_A2_RECORD_CIPHERTEXT_BYTES
        {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        let mut plaintext = vec![0u8; envelope.1.len()];
        let plaintext_len = transport
            .read_message(&envelope.1, &mut plaintext)
            .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
        plaintext.truncate(plaintext_len);
        if plaintext.is_empty() || plaintext.len() > MAX_A2_RECORD_PLAINTEXT_BYTES {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        Ok(plaintext)
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

    fn s2_wire_hash(s2_wire: &[u8]) -> AkeResult<[u8; 32]> {
        if s2_wire.is_empty() || s2_wire.len() > MAX_A2_RECORD_ENVELOPE_BYTES {
            return Err(OwnerSiteAkeFailure::Rejected);
        }
        hash_canonical(&S2WireHashTranscript(
            A2_DOMAIN, "s2-wire", A2_VERSION, s2_wire,
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

    // These two are shared with production through `owner_site_binding_glue`:
    // ONE implementation of each preimage, called by both sides. Do NOT
    // reintroduce local copies — two implementations of the same preimage
    // diverge in silence and the symptom is "handshake never works".
    fn pop_binding_pre(
        t1: [u8; 32],
        device_static: [u8; 32],
    ) -> AkeResult<crate::owner_site_binding_glue::ChannelBindingPre> {
        crate::owner_site_binding_glue::pop_binding_pre(t1, device_static)
            .map_err(|_| OwnerSiteAkeFailure::Rejected)
    }

    fn device_auth_hash(
        channel_binding_pre: &crate::owner_site_binding_glue::ChannelBindingPre,
        binding_id: OwnerSiteBindingId,
        binding_digest: OwnerSiteBindingDigest,
        participant_npub: &str,
        channel_auth_key_id: &OwnerSiteChannelAuthKeyId,
    ) -> AkeResult<[u8; 32]> {
        let hash = crate::owner_site_binding_glue::device_auth_hash(
            channel_binding_pre,
            &binding_id,
            &binding_digest,
            participant_npub,
            channel_auth_key_id,
        )
        .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
        Ok(*hash.as_bytes())
    }

    fn owner_action_hash(
        channel_binding_pre: &crate::owner_site_binding_glue::ChannelBindingPre,
        m2: &ServerHello,
        c1: &ClientHelloCore,
        binding_id: OwnerSiteBindingId,
        binding_digest: OwnerSiteBindingDigest,
        participant_npub: &str,
    ) -> AkeResult<[u8; 32]> {
        let intent_wire = encode_canonical(&c1.intent)?;
        let hash = crate::owner_site_binding_glue::owner_action_hash(
            channel_binding_pre,
            m2,
            c1,
            &binding_id,
            &binding_digest,
            participant_npub,
            &intent_wire,
        )
        .map_err(|_| OwnerSiteAkeFailure::Rejected)?;
        Ok(*hash.as_bytes())
    }

    fn hash_canonical<T: Serialize>(value: &T) -> AkeResult<[u8; 32]> {
        crate::owner_site_binding_glue::hash_canonical(value)
            .map_err(|_| OwnerSiteAkeFailure::Rejected)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const A2_R1_SEMANTIC_CORPUS_V1: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/mobile-claw-vpn/v1/owner_site_a2_r1_semantic_corpus_v1.json"
        ));
        const A2_R1_SEMANTIC_CORPUS_V1_SHA256: &str =
            "dde67030a035928d0a859a19fc7dcf14ea8e8fa54643e9f66302652740548330";

        /// Declarative A2-R1 record shape anchored by the frozen cross-language
        /// corpus.  Functional tests below must keep this exact envelope,
        /// direction, sequence, and bounded-size contract.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct A2R1RecordLayout {
            envelope_version: u8,
            s2_kind: u8,
            s2_direction: u8,
            s2_sequence: u64,
            s2_arity: usize,
            c3_kind: u8,
            c3_direction: u8,
            c3_sequence: u64,
            c3_arity: usize,
            max_ciphertext_bytes: usize,
            max_plaintext_bytes: usize,
            max_envelope_bytes: usize,
        }

        const A2_R1_RECORD_LAYOUT: A2R1RecordLayout = A2R1RecordLayout {
            envelope_version: 1,
            s2_kind: 1,
            s2_direction: 1,
            s2_sequence: 0,
            s2_arity: 14,
            c3_kind: 2,
            c3_direction: 0,
            c3_sequence: 0,
            c3_arity: 15,
            max_ciphertext_bytes: 16_384,
            max_plaintext_bytes: 16_368,
            max_envelope_bytes: 16_389,
        };

        fn fixture() -> OwnerSiteAkeFixture {
            OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("typed A2 fixture")
        }

        fn frozen_transport_kat() -> serde_json::Value {
            let corpus: serde_json::Value =
                serde_json::from_str(A2_R1_SEMANTIC_CORPUS_V1).expect("frozen corpus JSON");
            corpus["transport_kat_a2_r1"].clone()
        }

        fn frozen_hex(object: &serde_json::Value, field: &str) -> Vec<u8> {
            hex::decode(
                object[field]
                    .as_str()
                    .unwrap_or_else(|| panic!("frozen KAT {field} must be hex")),
            )
            .unwrap_or_else(|_| panic!("frozen KAT {field} must decode"))
        }

        fn frozen_u64(object: &serde_json::Value, field: &str) -> u64 {
            object[field]
                .as_u64()
                .unwrap_or_else(|| panic!("frozen KAT {field} must be uint"))
        }

        fn frozen_record_context(transport: &serde_json::Value) -> A2RecordContext {
            let channel = &transport["channel_context"];
            A2RecordContext {
                channel_id: array_32(&frozen_hex(channel, "channel_id_hex"))
                    .expect("32-byte frozen channel id"),
                channel_epoch: frozen_u64(channel, "channel_epoch"),
                h_final: array_32(&frozen_hex(transport, "h_final_hex"))
                    .expect("32-byte frozen H_final"),
                channel_binding: array_32(&frozen_hex(transport, "channel_binding_hex"))
                    .expect("32-byte frozen CB"),
                binding_id: array_32(&frozen_hex(channel, "binding_id_hex"))
                    .expect("32-byte frozen binding id"),
                binding_digest: array_32(&frozen_hex(channel, "binding_digest_hex"))
                    .expect("32-byte frozen binding digest"),
                authz_epoch: frozen_u64(channel, "authz_epoch"),
                roster_digest: array_32(&frozen_hex(channel, "roster_digest_hex"))
                    .expect("32-byte frozen roster digest"),
                fresh_until: frozen_u64(channel, "fresh_until_unix_s"),
            }
        }

        fn frozen_transport_pair() -> (TransportState, TransportState, A2RecordContext, u64) {
            let kat = frozen_transport_kat();
            let inputs = &kat["synthetic_x25519_private_inputs"];
            let prologue = frozen_hex(&kat, "p_a2_canonical_cbor_hex");
            let device_static = frozen_hex(inputs, "device_static_hex");
            let device_ephemeral = frozen_hex(inputs, "device_ephemeral_hex");
            let engine_static = frozen_hex(inputs, "engine_static_hex");
            let engine_ephemeral = frozen_hex(inputs, "engine_ephemeral_hex");
            let mut device = a2_noise_builder(&prologue)
                .expect("device builder")
                .local_private_key(&device_static)
                .expect("device static")
                .fixed_ephemeral_key_for_testing_only(&device_ephemeral)
                .build_initiator()
                .expect("device initiator");
            let mut engine = a2_noise_builder(&prologue)
                .expect("engine builder")
                .local_private_key(&engine_static)
                .expect("engine static")
                .fixed_ephemeral_key_for_testing_only(&engine_ephemeral)
                .build_responder()
                .expect("engine responder");
            let mut plaintext = vec![0u8; MAX_A2_FRAME_BYTES];
            let exchange = |sender: &mut HandshakeState,
                            receiver: &mut HandshakeState,
                            payload: Vec<u8>,
                            plaintext: &mut Vec<u8>| {
                let mut noise = vec![0u8; MAX_A2_FRAME_BYTES];
                let len = sender
                    .write_message(&payload, &mut noise)
                    .expect("Noise write");
                noise.truncate(len);
                let opened = receiver
                    .read_message(&noise, plaintext)
                    .expect("Noise inverse open");
                assert_eq!(&plaintext[..opened], payload);
            };
            exchange(
                &mut device,
                &mut engine,
                frozen_hex(&kat, "m1_payload_canonical_cbor_hex"),
                &mut plaintext,
            );
            exchange(
                &mut engine,
                &mut device,
                frozen_hex(&kat, "m2_payload_canonical_cbor_hex"),
                &mut plaintext,
            );
            exchange(
                &mut device,
                &mut engine,
                frozen_hex(&kat, "m3_payload_canonical_cbor_hex"),
                &mut plaintext,
            );
            let context = frozen_record_context(&kat);
            assert_eq!(
                context.h_final,
                final_handshake_hash(&device).expect("device H_final")
            );
            assert_eq!(
                context.h_final,
                final_handshake_hash(&engine).expect("engine H_final")
            );
            let now = frozen_u64(&kat["channel_context"], "kat_now_unix_s");
            (
                device.into_transport_mode().expect("device split"),
                engine.into_transport_mode().expect("engine split"),
                context,
                now,
            )
        }

        /// A separate fully completed XX channel used only to prove that an
        /// S2/C3 ciphertext from one WebSocket cannot be replayed into another
        /// channel, even when its record plaintext would otherwise be valid.
        fn independent_transport_pair() -> (TransportState, TransportState) {
            let prologue = a2_noise_prologue().expect("canonical P_A2");
            let mut device = a2_noise_builder(&prologue)
                .expect("independent device builder")
                .local_private_key(&[0x31; 32])
                .expect("independent device static")
                .fixed_ephemeral_key_for_testing_only(&[0x32; 32])
                .build_initiator()
                .expect("independent device initiator");
            let mut engine = a2_noise_builder(&prologue)
                .expect("independent engine builder")
                .local_private_key(&[0x41; 32])
                .expect("independent engine static")
                .fixed_ephemeral_key_for_testing_only(&[0x42; 32])
                .build_responder()
                .expect("independent engine responder");
            let mut plaintext = vec![0u8; MAX_A2_FRAME_BYTES];
            let exchange = |sender: &mut HandshakeState,
                            receiver: &mut HandshakeState,
                            payload: Vec<u8>,
                            plaintext: &mut Vec<u8>| {
                let mut noise = vec![0u8; MAX_A2_FRAME_BYTES];
                let len = sender
                    .write_message(&payload, &mut noise)
                    .expect("independent Noise write");
                noise.truncate(len);
                let opened = receiver
                    .read_message(&noise, plaintext)
                    .expect("independent Noise inverse open");
                assert_eq!(&plaintext[..opened], payload);
            };
            exchange(
                &mut device,
                &mut engine,
                encode_canonical(&(A2_DOMAIN, A2_VERSION, "independent-m1"))
                    .expect("independent M1"),
                &mut plaintext,
            );
            exchange(
                &mut engine,
                &mut device,
                encode_canonical(&(A2_DOMAIN, A2_VERSION, "independent-m2"))
                    .expect("independent M2"),
                &mut plaintext,
            );
            exchange(
                &mut device,
                &mut engine,
                encode_canonical(&(A2_DOMAIN, A2_VERSION, "independent-m3"))
                    .expect("independent M3"),
                &mut plaintext,
            );
            (
                device
                    .into_transport_mode()
                    .expect("independent device split"),
                engine
                    .into_transport_mode()
                    .expect("independent engine split"),
            )
        }

        fn assert_authenticated_s2_context_mutation_is_rejected(
            mutate: impl FnOnce(&mut A2RecordContext),
        ) {
            let (mut device, mut engine, expected, now) = frozen_transport_pair();
            let mut altered = expected.clone();
            mutate(&mut altered);
            let s2_payload = encode_canonical(&altered.s2_plain(0)).expect("altered S2 plaintext");
            let s2_wire =
                seal_a2_record(&mut engine, &s2_payload, 0).expect("authenticated altered S2");
            let received =
                open_a2_record(&mut device, &s2_wire, 0).expect("S2 tag still authentic");
            let decoded: A2S2Plain = decode_canonical(&received).expect("canonical altered S2");
            assert!(
                decoded.validate_for(&expected, 0, now).is_err(),
                "an authenticated but mismatched S2 context must be terminal"
            );
        }

        fn assert_authenticated_c3_context_mutation_is_rejected(
            mutate: impl FnOnce(&mut A2RecordContext),
        ) {
            let (mut device, mut engine, expected, now) = frozen_transport_pair();
            let s2_payload = encode_canonical(&expected.s2_plain(0)).expect("canonical S2");
            let s2_wire = seal_a2_record(&mut engine, &s2_payload, 0).expect("S2 wire");
            let opened_s2 = open_a2_record(&mut device, &s2_wire, 0).expect("S2 opens");
            let opened_s2: A2S2Plain = decode_canonical(&opened_s2).expect("canonical S2");
            opened_s2
                .validate_for(&expected, 0, now)
                .expect("S2 exact context");

            let hs2 = s2_wire_hash(&s2_wire).expect("exact S2 hash");
            let mut altered = expected.clone();
            mutate(&mut altered);
            let c3_payload =
                encode_canonical(&altered.c3_plain(0, hs2)).expect("altered C3 plaintext");
            let c3_wire =
                seal_a2_record(&mut device, &c3_payload, 0).expect("authenticated altered C3");
            let received = open_a2_record(&mut engine, &c3_wire, 0).expect("C3 tag authentic");
            let decoded: A2C3Plain = decode_canonical(&received).expect("canonical altered C3");
            assert!(
                decoded.validate_for(&expected, 0, hs2, now).is_err(),
                "an authenticated but mismatched C3 context must be terminal"
            );
        }

        fn assert_authenticated_s2_shape_mutation_is_rejected(mutate: impl FnOnce(&mut A2S2Plain)) {
            let (mut device, mut engine, context, now) = frozen_transport_pair();
            let mut altered = context.s2_plain(0);
            mutate(&mut altered);
            let payload = encode_canonical(&altered).expect("authenticated altered S2 plaintext");
            let wire = seal_a2_record(&mut engine, &payload, 0).expect("authenticated altered S2");
            let opened = open_a2_record(&mut device, &wire, 0).expect("S2 tag authentic");
            let decoded: A2S2Plain = decode_canonical(&opened).expect("canonical altered S2");
            assert!(
                decoded.validate_for(&context, 0, now).is_err(),
                "an authenticated S2 shape mutation must be terminal"
            );
        }

        fn assert_authenticated_c3_shape_mutation_is_rejected(mutate: impl FnOnce(&mut A2C3Plain)) {
            let (mut device, mut engine, context, now) = frozen_transport_pair();
            let s2_payload = encode_canonical(&context.s2_plain(0)).expect("canonical S2");
            let s2_wire = seal_a2_record(&mut engine, &s2_payload, 0).expect("S2 wire");
            let opened_s2 = open_a2_record(&mut device, &s2_wire, 0).expect("S2 opens");
            let opened_s2: A2S2Plain = decode_canonical(&opened_s2).expect("canonical S2");
            opened_s2
                .validate_for(&context, 0, now)
                .expect("S2 exact context");

            let mut altered = context.c3_plain(0, s2_wire_hash(&s2_wire).expect("exact S2 hash"));
            mutate(&mut altered);
            let payload = encode_canonical(&altered).expect("authenticated altered C3 plaintext");
            let wire = seal_a2_record(&mut device, &payload, 0).expect("authenticated altered C3");
            let opened = open_a2_record(&mut engine, &wire, 0).expect("C3 tag authentic");
            let decoded: A2C3Plain = decode_canonical(&opened).expect("canonical altered C3");
            assert!(
                decoded
                    .validate_for(
                        &context,
                        0,
                        s2_wire_hash(&s2_wire).expect("exact S2 hash"),
                        now
                    )
                    .is_err(),
                "an authenticated C3 shape mutation must be terminal"
            );
        }

        fn make_authenticated_c3(
            device: &mut TransportState,
            engine: &mut TransportState,
            context: &A2RecordContext,
            now: u64,
        ) -> Vec<u8> {
            let s2_sequence = engine.sending_nonce();
            let s2_payload =
                encode_canonical(&context.s2_plain(s2_sequence)).expect("canonical S2");
            let s2_wire =
                seal_a2_record(engine, &s2_payload, s2_sequence).expect("authenticated S2");
            let s2_sequence = device.receiving_nonce();
            let s2_payload =
                open_a2_record(device, &s2_wire, s2_sequence).expect("S2 inverse open");
            let s2: A2S2Plain = decode_canonical(&s2_payload).expect("canonical S2");
            s2.validate_for(context, s2_sequence, now)
                .expect("S2 exact context");

            let c3_sequence = device.sending_nonce();
            let c3_payload = encode_canonical(
                &context.c3_plain(c3_sequence, s2_wire_hash(&s2_wire).expect("exact S2 hash")),
            )
            .expect("canonical C3");
            seal_a2_record(device, &c3_payload, c3_sequence).expect("authenticated C3")
        }

        fn assert_each_s2_wire_byte_is_terminal() {
            let (device, mut engine, context, _) = frozen_transport_pair();
            let payload = encode_canonical(&context.s2_plain(0)).expect("canonical S2");
            let wire = seal_a2_record(&mut engine, &payload, 0).expect("frozen S2 wire");
            for index in 0..wire.len() {
                let (mut device_for_mutation, _engine_for_mutation, _, _) = frozen_transport_pair();
                let mut altered = wire.clone();
                altered[index] ^= 0x01;
                assert!(
                    open_a2_record(&mut device_for_mutation, &altered, 0).is_err(),
                    "S2 byte {index} must be terminal when altered"
                );
            }
            assert_eq!(device.receiving_nonce(), 0);
        }

        fn assert_each_c3_wire_byte_is_terminal() {
            let (mut device, mut engine, context, now) = frozen_transport_pair();
            let wire = make_authenticated_c3(&mut device, &mut engine, &context, now);
            for index in 0..wire.len() {
                let (_device_for_mutation, mut engine_for_mutation, _, _) = frozen_transport_pair();
                let mut altered = wire.clone();
                altered[index] ^= 0x01;
                assert!(
                    open_a2_record(&mut engine_for_mutation, &altered, 0).is_err(),
                    "C3 byte {index} must be terminal when altered"
                );
            }
            assert_eq!(engine.receiving_nonce(), 0);
        }

        #[test]
        fn a2_r1_semantic_corpus_is_frozen_non_authoritative_transport_contract() {
            assert_eq!(
                hex::encode(sha256(A2_R1_SEMANTIC_CORPUS_V1.as_bytes())),
                A2_R1_SEMANTIC_CORPUS_V1_SHA256,
                "the shared Rust/iOS corpus is a byte-for-byte frozen v1 anchor"
            );

            let corpus: serde_json::Value =
                serde_json::from_str(A2_R1_SEMANTIC_CORPUS_V1).expect("valid frozen corpus JSON");
            assert_eq!(corpus["version"], 1);
            assert_eq!(
                corpus["contract"],
                "soyeht-owner-site-a2-r1-semantic-corpus"
            );
            assert_eq!(
                corpus["authority_status"],
                "synthetic-test-only-non-authoritative"
            );
            assert_eq!(
                corpus["scope"],
                "synthetic-test-only-cross-language-witness"
            );

            assert_eq!(
                A2_R1_RECORD_LAYOUT,
                A2R1RecordLayout {
                    envelope_version: 1,
                    s2_kind: 1,
                    s2_direction: 1,
                    s2_sequence: 0,
                    s2_arity: 14,
                    c3_kind: 2,
                    c3_direction: 0,
                    c3_sequence: 0,
                    c3_arity: 15,
                    max_ciphertext_bytes: 16_384,
                    max_plaintext_bytes: 16_368,
                    max_envelope_bytes: 16_389,
                }
            );

            let transport = corpus["transport_kat_a2_r1"]
                .as_object()
                .expect("frozen transport KAT object");
            assert_eq!(transport["protocol_name"], A2_NOISE_PROTOCOL_NAME);
            for field in ["hs2_hex", "s2_wire_hex", "c3_wire_hex"] {
                let encoded = transport[field]
                    .as_str()
                    .expect("frozen KAT fields remain textual fixture input");
                assert!(
                    !encoded.is_empty()
                        && encoded.len() % 2 == 0
                        && encoded
                            .bytes()
                            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
                    "{field} must remain lowercase even-length fixture hex"
                );
            }

            let pre_c3_effects = corpus["semantic_cases"][0]["pre_c3_expected_effects"]
                .as_object()
                .expect("synthetic case fixes pre-C3 effects");
            assert!(
                pre_c3_effects.values().all(|value| value == 0),
                "the transport scaffold cannot turn the synthetic corpus into a peer, dial, proxy, mint, or site-byte effect"
            );
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
                    post_claim_recheck_rejections: 0,
                    s2_records_emitted: 0,
                    c3_records_accepted: 0,
                    post_c3_recheck_rejections: 0,
                    completed_m3_closures: 0,
                    verified_peers: 0,
                    dial_permits_issued: 0,
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
        fn a2_r1_transport_kat_matches_frozen_s2_c3_split_and_inverse_opens() {
            let kat = frozen_transport_kat();
            let inputs = &kat["synthetic_x25519_private_inputs"];
            let prologue = frozen_hex(&kat, "p_a2_canonical_cbor_hex");
            assert_eq!(
                prologue,
                a2_noise_prologue().expect("fixed A2-R1 prologue"),
                "the corpus must anchor the only allowed prologue"
            );

            let mut device = a2_noise_builder(&prologue)
                .expect("device builder")
                .local_private_key(&frozen_hex(inputs, "device_static_hex"))
                .expect("device static")
                .fixed_ephemeral_key_for_testing_only(&frozen_hex(inputs, "device_ephemeral_hex"))
                .build_initiator()
                .expect("device initiator");
            let mut engine = a2_noise_builder(&prologue)
                .expect("engine builder")
                .local_private_key(&frozen_hex(inputs, "engine_static_hex"))
                .expect("engine static")
                .fixed_ephemeral_key_for_testing_only(&frozen_hex(inputs, "engine_ephemeral_hex"))
                .build_responder()
                .expect("engine responder");

            let m1_payload = frozen_hex(&kat, "m1_payload_canonical_cbor_hex");
            let m2_payload = frozen_hex(&kat, "m2_payload_canonical_cbor_hex");
            let m3_payload = frozen_hex(&kat, "m3_payload_canonical_cbor_hex");
            let mut plaintext = vec![0u8; MAX_A2_FRAME_BYTES];

            let mut m1 = vec![0u8; MAX_A2_FRAME_BYTES];
            let m1_len = device
                .write_message(&m1_payload, &mut m1)
                .expect("M1 write");
            m1.truncate(m1_len);
            assert_eq!(m1, frozen_hex(&kat, "m1_noise_hex"));
            let m1_plaintext = engine.read_message(&m1, &mut plaintext).expect("M1 read");
            assert_eq!(&plaintext[..m1_plaintext], m1_payload);

            let mut m2 = vec![0u8; MAX_A2_FRAME_BYTES];
            let m2_len = engine
                .write_message(&m2_payload, &mut m2)
                .expect("M2 write");
            m2.truncate(m2_len);
            assert_eq!(m2, frozen_hex(&kat, "m2_noise_hex"));
            let m2_plaintext = device.read_message(&m2, &mut plaintext).expect("M2 read");
            assert_eq!(&plaintext[..m2_plaintext], m2_payload);

            let mut m3 = vec![0u8; MAX_A2_FRAME_BYTES];
            let m3_len = device
                .write_message(&m3_payload, &mut m3)
                .expect("M3 write");
            m3.truncate(m3_len);
            assert_eq!(m3, frozen_hex(&kat, "m3_noise_hex"));
            let m3_plaintext = engine.read_message(&m3, &mut plaintext).expect("M3 read");
            assert_eq!(&plaintext[..m3_plaintext], m3_payload);

            let h_final = final_handshake_hash(&engine).expect("finished engine transcript");
            assert_eq!(
                h_final,
                final_handshake_hash(&device).expect("finished device transcript")
            );
            assert_eq!(h_final.to_vec(), frozen_hex(&kat, "h_final_hex"));
            let context = frozen_record_context(&kat);
            let channel = &kat["channel_context"];
            context
                .validate_at(frozen_u64(channel, "kat_now_unix_s"))
                .expect("fresh frozen KAT context");
            assert_eq!(context.h_final, h_final);
            assert_eq!(
                context.channel_binding,
                channel_binding(h_final, &context.channel_id, context.channel_epoch)
                    .expect("frozen channel binding")
            );

            let mut device_transport = device
                .into_transport_mode()
                .expect("standard initiator Noise split");
            let mut engine_transport = engine
                .into_transport_mode()
                .expect("standard responder Noise split");
            assert!(device_transport.is_initiator());
            assert!(!engine_transport.is_initiator());
            assert_eq!(engine_transport.sending_nonce(), 0);
            assert_eq!(device_transport.receiving_nonce(), 0);

            let s2_sequence = engine_transport.sending_nonce();
            let s2_plain = context.s2_plain(s2_sequence);
            let s2_payload = encode_canonical(&s2_plain).expect("canonical S2 plaintext");
            let s2_wire = seal_a2_record(&mut engine_transport, &s2_payload, s2_sequence)
                .expect("responder S2 at nonce zero");
            assert_eq!(s2_wire, frozen_hex(&kat, "s2_wire_hex"));
            let hs2 = s2_wire_hash(&s2_wire).expect("HS2 over exact S2 wire");
            assert_eq!(hs2.to_vec(), frozen_hex(&kat, "hs2_hex"));
            assert_eq!(engine_transport.sending_nonce(), 1);

            let s2_received_sequence = device_transport.receiving_nonce();
            let server_finished_payload =
                open_a2_record(&mut device_transport, &s2_wire, s2_received_sequence)
                    .expect("initiator opens responder S2");
            let server_finished: A2S2Plain =
                decode_canonical(&server_finished_payload).expect("canonical authenticated S2");
            server_finished
                .validate_for(
                    &context,
                    s2_received_sequence,
                    frozen_u64(channel, "kat_now_unix_s"),
                )
                .expect("S2 exact context");
            assert_eq!(device_transport.receiving_nonce(), 1);

            let c3_sequence = device_transport.sending_nonce();
            let c3_plain = context.c3_plain(c3_sequence, hs2);
            let c3_payload = encode_canonical(&c3_plain).expect("canonical C3 plaintext");
            let c3_wire = seal_a2_record(&mut device_transport, &c3_payload, c3_sequence)
                .expect("initiator C3 at nonce zero");
            assert_eq!(c3_wire, frozen_hex(&kat, "c3_wire_hex"));
            assert_eq!(device_transport.sending_nonce(), 1);

            let c3_received_sequence = engine_transport.receiving_nonce();
            let client_ack_payload =
                open_a2_record(&mut engine_transport, &c3_wire, c3_received_sequence)
                    .expect("responder opens initiator C3");
            let client_ack: A2C3Plain =
                decode_canonical(&client_ack_payload).expect("canonical authenticated C3");
            client_ack
                .validate_for(
                    &context,
                    c3_received_sequence,
                    hs2,
                    frozen_u64(channel, "kat_now_unix_s"),
                )
                .expect("C3 exact context and HS2");
            assert_eq!(engine_transport.receiving_nonce(), 1);
        }

        #[test]
        fn a2_r1_records_fail_closed_for_tamper_replay_direction_and_context_swaps() {
            assert_each_s2_wire_byte_is_terminal();
            assert_each_c3_wire_byte_is_terminal();

            let (mut replay_device, mut replay_engine, replay_context, replay_now) =
                frozen_transport_pair();
            let replay_payload =
                encode_canonical(&replay_context.s2_plain(0)).expect("canonical replay S2");
            let replay_wire =
                seal_a2_record(&mut replay_engine, &replay_payload, 0).expect("replay S2 wire");
            let first_open =
                open_a2_record(&mut replay_device, &replay_wire, 0).expect("first S2 opens");
            let first_s2: A2S2Plain = decode_canonical(&first_open).expect("first canonical S2");
            first_s2
                .validate_for(&replay_context, 0, replay_now)
                .expect("first S2 context");
            assert_eq!(replay_device.receiving_nonce(), 1);
            assert!(
                open_a2_record(&mut replay_device, &replay_wire, 1).is_err(),
                "a replay cannot satisfy the next stateful CipherState nonce"
            );

            let (wrong_direction_device, mut wrong_direction_engine, direction_context, _) =
                frozen_transport_pair();
            let direction_payload =
                encode_canonical(&direction_context.s2_plain(0)).expect("direction S2");
            let direction_wire = seal_a2_record(&mut wrong_direction_engine, &direction_payload, 0)
                .expect("responder S2");
            assert!(
                open_a2_record(&mut wrong_direction_engine, &direction_wire, 0).is_err(),
                "the responder cannot open its own E-to-D record with the D-to-E key"
            );
            assert_eq!(wrong_direction_device.receiving_nonce(), 0);

            let (
                mut c3_wrong_direction_device,
                mut c3_wrong_direction_engine,
                c3_direction_context,
                c3_direction_now,
            ) = frozen_transport_pair();
            let c3_wrong_direction_wire = make_authenticated_c3(
                &mut c3_wrong_direction_device,
                &mut c3_wrong_direction_engine,
                &c3_direction_context,
                c3_direction_now,
            );
            let c3_wrong_direction_nonce = c3_wrong_direction_device.receiving_nonce();
            assert!(
                open_a2_record(
                    &mut c3_wrong_direction_device,
                    &c3_wrong_direction_wire,
                    c3_wrong_direction_nonce,
                )
                .is_err(),
                "the device cannot open its own D-to-E C3 record with the E-to-D c2 key"
            );
            assert_eq!(c3_wrong_direction_engine.receiving_nonce(), 0);

            assert_authenticated_s2_context_mutation_is_rejected(|altered| {
                altered.h_final[0] ^= 0x01;
            });
            assert_authenticated_s2_context_mutation_is_rejected(|altered| {
                altered.channel_binding[0] ^= 0x01;
            });
            assert_authenticated_s2_context_mutation_is_rejected(|altered| {
                altered.channel_id[0] ^= 0x01;
            });
            assert_authenticated_s2_context_mutation_is_rejected(|altered| {
                altered.binding_id[0] ^= 0x01;
            });
            assert_authenticated_s2_context_mutation_is_rejected(|altered| {
                altered.binding_digest[0] ^= 0x01;
            });
            assert_authenticated_s2_context_mutation_is_rejected(|altered| {
                altered.roster_digest[0] ^= 0x01;
            });
            assert_authenticated_s2_context_mutation_is_rejected(|altered| {
                altered.channel_epoch += 1;
            });
            assert_authenticated_s2_context_mutation_is_rejected(|altered| {
                altered.authz_epoch += 1;
            });
            assert_authenticated_s2_context_mutation_is_rejected(|altered| {
                altered.fresh_until += 1;
            });
            assert_authenticated_s2_shape_mutation_is_rejected(|altered| {
                altered.3 = A2_DIRECTION_DEVICE_TO_ENGINE;
            });
            assert_authenticated_s2_shape_mutation_is_rejected(|altered| {
                altered.4 = 1;
            });

            assert_authenticated_c3_context_mutation_is_rejected(|altered| {
                altered.h_final[0] ^= 0x01;
            });
            assert_authenticated_c3_context_mutation_is_rejected(|altered| {
                altered.channel_binding[0] ^= 0x01;
            });
            assert_authenticated_c3_context_mutation_is_rejected(|altered| {
                altered.binding_id[0] ^= 0x01;
            });
            assert_authenticated_c3_context_mutation_is_rejected(|altered| {
                altered.binding_digest[0] ^= 0x01;
            });
            assert_authenticated_c3_context_mutation_is_rejected(|altered| {
                altered.authz_epoch += 1;
            });
            assert_authenticated_c3_context_mutation_is_rejected(|altered| {
                altered.channel_epoch += 1;
            });
            assert_authenticated_c3_context_mutation_is_rejected(|altered| {
                altered.fresh_until += 1;
            });
            assert_authenticated_c3_shape_mutation_is_rejected(|altered| {
                altered.3 = A2_DIRECTION_ENGINE_TO_DEVICE;
            });
            assert_authenticated_c3_shape_mutation_is_rejected(|altered| {
                altered.4 = 1;
            });

            let (mut c3_device, mut c3_engine, c3_context, c3_now) = frozen_transport_pair();
            let c3_s2_payload = encode_canonical(&c3_context.s2_plain(0)).expect("C3 S2 plaintext");
            let c3_s2_wire = seal_a2_record(&mut c3_engine, &c3_s2_payload, 0).expect("C3 S2 wire");
            let s2_for_c3_payload =
                open_a2_record(&mut c3_device, &c3_s2_wire, 0).expect("C3 S2 open");
            let s2_for_c3: A2S2Plain =
                decode_canonical(&s2_for_c3_payload).expect("C3 S2 canonical");
            s2_for_c3
                .validate_for(&c3_context, 0, c3_now)
                .expect("C3 S2 context");
            let hs2 = s2_wire_hash(&c3_s2_wire).expect("C3 HS2");
            let mut altered_hs2 = hs2;
            altered_hs2[0] ^= 0x01;
            let c3_payload =
                encode_canonical(&c3_context.c3_plain(0, altered_hs2)).expect("altered C3");
            let c3_wire = seal_a2_record(&mut c3_device, &c3_payload, 0).expect("C3 wire");
            let client_ack_payload = open_a2_record(&mut c3_engine, &c3_wire, 0).expect("C3 open");
            let client_ack: A2C3Plain =
                decode_canonical(&client_ack_payload).expect("C3 canonical");
            assert!(
                client_ack
                    .validate_for(&c3_context, 0, hs2, c3_now)
                    .is_err(),
                "C3 must acknowledge the exact stored S2 wire hash"
            );

            let (mut replay_c3_device, mut replay_c3_engine, replay_c3_context, replay_c3_now) =
                frozen_transport_pair();
            let replay_c3 = make_authenticated_c3(
                &mut replay_c3_device,
                &mut replay_c3_engine,
                &replay_c3_context,
                replay_c3_now,
            );
            assert!(
                open_a2_record(&mut replay_c3_engine, &replay_c3, 0).is_ok(),
                "the first C3 is the expected stateful record"
            );
            assert!(
                open_a2_record(&mut replay_c3_engine, &replay_c3, 1).is_err(),
                "a C3 replay cannot satisfy the next receiving nonce"
            );

            let (mut cross_device, mut cross_engine, cross_context, cross_now) =
                frozen_transport_pair();
            let cross_c3 = make_authenticated_c3(
                &mut cross_device,
                &mut cross_engine,
                &cross_context,
                cross_now,
            );
            let (_other_device, mut other_engine) = independent_transport_pair();
            assert!(
                open_a2_record(&mut other_engine, &cross_c3, 0).is_err(),
                "a C3 from another completed WebSocket must fail its distinct split key"
            );
        }

        #[test]
        fn a2_r1_rejects_raw_noncanonical_oversize_and_c3_before_s2() {
            let (mut raw_device, _raw_engine, raw_context, _) = frozen_transport_pair();
            let raw_plaintext =
                encode_canonical(&raw_context.s2_plain(0)).expect("raw S2 plaintext");
            assert!(
                open_a2_record(&mut raw_device, &raw_plaintext, 0).is_err(),
                "an unsealed S2 plaintext is never a record envelope"
            );

            let (mut legacy_device, _legacy_engine, _, _) = frozen_transport_pair();
            let legacy_ake_frame =
                encode_frame(AkeMessageKind::M3, vec![0x01]).expect("legacy handshake frame");
            assert!(
                open_a2_record(&mut legacy_device, &legacy_ake_frame, 0).is_err(),
                "the pre-Finished AkeFrame map is not a post-M3 A2 envelope"
            );

            let (mut noncanonical_device, _noncanonical_engine, _, _) = frozen_transport_pair();
            let nonminimal_array_length = vec![0x98, 0x02, 0x01, 0x40];
            assert!(
                open_a2_record(&mut noncanonical_device, &nonminimal_array_length, 0).is_err(),
                "non-minimal CBOR array syntax is terminal before decryption"
            );

            let (mut wrong_version_device, _wrong_version_engine, _, _) = frozen_transport_pair();
            let wrong_version = encode_canonical(&A2RecordEnvelope(2, vec![0x7f; 16]))
                .expect("canonical wrong-version envelope");
            assert!(
                open_a2_record(&mut wrong_version_device, &wrong_version, 0).is_err(),
                "only envelope version one is accepted"
            );

            let (mut extra_arity_device, _extra_arity_engine, _, _) = frozen_transport_pair();
            let mut extra_arity = vec![0x83, 0x01, 0x50];
            extra_arity.extend_from_slice(&[0x00; 16]);
            extra_arity.push(0x00);
            assert!(
                open_a2_record(&mut extra_arity_device, &extra_arity, 0).is_err(),
                "an envelope with an unknown third field is rejected"
            );

            let (mut short_cipher_device, _short_cipher_engine, _, _) = frozen_transport_pair();
            let short_ciphertext = encode_canonical(&A2RecordEnvelope(1, vec![0x00; 15]))
                .expect("canonical short envelope");
            assert!(
                open_a2_record(&mut short_cipher_device, &short_ciphertext, 0).is_err(),
                "a record ciphertext must carry the full ChaChaPoly tag"
            );

            let (mut empty_cipher_device, _empty_cipher_engine, _, _) = frozen_transport_pair();
            let empty_ciphertext =
                encode_canonical(&A2RecordEnvelope(1, Vec::new())).expect("empty envelope");
            assert!(
                open_a2_record(&mut empty_cipher_device, &empty_ciphertext, 0).is_err(),
                "an empty ciphertext envelope is rejected"
            );

            let (mut oversized_cipher_device, _oversized_cipher_engine, _, _) =
                frozen_transport_pair();
            let oversized_ciphertext = encode_canonical(&A2RecordEnvelope(
                1,
                vec![0x00; MAX_A2_RECORD_CIPHERTEXT_BYTES + 1],
            ))
            .expect("canonical oversized ciphertext envelope");
            assert!(oversized_ciphertext.len() > MAX_A2_RECORD_ENVELOPE_BYTES);
            assert!(
                open_a2_record(&mut oversized_cipher_device, &oversized_ciphertext, 0).is_err(),
                "a ciphertext above the 16,384-byte bound is rejected at the 16,389-byte envelope frontier"
            );

            let (mut bounded_device, mut bounded_engine, _bounded_context, _) =
                frozen_transport_pair();
            let maximum_plaintext = vec![0x5a; MAX_A2_RECORD_PLAINTEXT_BYTES];
            let maximum_wire = seal_a2_record(&mut bounded_engine, &maximum_plaintext, 0)
                .expect("the exact plaintext bound is allowed");
            assert!(maximum_wire.len() <= MAX_A2_RECORD_ENVELOPE_BYTES);
            assert_eq!(
                open_a2_record(&mut bounded_device, &maximum_wire, 0)
                    .expect("the exact ciphertext bound is allowed"),
                maximum_plaintext
            );
            assert_eq!(bounded_engine.sending_nonce(), 1);
            assert_eq!(bounded_device.receiving_nonce(), 1);
            assert!(
                seal_a2_record(&mut bounded_engine, &[0x01], 0).is_err(),
                "the caller cannot reuse a sending nonce"
            );
            assert!(
                seal_a2_record(
                    &mut bounded_engine,
                    &vec![0x00; MAX_A2_RECORD_PLAINTEXT_BYTES + 1],
                    1,
                )
                .is_err(),
                "plaintext above 16,368 bytes is rejected before encryption"
            );
            assert!(
                open_a2_record(
                    &mut bounded_device,
                    &vec![0x00; MAX_A2_RECORD_ENVELOPE_BYTES + 1],
                    1,
                )
                .is_err(),
                "a WebSocket payload above 16,389 bytes is rejected before parsing"
            );

            let fixture = fixture();
            let harness = fixture
                .provider
                .harness_for_test()
                .expect("test-only A2 harness");
            let (mut client, m1) = fixture.client.start().expect("M1");
            let (mut server, m2) = harness.begin_m1(&harness.resource, &m1).expect("M2");
            let m3 = client.accept_m2_and_make_m3(&m2).expect("M3");
            assert_eq!(server.accept_m3(&harness, &m3), Ok(()));
            let context = harness
                .rechecked_record_context(&server)
                .expect("exact post-claim context");
            let mut pending = server
                .into_pending_finished(context)
                .expect("server-only pending state");
            let premature_c3 = encode_canonical(&A2RecordEnvelope(1, vec![0x7f; 16]))
                .expect("premature C3-shaped envelope");
            assert!(
                pending.accept_c3(&premature_c3).is_err(),
                "C3 before a server-emitted S2 is terminal"
            );
            assert!(pending.s2_wire.is_empty());
            assert_eq!(pending.transport.receiving_nonce(), 0);
            let effects = fixture.effects.snapshot();
            assert_eq!(effects.challenge_claims, 1);
            assert_eq!(effects.verified_peers, 0);
            assert_eq!(effects.mints, 0);
            assert_eq!(effects.consumes, 0);
            assert_eq!(effects.proxy_dials, 0);
            assert_eq!(effects.site_bytes, 0);
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
        fn relay_forwarding_splices_only_a2_ciphertext_and_gets_no_peer_or_site_bytes() {
            let fixture = fixture();
            let harness = fixture
                .provider
                .harness_for_test()
                .expect("test harness provider");

            // Carrier M forwards the same WebSocket but has neither a signing
            // key nor a transport key. M1 names the requested resource; M2/M3
            // and every post-M3 record are Noise protected.
            let (mut device, m1_from_device) = fixture.client.start().expect("M1");
            let initial_handshake_for_carrier = m1_from_device.clone();
            let (mut engine, m2_to_carrier) = harness
                .begin_m1(&harness.resource, &initial_handshake_for_carrier)
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
            let context = harness
                .rechecked_record_context(&engine)
                .expect("exact post-claim snapshot");
            let mut pending = engine
                .into_pending_finished(context)
                .expect("server-only pending record state");
            let s2_to_carrier = pending.emit_s2().expect("encrypted S2");
            assert!(!contains_bytes(&s2_to_carrier, b"npub1owneralpha"));
            assert!(!contains_bytes(&s2_to_carrier, b"owner-action"));
            let c3_from_device = device
                .accept_s2_and_make_c3(&s2_to_carrier)
                .expect("device authenticates S2 before C3");
            let acknowledgement_for_carrier = c3_from_device.clone();
            assert!(!contains_bytes(
                &acknowledgement_for_carrier,
                b"npub1owneralpha"
            ));
            assert_eq!(pending.accept_c3(&acknowledgement_for_carrier), Ok(()));
            assert!(harness.recheck_pending_finished(&pending));

            // A splicing carrier can move only opaque A2 ciphertext.  This
            // transport slice still creates no plaintext success, credential,
            // verified peer, dial, proxy, or site byte after C3.
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

#[cfg(test)]
mod pair1_promotion_tests {
    //! RED for the pair-1 promotion: the roster arm preserves default-deny
    //! until an observation exists, admits only the exact server-owned
    //! resource, and never admits on resource mismatch. The observation is
    //! injected through the refresh-loop slot — the same path production
    //! uses, not a test backdoor into the decision.

    use super::*;
    use crate::owner_site_authority::OwnerSiteAuthorityObservation;

    fn resource(name: &str) -> OwnerSiteResource {
        OwnerSiteResource::from_route_claw(name).expect("valid resource")
    }

    fn observation() -> OwnerSiteAuthorityObservation {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        OwnerSiteAuthorityObservation::from_roster_adapter(
            "hh-test".to_string(),
            1,
            [7u8; 32],
            1,
            0,
            [3u8; 33],
            now,
            now + 86_400,
        )
        .expect("non-degenerate observation")
    }

    #[test]
    fn roster_arm_denies_everything_until_an_observation_exists() {
        let provider = OwnerSiteAkeProvider::for_roster(&resource("claw-a"));
        assert!(
            !provider.admits_resource(&resource("claw-a")),
            "default-deny must hold until the adapter produces an observation"
        );
    }

    #[test]
    fn roster_arm_admits_the_exact_resource_once_observing() {
        let provider = OwnerSiteAkeProvider::for_roster(&resource("claw-a"));
        let slot = provider
            .roster_arm()
            .expect("roster arm present")
            .observation_slot();
        *slot.write().expect("slot write") = Some(observation());

        assert!(provider.admits_resource(&resource("claw-a")));
        assert!(
            !provider.admits_resource(&resource("claw-b")),
            "resource mismatch must still refuse, observation or not"
        );
    }

    #[test]
    fn replacing_the_slot_with_none_closes_again() {
        let provider = OwnerSiteAkeProvider::for_roster(&resource("claw-a"));
        let slot = provider
            .roster_arm()
            .expect("roster arm present")
            .observation_slot();
        *slot.write().expect("slot write") = Some(observation());
        assert!(provider.admits_resource(&resource("claw-a")));
        *slot.write().expect("slot write") = None;
        assert!(!provider.admits_resource(&resource("claw-a")));
    }
}

#[cfg(test)]
mod refresh_budget_tests {
    //! THE REFRESH-FAILURE-BUDGET RED (the coordinator's condition for the
    //! staleness term): the refresh loop stopped (slot holds an OLD
    //! observation whose checkpoint `not_after` is far in the future) and
    //! admission must REFUSE once the observation is older than
    //! REFRESH_FAILURE_BUDGET_SECS — measured at the decision, which is the
    //! effect this module owns. Without this pin the staleness term is
    //! decoration and a future "simplification" removes it.

    use super::*;
    use crate::owner_site_authority::{OwnerSiteAuthorityObservation, REFRESH_FAILURE_BUDGET_SECS};

    fn resource(name: &str) -> OwnerSiteResource {
        OwnerSiteResource::from_route_claw(name).expect("valid resource")
    }

    fn observation_observed_at(
        observed_at: u64,
        checkpoint_not_after: u64,
    ) -> OwnerSiteAuthorityObservation {
        OwnerSiteAuthorityObservation::from_roster_adapter(
            "hh".to_string(),
            1,
            [7u8; 32],
            1,
            0,
            [3u8; 33],
            observed_at,
            checkpoint_not_after,
        )
        .expect("non-degenerate observation")
    }

    #[test]
    fn a_fresh_observation_admits() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let provider = OwnerSiteAkeProvider::for_roster(&resource("claw-a"));
        let slot = provider.roster_arm().unwrap().observation_slot();
        *slot.write().unwrap() = Some(observation_observed_at(now, now + 86_400));
        assert!(provider.admits_resource(&resource("claw-a")));
    }

    #[test]
    fn refresh_stopped_with_future_checkpoint_still_refuses_after_the_budget() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // The checkpoint is valid for another DAY (authority's not_after is
        // far away), but the observation is TEN MINUTES old — the refresh
        // loop has been dead for ten minutes.
        let stale_observation = observation_observed_at(now - 600, now + 86_400);
        assert!(
            !stale_observation.is_fresh_at(now),
            "observed_at + 300s budget has passed: not fresh even with a day of checkpoint validity"
        );
        let provider = OwnerSiteAkeProvider::for_roster(&resource("claw-a"));
        let slot = provider.roster_arm().unwrap().observation_slot();
        *slot.write().unwrap() = Some(stale_observation);
        assert!(
            !provider.admits_resource(&resource("claw-a")),
            "refresh stopped + future not_after must STILL refuse after the budget"
        );
    }

    #[test]
    fn the_authority_ceiling_is_never_exceeded() {
        // not_after is BEFORE observed_at + budget: the min picks the
        // authority, never the budget.
        let obs = observation_observed_at(1_000, 1_100);
        assert!(!obs.is_fresh_at(1_101), "the authority ceiling rules");
        assert!(obs.is_fresh_at(1_100));
    }
}
