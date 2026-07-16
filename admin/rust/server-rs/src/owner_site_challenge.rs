//! Pre-effect A2 challenge types and test-only one-shot table.
//!
//! This module reserves the challenge state required by the reviewed A2
//! profile. It does not mount an endpoint, parse a WebSocket message, construct
//! a Noise handshake, validate a signature, or expose a byte of a backend.
//! In particular, its mutable table API is test-only until the later M1/M2/M3
//! handler can supply the complete A2 context on one verified WebSocket.

#![allow(dead_code)] // deliberately staged, unreachable until the reviewed A2 handler slice

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;

#[cfg(test)]
use rand::RngCore;
#[cfg(test)]
use rand::rngs::OsRng;
#[cfg(test)]
use sha2::{Digest, Sha256};
#[cfg(test)]
use subtle::ConstantTimeEq;

#[cfg(test)]
use crate::owner_site_authority::OwnerSiteBindingDigest;
use crate::owner_site_authority::{
    OwnerSiteAuthorityGeneration, OwnerSiteBindingId, OwnerSiteResolvedBinding,
};
#[cfg(test)]
use crate::owner_site_capability::OwnerSiteIntentError;
use crate::owner_site_capability::{OwnerSiteIntent, OwnerSitePreAuthIntent};

/// Entropy length for the opaque A2 challenge id and distinct challenge secret.
pub(crate) const OWNER_SITE_CHALLENGE_BYTES: usize = 32;

/// Fixed short lifetime from the reviewed A2 profile. The pre-effect table does
/// not accept a caller-selected TTL.
pub(crate) const OWNER_SITE_CHALLENGE_TTL_SECS: u64 = 60;

/// Bounded outstanding server-held challenge state.
#[cfg(test)]
const MAX_OUTSTANDING_OWNER_SITE_CHALLENGES: usize = 16_384;

/// Server-created identifier that is safe to name in a future M2 payload. It
/// is an index, never a secret or a bearer capability.
#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct OwnerSiteChallengeId([u8; OWNER_SITE_CHALLENGE_BYTES]);

impl std::fmt::Debug for OwnerSiteChallengeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnerSiteChallengeId(REDACTED)")
    }
}

/// CSPRNG secret committed to the future `pop_D`. The table never keeps this
/// value in plaintext; it stores only its SHA-256 digest.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct OwnerSiteChallengeSecret([u8; OWNER_SITE_CHALLENGE_BYTES]);

impl std::fmt::Debug for OwnerSiteChallengeSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnerSiteChallengeSecret(REDACTED)")
    }
}

/// Server-owned identifier for exactly one accepted WebSocket instance.
///
/// It is not a socket address, HTTP header, client field, or transferable
/// session id. A later A2 handler will generate it after the local
/// `Ready + VerifiedMeshLocalAddress` gate succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteWebSocketInstance([u8; 32]);

impl OwnerSiteWebSocketInstance {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn injected_for_harness(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// CSPRNG server-owned channel id for the future one-WebSocket A2 session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteChannelId([u8; 32]);

impl OwnerSiteChannelId {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn injected_for_harness(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Nonzero server-owned channel epoch. Reconnect, restart, rekey, and revoke
/// must obtain a new value in the later handshake slice; no resumption exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteChannelEpoch(std::num::NonZeroU64);

impl OwnerSiteChannelEpoch {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(value: u64) -> Result<Self, OwnerSiteChallengeError> {
        std::num::NonZeroU64::new(value)
            .map(Self)
            .ok_or(OwnerSiteChallengeError::ZeroChannelEpoch)
    }
}

/// Canonical `T1` server-auth transcript commitment from A2 `M2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteTranscriptT1([u8; 32]);

impl OwnerSiteTranscriptT1 {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn injected_for_harness(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Engine identity commitment that the later M2 transcript must bind before a
/// device signs channel material. The actual machine-certificate verification
/// belongs to the AKE/provider slice; this shape prevents the certificate and
/// key id from being silently omitted from challenge state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteEngineIdentityCommitment {
    machine_certificate_digest: [u8; 32],
    engine_key_id: String,
}

impl OwnerSiteEngineIdentityCommitment {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        machine_certificate_digest: [u8; 32],
        engine_key_id: &str,
    ) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            machine_certificate_digest,
            engine_key_id: validated_engine_key_id(engine_key_id)?,
        })
    }
}

/// Engine key ids are not route components. The canonical A2 grammar accepts
/// the existing `engine:test` and `engine.v1` forms while remaining bounded and
/// ASCII-only; the AKE/provider slice will bind the exact id to a household
/// authority before it has any meaning.
#[cfg(test)]
fn validated_engine_key_id(value: &str) -> Result<String, OwnerSiteIntentError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(OwnerSiteIntentError::InvalidComponent);
    }
    Ok(value.to_owned())
}

/// All context known when the engine emits A2 `M2`/`S1`.
///
/// It intentionally contains only the unauthenticated canonical `C1` intent
/// and a claimed binding index. It has no actor, remote principal, resolved
/// binding, or final action `PoP`: those become available only after `M3`/`C2`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteChallengeIssueScope {
    pre_auth_intent: OwnerSitePreAuthIntent,
    claimed_binding_id: OwnerSiteBindingId,
    ws_instance: OwnerSiteWebSocketInstance,
    channel_id: OwnerSiteChannelId,
    channel_epoch: OwnerSiteChannelEpoch,
    engine_identity: OwnerSiteEngineIdentityCommitment,
    transcript_t1: OwnerSiteTranscriptT1,
    authority_generation: OwnerSiteAuthorityGeneration,
    fresh_until: u64,
}

impl OwnerSiteChallengeIssueScope {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn injected_for_harness(
        pre_auth_intent: OwnerSitePreAuthIntent,
        claimed_binding_id: OwnerSiteBindingId,
        ws_instance: OwnerSiteWebSocketInstance,
        channel_id: OwnerSiteChannelId,
        channel_epoch: OwnerSiteChannelEpoch,
        engine_identity: OwnerSiteEngineIdentityCommitment,
        transcript_t1: OwnerSiteTranscriptT1,
        authority_generation: OwnerSiteAuthorityGeneration,
        fresh_until: u64,
    ) -> Self {
        Self {
            pre_auth_intent,
            claimed_binding_id,
            ws_instance,
            channel_id,
            channel_epoch,
            engine_identity,
            transcript_t1,
            authority_generation,
            fresh_until,
        }
    }
}

/// Full server-side context expected when a later A2 `M3` has been validated.
///
/// It binds the one-shot secret to the same `C1`/`M2` context *and* to one
/// exact local C-resolution. There is no constructor in production before the
/// AKE slice, and this is never derived from an address or `ConnectInfo`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteChallengeClaimScope {
    issue: OwnerSiteChallengeIssueScope,
    resolved_intent: OwnerSiteIntent,
    resolved_binding: OwnerSiteResolvedBinding,
}

impl OwnerSiteChallengeClaimScope {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        issue: OwnerSiteChallengeIssueScope,
        resolved_intent: OwnerSiteIntent,
        resolved_binding: OwnerSiteResolvedBinding,
    ) -> Result<Self, OwnerSiteChallengeError> {
        if issue.pre_auth_intent != *resolved_intent.pre_auth()
            || issue.claimed_binding_id != resolved_binding.binding_id_for_harness()
            || issue.authority_generation.digest() == [0; 32]
        {
            return Err(OwnerSiteChallengeError::ClaimContextMismatch);
        }
        if issue.authority_generation.authz_epoch() == 0 {
            return Err(OwnerSiteChallengeError::ClaimContextMismatch);
        }
        let _ = (
            resolved_binding.binding_digest_for_harness(),
            resolved_binding.participant_npub_for_harness(),
            resolved_binding.channel_auth_key_id_for_harness(),
            resolved_binding.action_pop_key_id_for_harness(),
        );
        Ok(Self {
            issue,
            resolved_intent,
            resolved_binding,
        })
    }
}

/// Material a future `M2` carries to the client. The final A2 CBOR encoding is
/// deliberately not implemented in this pre-effect slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteIssuedChallenge {
    challenge_id: OwnerSiteChallengeId,
    challenge_secret: OwnerSiteChallengeSecret,
}

impl OwnerSiteIssuedChallenge {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn id_for_harness(&self) -> &OwnerSiteChallengeId {
        &self.challenge_id
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn secret_for_harness(&self) -> &OwnerSiteChallengeSecret {
        &self.challenge_secret
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnerSiteChallengeEntry {
    challenge_hash: [u8; 32],
    issue: OwnerSiteChallengeIssueScope,
    expires_at: u64,
    state: OwnerSiteChallengeState,
}

/// The only state present before atomic claim is `Unused`. A later handler
/// removes the entry at its point of no return; there is no retry/resumption
/// state in this model.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerSiteChallengeState {
    Unused,
}

/// Test-only implementation of the bounded one-shot A2 challenge table.
///
/// Keeping mutation under `cfg(test)` prevents the pre-effect HTTP endpoint
/// from accidentally becoming an issuance or claim surface. The later AKE PR
/// must promote it only together with the single-WS local gate and full M1/M2/
/// M3 validation order.
#[cfg(test)]
pub(crate) struct OwnerSiteChallengeTable {
    entries: Mutex<HashMap<OwnerSiteChallengeId, OwnerSiteChallengeEntry>>,
    capacity: usize,
}

#[cfg(test)]
impl OwnerSiteChallengeTable {
    #[must_use]
    pub(crate) fn new_for_harness() -> Self {
        Self::with_capacity_for_harness(MAX_OUTSTANDING_OWNER_SITE_CHALLENGES)
    }

    #[must_use]
    pub(crate) fn with_capacity_for_harness(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Generates distinct CSPRNG id and secret values, retaining only
    /// `SHA-256(secret)` plus the complete pre-auth A2 issuance context.
    pub(crate) fn issue_for_harness(
        &self,
        issue: OwnerSiteChallengeIssueScope,
        now_unix: u64,
    ) -> Result<OwnerSiteIssuedChallenge, OwnerSiteChallengeError> {
        let expires_at = now_unix
            .checked_add(OWNER_SITE_CHALLENGE_TTL_SECS)
            .ok_or(OwnerSiteChallengeError::ClockOverflow)?;
        if issue.fresh_until <= now_unix || issue.fresh_until < expires_at {
            return Err(OwnerSiteChallengeError::AuthorityLeaseTooShort);
        }
        let mut entries = self.lock_entries()?;
        entries.retain(|_, entry| entry.expires_at > now_unix);
        if entries.len() >= self.capacity {
            return Err(OwnerSiteChallengeError::CapacityReached);
        }

        loop {
            let challenge_id = random_id();
            if entries.contains_key(&challenge_id) {
                continue;
            }
            let challenge_secret = random_secret();
            let challenge_hash = hash_secret(&challenge_secret);
            entries.insert(
                challenge_id.clone(),
                OwnerSiteChallengeEntry {
                    challenge_hash,
                    issue,
                    expires_at,
                    state: OwnerSiteChallengeState::Unused,
                },
            );
            return Ok(OwnerSiteIssuedChallenge {
                challenge_id,
                challenge_secret,
            });
        }
    }

    /// Atomically removes one exact, unexpired entry after the caller supplies
    /// the full M3-resolved scope and the secret that hashes to the stored
    /// digest. A wrong secret or scope deliberately leaves the entry intact.
    pub(crate) fn claim_once_for_harness(
        &self,
        challenge_id: &OwnerSiteChallengeId,
        challenge_secret: &OwnerSiteChallengeSecret,
        expected: &OwnerSiteChallengeClaimScope,
        now_unix: u64,
    ) -> Result<(), OwnerSiteChallengeError> {
        let mut entries = self.lock_entries()?;
        entries.retain(|_, entry| entry.expires_at > now_unix);
        let entry = entries
            .get(challenge_id)
            .ok_or(OwnerSiteChallengeError::MissingOrExpired)?;
        if entry.state != OwnerSiteChallengeState::Unused
            || entry.issue != expected.issue
            || !bool::from(entry.challenge_hash.ct_eq(&hash_secret(challenge_secret)))
        {
            return Err(OwnerSiteChallengeError::ClaimContextMismatch);
        }
        entries.remove(challenge_id);
        Ok(())
    }

    #[must_use]
    pub(crate) fn outstanding_for_harness(
        &self,
        now_unix: u64,
    ) -> Result<usize, OwnerSiteChallengeError> {
        let mut entries = self.lock_entries()?;
        entries.retain(|_, entry| entry.expires_at > now_unix);
        Ok(entries.len())
    }

    #[must_use]
    pub(crate) fn stored_hash_for_harness(
        &self,
        challenge_id: &OwnerSiteChallengeId,
    ) -> Result<[u8; 32], OwnerSiteChallengeError> {
        self.lock_entries()?
            .get(challenge_id)
            .map(|entry| entry.challenge_hash)
            .ok_or(OwnerSiteChallengeError::MissingOrExpired)
    }

    fn lock_entries(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, HashMap<OwnerSiteChallengeId, OwnerSiteChallengeEntry>>,
        OwnerSiteChallengeError,
    > {
        self.entries
            .lock()
            .map_err(|_| OwnerSiteChallengeError::Unavailable)
    }
}

#[cfg(test)]
fn random_id() -> OwnerSiteChallengeId {
    let mut bytes = [0u8; OWNER_SITE_CHALLENGE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    OwnerSiteChallengeId(bytes)
}

#[cfg(test)]
fn random_secret() -> OwnerSiteChallengeSecret {
    let mut bytes = [0u8; OWNER_SITE_CHALLENGE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    OwnerSiteChallengeSecret(bytes)
}

#[cfg(test)]
fn hash_secret(secret: &OwnerSiteChallengeSecret) -> [u8; 32] {
    Sha256::digest(secret.0).into()
}

/// Fail-closed outcomes reserved for the future A2 claim sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSiteChallengeError {
    ZeroChannelEpoch,
    ClaimContextMismatch,
    AuthorityLeaseTooShort,
    ClockOverflow,
    CapacityReached,
    MissingOrExpired,
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner_site_authority::{
        OwnerSiteActionPopKey, OwnerSiteChannelAuthKey, OwnerSiteResolvedBinding,
    };
    use crate::owner_site_capability::{
        OwnerSiteCanonicalRequest, OwnerSiteRequestMethod, OwnerSiteResource,
    };
    use household_rs::keys::{IdentityKey, P256Keypair};
    use std::sync::{Arc, Barrier};

    fn ids() -> (OwnerSiteBindingId, OwnerSiteBindingDigest) {
        (
            OwnerSiteBindingId::injected_for_harness([0x01; 32]).expect("binding id"),
            OwnerSiteBindingDigest::injected_for_harness([0x51; 32]).expect("binding digest"),
        )
    }

    fn issue_scope(
        route: &str,
        body_hash: [u8; 32],
        ws_byte: u8,
        channel_byte: u8,
    ) -> OwnerSiteChallengeIssueScope {
        let resource = OwnerSiteResource::from_route_claw("picoclaw").expect("resource");
        let request = OwnerSiteCanonicalRequest::injected_for_harness(
            OwnerSiteRequestMethod::Post,
            route,
            body_hash,
        )
        .expect("canonical request");
        let intent = OwnerSiteIntent::injected_for_harness_with_request(
            "household-alpha",
            "owner-site-mesh",
            "owner-alpha",
            resource,
            request,
        )
        .expect("resolved intent");
        let (binding_id, _) = ids();
        OwnerSiteChallengeIssueScope::injected_for_harness(
            intent.pre_auth().clone(),
            binding_id,
            OwnerSiteWebSocketInstance::injected_for_harness([ws_byte; 32]),
            OwnerSiteChannelId::injected_for_harness([channel_byte; 32]),
            OwnerSiteChannelEpoch::injected_for_harness(1).expect("epoch"),
            OwnerSiteEngineIdentityCommitment::injected_for_harness([0x66; 32], "engine:test.v1")
                .expect("engine identity"),
            OwnerSiteTranscriptT1::injected_for_harness([0x77; 32]),
            OwnerSiteAuthorityGeneration::injected_for_harness(7, [0x88; 32]).expect("generation"),
            1_100,
        )
    }

    fn claim_scope(
        issue: OwnerSiteChallengeIssueScope,
        body_hash: [u8; 32],
    ) -> Result<OwnerSiteChallengeClaimScope, OwnerSiteChallengeError> {
        let resource = OwnerSiteResource::from_route_claw("picoclaw").expect("resource");
        let request = OwnerSiteCanonicalRequest::injected_for_harness(
            OwnerSiteRequestMethod::Post,
            "/api/v1/household/claws/{name}/owner-site/preflight",
            body_hash,
        )
        .expect("canonical request");
        let intent = OwnerSiteIntent::injected_for_harness_with_request(
            "household-alpha",
            "owner-site-mesh",
            "owner-alpha",
            resource,
            request,
        )
        .expect("resolved intent");
        let (binding_id, binding_digest) = ids();
        let channel_auth = P256Keypair::generate();
        let action_pop = P256Keypair::generate();
        let resolved = OwnerSiteResolvedBinding::injected_for_harness(
            binding_id,
            binding_digest,
            "npub1owneralpha",
            OwnerSiteChannelAuthKey::injected_for_harness(
                "channel-auth-alpha",
                channel_auth.public(),
            )
            .expect("channel auth key"),
            OwnerSiteActionPopKey::injected_for_harness("action-pop-alpha", action_pop.public())
                .expect("action pop key"),
        )
        .expect("resolved binding");
        OwnerSiteChallengeClaimScope::injected_for_harness(issue, intent, resolved)
    }

    fn matching_scopes() -> (OwnerSiteChallengeIssueScope, OwnerSiteChallengeClaimScope) {
        let issue = issue_scope(
            "/api/v1/household/claws/{name}/owner-site/preflight",
            [0x44; 32],
            0x11,
            0x22,
        );
        let claim = claim_scope(issue.clone(), [0x44; 32]).expect("matching claim scope");
        (issue, claim)
    }

    #[test]
    fn issue_keeps_only_hash_of_distinct_csprng_secret_and_claims_once() {
        let table = OwnerSiteChallengeTable::new_for_harness();
        let (issue, claim) = matching_scopes();
        let issued = table.issue_for_harness(issue, 1_000).expect("challenge");
        let stored = table
            .stored_hash_for_harness(issued.id_for_harness())
            .expect("stored hash");

        assert_ne!(stored, issued.secret_for_harness().0);
        assert_eq!(table.outstanding_for_harness(1_001), Ok(1));
        assert_eq!(
            table.claim_once_for_harness(
                issued.id_for_harness(),
                issued.secret_for_harness(),
                &claim,
                1_001,
            ),
            Ok(())
        );
        assert_eq!(table.outstanding_for_harness(1_002), Ok(0));
    }

    #[test]
    fn wrong_secret_ws_channel_or_canonical_request_does_not_claim() {
        let table = OwnerSiteChallengeTable::new_for_harness();
        let (issue, claim) = matching_scopes();
        let issued = table.issue_for_harness(issue, 1_000).expect("challenge");
        let wrong_secret = OwnerSiteChallengeSecret([0x99; OWNER_SITE_CHALLENGE_BYTES]);
        assert_eq!(
            table.claim_once_for_harness(issued.id_for_harness(), &wrong_secret, &claim, 1_001,),
            Err(OwnerSiteChallengeError::ClaimContextMismatch)
        );
        assert_eq!(table.outstanding_for_harness(1_001), Ok(1));

        let wrong_ws = issue_scope(
            "/api/v1/household/claws/{name}/owner-site/preflight",
            [0x44; 32],
            0x12,
            0x22,
        );
        let wrong_ws_claim = claim_scope(wrong_ws, [0x44; 32]).expect("wrong-ws claim scope");
        assert_eq!(
            table.claim_once_for_harness(
                issued.id_for_harness(),
                issued.secret_for_harness(),
                &wrong_ws_claim,
                1_001,
            ),
            Err(OwnerSiteChallengeError::ClaimContextMismatch)
        );

        let wrong_channel = issue_scope(
            "/api/v1/household/claws/{name}/owner-site/preflight",
            [0x44; 32],
            0x11,
            0x23,
        );
        let wrong_channel_claim =
            claim_scope(wrong_channel, [0x44; 32]).expect("wrong-channel claim scope");
        assert_eq!(
            table.claim_once_for_harness(
                issued.id_for_harness(),
                issued.secret_for_harness(),
                &wrong_channel_claim,
                1_001,
            ),
            Err(OwnerSiteChallengeError::ClaimContextMismatch)
        );

        let wrong_request = issue_scope(
            "/api/v1/household/claws/{name}/owner-site/preflight",
            [0x45; 32],
            0x11,
            0x22,
        );
        assert_eq!(
            claim_scope(wrong_request, [0x44; 32]),
            Err(OwnerSiteChallengeError::ClaimContextMismatch)
        );
        assert_eq!(table.outstanding_for_harness(1_001), Ok(1));
    }

    #[test]
    fn engine_identity_key_id_uses_the_a2_specific_canonical_grammar() {
        assert!(
            OwnerSiteEngineIdentityCommitment::injected_for_harness([0x66; 32], "engine:test.v1",)
                .is_ok()
        );
        assert!(
            OwnerSiteEngineIdentityCommitment::injected_for_harness([0x66; 32], "engine key",)
                .is_err()
        );
    }

    #[test]
    fn expiry_capacity_and_short_authority_lease_fail_closed() {
        let table = OwnerSiteChallengeTable::with_capacity_for_harness(1);
        let (issue, _) = matching_scopes();
        let issued = table
            .issue_for_harness(issue.clone(), 1_000)
            .expect("challenge");
        assert_eq!(
            table.issue_for_harness(issue.clone(), 1_001),
            Err(OwnerSiteChallengeError::CapacityReached)
        );
        assert_eq!(table.outstanding_for_harness(1_060), Ok(0));

        let too_short = OwnerSiteChallengeIssueScope::injected_for_harness(
            issue.pre_auth_intent,
            issue.claimed_binding_id,
            issue.ws_instance,
            issue.channel_id,
            issue.channel_epoch,
            issue.engine_identity,
            issue.transcript_t1,
            issue.authority_generation,
            1_059,
        );
        assert_eq!(
            table.issue_for_harness(too_short, 1_000),
            Err(OwnerSiteChallengeError::AuthorityLeaseTooShort)
        );
        assert_eq!(
            table.claim_once_for_harness(
                issued.id_for_harness(),
                issued.secret_for_harness(),
                &matching_scopes().1,
                1_060,
            ),
            Err(OwnerSiteChallengeError::MissingOrExpired)
        );
    }

    #[test]
    fn concurrent_claim_has_exactly_one_winner() {
        let table = Arc::new(OwnerSiteChallengeTable::new_for_harness());
        let (issue, claim) = matching_scopes();
        let issued = table.issue_for_harness(issue, 1_000).expect("challenge");
        let barrier = Arc::new(Barrier::new(3));
        let mut joins = Vec::new();

        for _ in 0..2 {
            let table = Arc::clone(&table);
            let claim = claim.clone();
            let challenge_id = issued.id_for_harness().clone();
            let challenge_secret = issued.secret_for_harness().clone();
            let barrier = Arc::clone(&barrier);
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                table
                    .claim_once_for_harness(&challenge_id, &challenge_secret, &claim, 1_001)
                    .is_ok()
            }));
        }
        barrier.wait();

        assert_eq!(
            joins
                .into_iter()
                .map(|join| join.join().expect("claim thread"))
                .filter(|won| *won)
                .count(),
            1
        );
    }

    #[test]
    fn poisoned_table_fails_closed() {
        let table = Arc::new(OwnerSiteChallengeTable::new_for_harness());
        let poison = Arc::clone(&table);
        let _ = std::thread::spawn(move || {
            let _guard = poison.entries.lock().expect("lock");
            panic!("intentional test poison");
        })
        .join();

        let (issue, _) = matching_scopes();
        assert_eq!(
            table.issue_for_harness(issue, 1_000),
            Err(OwnerSiteChallengeError::Unavailable)
        );
    }
}
