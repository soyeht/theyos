//! A2 challenge types and test-only one-shot table.
//!
//! This module reserves the challenge state required by the reviewed A2 profile.
//! It does not mount an endpoint or expose a byte of a backend. Its mutable
//! table remains test-only while there is no reviewed production authority
//! provider; the crate-test AKE harness may use it only after it has the full
//! one-WebSocket M1/M2/M3 context.

#![allow(dead_code)] // staged until a reviewed production authority provider exists

use std::collections::HashMap;
use std::sync::Mutex;

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[cfg(test)]
use crate::owner_site_authority::OwnerSiteBindingDigest;
use crate::owner_site_authority::{
    OwnerSiteAuthorityGeneration, OwnerSiteBindingId, OwnerSiteResolvedBinding,
};
use crate::owner_site_capability::OwnerSiteIntentError;
use crate::owner_site_capability::{OwnerSiteIntent, OwnerSitePreAuthIntent};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Entropy length for the opaque A2 challenge id and distinct challenge secret.
pub(crate) const OWNER_SITE_CHALLENGE_BYTES: usize = 32;

/// Fixed short lifetime from the reviewed A2 profile. The pre-effect table does
/// not accept a caller-selected TTL.
pub(crate) const OWNER_SITE_CHALLENGE_TTL_SECS: u64 = 60;

/// Bounded outstanding server-held challenge state.
const MAX_OUTSTANDING_OWNER_SITE_CHALLENGES: usize = 16_384;

/// Server-created identifier that is safe to name in a future M2 payload. It
/// is an index, never a secret or a bearer capability.
#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct OwnerSiteChallengeId([u8; OWNER_SITE_CHALLENGE_BYTES]);

impl OwnerSiteChallengeId {
    /// The production constructor: CSPRNG bytes, no test gate. Used by the
    /// M1/M2 responder (3a-5 follow-on).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn generate() -> Self {
        random_id()
    }

    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; OWNER_SITE_CHALLENGE_BYTES] {
        &self.0
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn bytes_for_harness(&self) -> &[u8; OWNER_SITE_CHALLENGE_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for OwnerSiteChallengeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnerSiteChallengeId(REDACTED)")
    }
}

/// CSPRNG secret committed to the future `pop_D`. The table never keeps this
/// value in plaintext; it stores only its SHA-256 digest.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct OwnerSiteChallengeSecret([u8; OWNER_SITE_CHALLENGE_BYTES]);

impl OwnerSiteChallengeSecret {
    /// The production constructor: CSPRNG bytes, no test gate. Used by the
    /// M1/M2 responder (3a-5 follow-on).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn generate() -> Self {
        random_secret()
    }

    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; OWNER_SITE_CHALLENGE_BYTES] {
        &self.0
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn bytes_for_harness(&self) -> &[u8; OWNER_SITE_CHALLENGE_BYTES] {
        &self.0
    }
}

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
    /// The production constructor: CSPRNG bytes, no test gate.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self(bytes)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn injected_for_harness(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl OwnerSiteWebSocketInstance {
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// CSPRNG server-owned channel id for the future one-WebSocket A2 session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteChannelId([u8; 32]);

impl OwnerSiteChannelId {
    /// The production constructor: CSPRNG bytes, no test gate.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self(bytes)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn injected_for_harness(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn bytes_for_harness(&self) -> &[u8; 32] {
        &self.0
    }
}

impl OwnerSiteChannelId {
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Nonzero server-owned channel epoch. Reconnect, restart, rekey, and revoke
/// must obtain a new value in the later handshake slice; no resumption exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteChannelEpoch(std::num::NonZeroU64);

impl OwnerSiteChannelEpoch {
    /// The production constructor: validated nonzero, no test gate. The
    /// responder's counter supplies the value; resumption does not exist.
    #[allow(dead_code)]
    pub(crate) fn new(value: u64) -> Result<Self, OwnerSiteChallengeError> {
        std::num::NonZeroU64::new(value)
            .map(Self)
            .ok_or(OwnerSiteChallengeError::ZeroChannelEpoch)
    }

    #[cfg(test)]
    pub(crate) fn injected_for_harness(value: u64) -> Result<Self, OwnerSiteChallengeError> {
        std::num::NonZeroU64::new(value)
            .map(Self)
            .ok_or(OwnerSiteChallengeError::ZeroChannelEpoch)
    }

    #[must_use]
    pub(crate) fn get(self) -> u64 {
        self.0.get()
    }
}

/// Canonical `T1` server-auth transcript commitment from A2 `M2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteTranscriptT1([u8; 32]);

impl OwnerSiteTranscriptT1 {
    /// The production constructor: wraps the T1 the responder JUST computed
    /// with `server_auth_t1` — never wire bytes (the challenge commits the
    /// server's own transcript).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn from_computed_t1(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn injected_for_harness(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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
    /// The production constructor: the engine's own machine-certificate
    /// digest and key id, from the loaded household identity — never from a
    /// peer message.
    #[allow(dead_code)]
    pub(crate) fn from_engine_identity(
        machine_certificate_digest: [u8; 32],
        engine_key_id: &str,
    ) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            machine_certificate_digest,
            engine_key_id: validated_engine_key_id(engine_key_id)?,
        })
    }

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

    #[must_use]
    pub(crate) fn machine_certificate_digest(&self) -> &[u8; 32] {
        &self.machine_certificate_digest
    }

    #[must_use]
    pub(crate) fn engine_key_id(&self) -> &str {
        &self.engine_key_id
    }
}

/// Engine key ids are not route components. The canonical A2 grammar accepts
/// the existing `engine:test` and `engine.v1` forms while remaining bounded and
/// ASCII-only; the AKE/provider slice will bind the exact id to a household
/// authority before it has any meaning.
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
    /// The production constructor for the responder's `begin_m1`: every field
    /// arrives from server-held state (see the field docs above).
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_responder(
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
    /// The production constructor: builds the claim scope from the server's
    /// OWN session state (issue from `begin_m1`, resolved intent and binding
    /// from roster resolution), with the same consistency checks as the
    /// harness path.
    #[allow(dead_code)]
    pub(crate) fn from_session(
        issue: OwnerSiteChallengeIssueScope,
        resolved_intent: OwnerSiteIntent,
        resolved_binding: OwnerSiteResolvedBinding,
    ) -> Result<Self, OwnerSiteChallengeError> {
        if issue.pre_auth_intent != *resolved_intent.pre_auth()
            || issue.claimed_binding_id != resolved_binding.binding_id()
            || issue.authority_generation.digest() == [0; 32]
        {
            return Err(OwnerSiteChallengeError::ClaimContextMismatch);
        }
        if issue.authority_generation.authz_epoch() == 0 {
            return Err(OwnerSiteChallengeError::ClaimContextMismatch);
        }
        Ok(Self {
            issue,
            resolved_intent,
            resolved_binding,
        })
    }

    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        issue: OwnerSiteChallengeIssueScope,
        resolved_intent: OwnerSiteIntent,
        resolved_binding: OwnerSiteResolvedBinding,
    ) -> Result<Self, OwnerSiteChallengeError> {
        if issue.pre_auth_intent != *resolved_intent.pre_auth()
            || issue.claimed_binding_id != resolved_binding.binding_id()
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
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteIssuedChallenge {
    challenge_id: OwnerSiteChallengeId,
    challenge_secret: OwnerSiteChallengeSecret,
}

impl OwnerSiteIssuedChallenge {
    /// Generates the opaque challenge material before T1 is assembled.  The
    /// A2 transcript commits both values, so a later atomic table insertion
    /// receives the completed issue scope rather than accepting caller-chosen
    /// entropy.
    /// The production constructor: CSPRNG challenge material, no test gate.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn generate() -> Self {
        Self {
            challenge_id: random_id(),
            challenge_secret: random_secret(),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn generated_for_ake_harness() -> Self {
        Self::generate()
    }

    /// The issued id, for the M2 wire and the transcript commit.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn id(&self) -> &OwnerSiteChallengeId {
        &self.challenge_id
    }

    /// The issued secret, for the M2 wire and the transcript commit.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn secret(&self) -> &OwnerSiteChallengeSecret {
        &self.challenge_secret
    }

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerSiteChallengeState {
    Unused,
}

/// The bounded one-shot A2 challenge table, PROMOTED to production (S2).
///
/// DOWNGRADE, SAID OUT LOUD: before this promotion, no challenge could exist
/// in production at all — fail-closed by ABSENCE, the table uninhabitable.
/// After it, challenges exist under bounds: capacity, 60s TTL, one-shot
/// atomic claim, and the authority-lease check (`AuthorityLeaseTooShort` —
/// a challenge may never outlive the authority freshness that issued it).
/// That is fail-closed by DECISION, strictly weaker than absence. Named so
/// the next reader does not mistake a promoted guarantee for a kept one.
pub(crate) struct OwnerSiteChallengeTable {
    entries: Mutex<HashMap<OwnerSiteChallengeId, OwnerSiteChallengeEntry>>,
    capacity: usize,
}

#[allow(dead_code)] // consumed by the A2 responder (next increment)
impl OwnerSiteChallengeTable {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_capacity(MAX_OUTSTANDING_OWNER_SITE_CHALLENGES)
    }

    #[must_use]
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Generates distinct CSPRNG id and secret values, retaining only
    /// `SHA-256(secret)` plus the complete pre-auth A2 issuance context.
    pub(crate) fn issue(
        &self,
        issue: OwnerSiteChallengeIssueScope,
        now_unix: u64,
    ) -> Result<OwnerSiteIssuedChallenge, OwnerSiteChallengeError> {
        let issued = OwnerSiteIssuedChallenge::generate();
        self.insert_generated(issue, &issued, now_unix)?;
        Ok(issued)
    }

    /// Inserts CSPRNG material already generated by the A2 responder after it
    /// has committed that exact material into T1.  This is crate-test-only
    /// while no reviewed production authority provider can enter the handler.
    pub(crate) fn insert_generated(
        &self,
        issue: OwnerSiteChallengeIssueScope,
        issued: &OwnerSiteIssuedChallenge,
        now_unix: u64,
    ) -> Result<(), OwnerSiteChallengeError> {
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

        if entries.contains_key(&issued.challenge_id) {
            return Err(OwnerSiteChallengeError::CapacityReached);
        }
        let challenge_hash = hash_secret(&issued.challenge_secret);
        entries.insert(
            issued.challenge_id.clone(),
            OwnerSiteChallengeEntry {
                challenge_hash,
                issue,
                expires_at,
                state: OwnerSiteChallengeState::Unused,
            },
        );
        Ok(())
    }

    /// Atomically removes one exact, unexpired entry after the caller supplies
    /// the full M3-resolved scope and the secret that hashes to the stored
    /// digest. A wrong secret or scope deliberately leaves the entry intact.
    pub(crate) fn claim_once(
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

    /// Removes a challenge only after the AKE verifier has proved possession
    /// of its secret by verifying `pop_D` over the exact local challenge.
    ///
    /// The secret is intentionally not echoed in M3: the table retains only
    /// its hash, while the ephemeral M1/M2/M3 state supplies it to the signed
    /// transcript verifier before this atomic transition.
    pub(crate) fn claim_after_verified_pop(
        &self,
        challenge_id: &OwnerSiteChallengeId,
        expected: &OwnerSiteChallengeClaimScope,
        now_unix: u64,
    ) -> Result<(), OwnerSiteChallengeError> {
        let mut entries = self.lock_entries()?;
        entries.retain(|_, entry| entry.expires_at > now_unix);
        let entry = entries
            .get(challenge_id)
            .ok_or(OwnerSiteChallengeError::MissingOrExpired)?;
        if entry.state != OwnerSiteChallengeState::Unused || entry.issue != expected.issue {
            return Err(OwnerSiteChallengeError::ClaimContextMismatch);
        }
        entries.remove(challenge_id);
        Ok(())
    }

    pub(crate) fn outstanding(&self, now_unix: u64) -> Result<usize, OwnerSiteChallengeError> {
        let mut entries = self.lock_entries()?;
        entries.retain(|_, entry| entry.expires_at > now_unix);
        Ok(entries.len())
    }

    pub(crate) fn stored_hash(
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

fn random_id() -> OwnerSiteChallengeId {
    let mut bytes = [0u8; OWNER_SITE_CHALLENGE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    OwnerSiteChallengeId(bytes)
}

fn random_secret() -> OwnerSiteChallengeSecret {
    let mut bytes = [0u8; OWNER_SITE_CHALLENGE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    OwnerSiteChallengeSecret(bytes)
}

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
        let table = OwnerSiteChallengeTable::new();
        let (issue, claim) = matching_scopes();
        let issued = table.issue(issue, 1_000).expect("challenge");
        let stored = table
            .stored_hash(issued.id_for_harness())
            .expect("stored hash");

        assert_ne!(stored, issued.secret_for_harness().0);
        assert_eq!(table.outstanding(1_001), Ok(1));
        assert_eq!(
            table.claim_once(
                issued.id_for_harness(),
                issued.secret_for_harness(),
                &claim,
                1_001,
            ),
            Ok(())
        );
        assert_eq!(table.outstanding(1_002), Ok(0));
    }

    #[test]
    fn wrong_secret_ws_channel_or_canonical_request_does_not_claim() {
        let table = OwnerSiteChallengeTable::new();
        let (issue, claim) = matching_scopes();
        let issued = table.issue(issue, 1_000).expect("challenge");
        let wrong_secret = OwnerSiteChallengeSecret([0x99; OWNER_SITE_CHALLENGE_BYTES]);
        assert_eq!(
            table.claim_once(issued.id_for_harness(), &wrong_secret, &claim, 1_001,),
            Err(OwnerSiteChallengeError::ClaimContextMismatch)
        );
        assert_eq!(table.outstanding(1_001), Ok(1));

        let wrong_ws = issue_scope(
            "/api/v1/household/claws/{name}/owner-site/preflight",
            [0x44; 32],
            0x12,
            0x22,
        );
        let wrong_ws_claim = claim_scope(wrong_ws, [0x44; 32]).expect("wrong-ws claim scope");
        assert_eq!(
            table.claim_once(
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
            table.claim_once(
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
        assert_eq!(table.outstanding(1_001), Ok(1));
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
        let table = OwnerSiteChallengeTable::with_capacity(1);
        let (issue, _) = matching_scopes();
        let issued = table.issue(issue.clone(), 1_000).expect("challenge");
        assert_eq!(
            table.issue(issue.clone(), 1_001),
            Err(OwnerSiteChallengeError::CapacityReached)
        );
        assert_eq!(table.outstanding(1_060), Ok(0));

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
            table.issue(too_short, 1_000),
            Err(OwnerSiteChallengeError::AuthorityLeaseTooShort)
        );
        assert_eq!(
            table.claim_once(
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
        let table = Arc::new(OwnerSiteChallengeTable::new());
        let (issue, claim) = matching_scopes();
        let issued = table.issue(issue, 1_000).expect("challenge");
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
                    .claim_once(&challenge_id, &challenge_secret, &claim, 1_001)
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
        let table = Arc::new(OwnerSiteChallengeTable::new());
        let poison = Arc::clone(&table);
        let _ = std::thread::spawn(move || {
            let _guard = poison.entries.lock().expect("lock");
            panic!("intentional test poison");
        })
        .join();

        let (issue, _) = matching_scopes();
        assert_eq!(
            table.issue(issue, 1_000),
            Err(OwnerSiteChallengeError::Unavailable)
        );
    }
}

#[cfg(test)]
mod production_constructor_tests {
    //! REDs for the production constructors: CSPRNG material differs across
    //! calls (a constant-source mutant fails), epochs are nonzero, and the
    //! harness constructors keep their exact old behavior.

    use super::*;

    #[test]
    fn two_generated_challenges_differ() {
        let a = OwnerSiteIssuedChallenge::generate();
        let b = OwnerSiteIssuedChallenge::generate();
        assert_ne!(a.id().as_bytes(), b.id().as_bytes());
        assert_ne!(a.secret().as_bytes(), b.secret().as_bytes());
    }

    #[test]
    fn channel_ids_and_ws_instances_are_random_per_call() {
        assert_ne!(
            OwnerSiteChannelId::generate().as_bytes(),
            OwnerSiteChannelId::generate().as_bytes()
        );
        assert_ne!(
            OwnerSiteWebSocketInstance::generate().as_bytes(),
            OwnerSiteWebSocketInstance::generate().as_bytes()
        );
    }

    #[test]
    fn production_epoch_rejects_zero() {
        assert!(OwnerSiteChannelEpoch::new(0).is_err());
        assert_eq!(OwnerSiteChannelEpoch::new(7).unwrap().get(), 7);
    }
}
