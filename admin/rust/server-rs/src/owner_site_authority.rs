//! Pre-effect owner-site membership and roster authority types.
//!
//! This is deliberately a typed *shape*, not a production authority provider.
//! A [`household_rs::MemberDeviceBinding`] verifies that a member key vouched
//! for a device key and participant identity. It does not make that member
//! trusted for a household, identify an incoming TCP connection, or establish
//! that a roster was signed by the household owner. Those three properties stay
//! fail-closed until the reviewed remote-principal and roster-provider slices.
//!
//! In particular, this module does not read `ConnectInfo`, addresses, interface
//! names, or mesh projections. The sole admitting variant is compiled only for
//! crate tests; production has no constructor that can produce an authority.

#![allow(dead_code)] // deliberately staged, unreachable until the reviewed A2/provider slices

use std::num::NonZeroU64;

use household_rs::{MemberDeviceBinding, P256PublicKey};

use crate::owner_site_capability::{OwnerSiteIntent, OwnerSiteResource};
#[cfg(test)]
use crate::owner_site_capability::{
    OwnerSiteIntentError, validated_component, validated_server_identifier,
};

/// Version reserved for the future signed owner-site roster envelope.
///
/// No parser, signer, verifier, persistence, or provider accepts this shape in
/// this PR. Keeping the version private to server types prevents a provisional
/// HTTP or A2 encoding from becoming a protocol commitment.
pub(crate) const OWNER_SITE_ROSTER_VERSION: u8 = 1;

/// Opaque identity expected from the future reviewed connection-principal
/// boundary.
///
/// It is intentionally an identity string, never an IP address or a client
/// supplied request field. Production cannot construct one in this slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteRemotePrincipal {
    participant_npub: String,
}

impl OwnerSiteRemotePrincipal {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        participant_npub: &str,
    ) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            participant_npub: validated_component(participant_npub)?,
        })
    }

    #[must_use]
    pub(crate) fn participant_npub(&self) -> &str {
        &self.participant_npub
    }
}

/// Monotonic authorization epoch plus the opaque digest of the authoritative
/// roster content for one household/network scope.
///
/// The epoch is deliberately not a timestamp. A future durable provider must
/// reject rollback or a conflicting digest before it can emit this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteAuthorityGeneration {
    authz_epoch: NonZeroU64,
    digest: [u8; 32],
}

impl OwnerSiteAuthorityGeneration {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        authz_epoch: u64,
        digest: [u8; 32],
    ) -> Result<Self, OwnerSiteAuthorityError> {
        let authz_epoch =
            NonZeroU64::new(authz_epoch).ok_or(OwnerSiteAuthorityError::ZeroGeneration)?;
        Ok(Self {
            authz_epoch,
            digest,
        })
    }

    #[must_use]
    pub(crate) fn authz_epoch(self) -> u64 {
        self.authz_epoch.get()
    }

    #[must_use]
    pub(crate) fn digest(self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    fn is_after(self, other: Self) -> bool {
        self.authz_epoch() > other.authz_epoch()
    }

    #[must_use]
    fn is_same_epoch_with_different_digest(self, other: Self) -> bool {
        self.authz_epoch() == other.authz_epoch() && self.digest != other.digest
    }

    /// A nested binding or tombstone may be historical, or may belong to the
    /// exact snapshot generation that carries it. A same-epoch digest mismatch
    /// is an authority conflict, never an ordering tie to accept.
    #[must_use]
    fn is_nested_in_or_before(self, snapshot: Self) -> bool {
        self.authz_epoch() < snapshot.authz_epoch()
            || (self.authz_epoch() == snapshot.authz_epoch() && self.digest == snapshot.digest)
    }
}

/// Household and mesh network namespace for an owner-site authority snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteRosterScope {
    household_id: String,
    network_id: String,
}

impl OwnerSiteRosterScope {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        household_id: &str,
        network_id: &str,
    ) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            household_id: validated_server_identifier(household_id)?,
            network_id: validated_component(network_id)?,
        })
    }

    #[must_use]
    fn matches_intent(&self, intent: &OwnerSiteIntent) -> bool {
        self.household_id == intent.household_id() && self.network_id == intent.network_id()
    }
}

/// Owner-site role carried by a future owner-signed roster decision.
///
/// PR2 records the role in the staged type but authorizes no production caller.
/// The only harness positive uses `Owner`; membership/ACL policy remains a
/// reviewed provider decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSiteMembershipRole {
    Owner,
    Member,
}

/// Opaque roster-local identifier for a member-device enrollment.
///
/// Its canonical derivation and owner signature are deliberately deferred. The
/// identifier exists now only so tombstones can be typed separately from a
/// live `MemberDeviceBinding` and can never be confused with a peer address.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct OwnerSiteBindingId([u8; 32]);

impl std::fmt::Debug for OwnerSiteBindingId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnerSiteBindingId(REDACTED)")
    }
}

impl OwnerSiteBindingId {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(bytes: [u8; 32]) -> Result<Self, OwnerSiteAuthorityError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(OwnerSiteAuthorityError::ZeroBindingId);
        }
        Ok(Self(bytes))
    }
}

/// Opaque canonical digest of the owner-site binding as committed by a future
/// signed roster envelope.
///
/// The digest is deliberately injected only in tests for now: deriving it and
/// signing the exact CBOR envelope are part of the reviewed authority-provider
/// slice, not a license to accept an ad-hoc client binding.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct OwnerSiteBindingDigest([u8; 32]);

impl std::fmt::Debug for OwnerSiteBindingDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnerSiteBindingDigest(REDACTED)")
    }
}

impl OwnerSiteBindingDigest {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(bytes: [u8; 32]) -> Result<Self, OwnerSiteAuthorityError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(OwnerSiteAuthorityError::ZeroBindingDigest);
        }
        Ok(Self(bytes))
    }
}

/// Channel-auth P-256 signer in one owner-site binding.
///
/// The Secure Enclave/P-256 key signs channel material; it never supplies the
/// X25519 ECDH secret. The wrapper exists so the roster can bind two distinct
/// logical signers without changing the compatibility-sensitive generic
/// [`MemberDeviceBinding`] wire format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteChannelAuthKey {
    key_id: OwnerSiteChannelAuthKeyId,
    public_key: P256PublicKey,
}

impl OwnerSiteChannelAuthKey {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        key_id: &str,
        public_key: P256PublicKey,
    ) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            key_id: OwnerSiteChannelAuthKeyId::injected_for_harness(key_id)?,
            public_key,
        })
    }

    /// Exposes the exact verified channel-auth public key only to the future
    /// A2 verifier. Its distinct wrapper type prevents it from being used as
    /// the action-PoP key by accident.
    #[must_use]
    pub(crate) fn verifying_key(&self) -> &P256PublicKey {
        &self.public_key
    }
}

/// Action-PoP P-256 signer in one owner-site binding.
///
/// This deliberately has a different Rust type from
/// [`OwnerSiteChannelAuthKey`]. A future A2 handler cannot accidentally pass a
/// `PoP` signer where a channel-auth signature is required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteActionPopKey {
    key_id: OwnerSiteActionPopKeyId,
    public_key: P256PublicKey,
}

impl OwnerSiteActionPopKey {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        key_id: &str,
        public_key: P256PublicKey,
    ) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            key_id: OwnerSiteActionPopKeyId::injected_for_harness(key_id)?,
            public_key,
        })
    }

    /// Exposes the exact verified action-PoP public key only to the future
    /// A2 verifier. It has a distinct Rust type from channel authentication.
    #[must_use]
    pub(crate) fn verifying_key(&self) -> &P256PublicKey {
        &self.public_key
    }
}

/// Typed key identifier for the P-256 signature that authenticates A2 channel
/// material. It is intentionally not interchangeable with an action-PoP id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteChannelAuthKeyId(String);

impl OwnerSiteChannelAuthKeyId {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(value: &str) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self(validated_component(value)?))
    }
}

/// Typed key identifier for the P-256 signature authorizing the final action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteActionPopKeyId(String);

impl OwnerSiteActionPopKeyId {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(value: &str) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self(validated_component(value)?))
    }
}

/// One active member-device enrollment scoped to a household, mesh network,
/// role, and exact owner-site resource.
///
/// `MemberDeviceBinding` must verify before this staging type can be built.
/// That still does not turn it into household authority: the future signed
/// roster envelope and the per-connection principal assertion are both
/// mandatory before any effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteRosterBinding {
    binding_id: OwnerSiteBindingId,
    binding_digest: OwnerSiteBindingDigest,
    scope: OwnerSiteRosterScope,
    member_device: MemberDeviceBinding,
    role: OwnerSiteMembershipRole,
    resource: OwnerSiteResource,
    channel_auth: OwnerSiteChannelAuthKey,
    action_pop: OwnerSiteActionPopKey,
    enrolled_at: OwnerSiteAuthorityGeneration,
}

impl OwnerSiteRosterBinding {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        binding_id: OwnerSiteBindingId,
        binding_digest: OwnerSiteBindingDigest,
        scope: OwnerSiteRosterScope,
        member_device: MemberDeviceBinding,
        role: OwnerSiteMembershipRole,
        resource: OwnerSiteResource,
        channel_auth: OwnerSiteChannelAuthKey,
        action_pop: OwnerSiteActionPopKey,
        enrolled_at: OwnerSiteAuthorityGeneration,
    ) -> Result<Self, OwnerSiteAuthorityError> {
        member_device
            .verify()
            .map_err(|_| OwnerSiteAuthorityError::MemberDeviceBindingRejected)?;
        if channel_auth.key_id.0 == action_pop.key_id.0
            || channel_auth.public_key == action_pop.public_key
        {
            return Err(OwnerSiteAuthorityError::ChannelAndActionKeysNotDistinct);
        }
        Ok(Self {
            binding_id,
            binding_digest,
            scope,
            member_device,
            role,
            resource,
            channel_auth,
            action_pop,
            enrolled_at,
        })
    }

    #[must_use]
    fn binding_id(&self) -> OwnerSiteBindingId {
        self.binding_id
    }

    #[must_use]
    fn binding_digest(&self) -> OwnerSiteBindingDigest {
        self.binding_digest
    }

    #[must_use]
    fn resolves(
        &self,
        intent: &OwnerSiteIntent,
        principal: &OwnerSiteRemotePrincipal,
    ) -> Option<OwnerSiteResolvedBinding> {
        if !(self.scope.matches_intent(intent)
            && self.member_device.member_id == intent.actor_id()
            && self.member_device.participant_npub == principal.participant_npub()
            && self.role == OwnerSiteMembershipRole::Owner
            && self.resource == *intent.resource())
        {
            return None;
        }
        Some(OwnerSiteResolvedBinding {
            binding_id: self.binding_id,
            binding_digest: self.binding_digest,
            participant_npub: self.member_device.participant_npub.clone(),
            channel_auth: self.channel_auth.clone(),
            action_pop: self.action_pop.clone(),
        })
    }
}

/// Exact local C-resolution for a future A2 `C2` message.
///
/// It is server-only, not serializable, and can be created only after the
/// roster provider resolves one exact binding. PR2 exposes it only through a
/// crate-test fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteResolvedBinding {
    binding_id: OwnerSiteBindingId,
    binding_digest: OwnerSiteBindingDigest,
    participant_npub: String,
    channel_auth: OwnerSiteChannelAuthKey,
    action_pop: OwnerSiteActionPopKey,
}

impl OwnerSiteResolvedBinding {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        binding_id: OwnerSiteBindingId,
        binding_digest: OwnerSiteBindingDigest,
        participant_npub: &str,
        channel_auth: OwnerSiteChannelAuthKey,
        action_pop: OwnerSiteActionPopKey,
    ) -> Result<Self, OwnerSiteIntentError> {
        Ok(Self {
            binding_id,
            binding_digest,
            participant_npub: validated_component(participant_npub)?,
            channel_auth,
            action_pop,
        })
    }

    /// Returns the sealed channel-auth key selected by exact roster
    /// resolution. The AKE slice must use this for `signature_D` only.
    #[must_use]
    pub(crate) fn channel_auth_key(&self) -> &OwnerSiteChannelAuthKey {
        &self.channel_auth
    }

    /// Returns the sealed action-PoP key selected by exact roster resolution.
    /// The AKE slice must use this for `pop_D` only.
    #[must_use]
    pub(crate) fn action_pop_key(&self) -> &OwnerSiteActionPopKey {
        &self.action_pop
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn binding_id_for_harness(&self) -> OwnerSiteBindingId {
        self.binding_id
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn binding_digest_for_harness(&self) -> OwnerSiteBindingDigest {
        self.binding_digest
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn participant_npub_for_harness(&self) -> &str {
        &self.participant_npub
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn channel_auth_key_id_for_harness(&self) -> &OwnerSiteChannelAuthKeyId {
        &self.channel_auth.key_id
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn action_pop_key_id_for_harness(&self) -> &OwnerSiteActionPopKeyId {
        &self.action_pop.key_id
    }
}

/// Durable revoke record staged for the future signed roster provider.
///
/// A tombstone names the enrollment it revokes and the epoch at which the
/// revoke took effect. It intentionally contains no route, peer address, or
/// transport operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteRevocationTombstone {
    binding_id: OwnerSiteBindingId,
    revoked_at: OwnerSiteAuthorityGeneration,
}

impl OwnerSiteRevocationTombstone {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        binding_id: OwnerSiteBindingId,
        revoked_at: OwnerSiteAuthorityGeneration,
    ) -> Self {
        Self {
            binding_id,
            revoked_at,
        }
    }
}

/// Pre-effect shape for a future owner-signed roster snapshot.
///
/// The signature/issuer bytes are deliberately opaque and never accepted or
/// verified here. This type only makes the required fields and monotonicity
/// rules explicit for tests. A real provider must verify the envelope, persist
/// the highest accepted `(epoch, digest)`, enforce freshness, and bind a
/// verified principal to the exact incoming channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteRosterSnapshot {
    version: u8,
    scope: OwnerSiteRosterScope,
    generation: OwnerSiteAuthorityGeneration,
    bindings: Vec<OwnerSiteRosterBinding>,
    tombstones: Vec<OwnerSiteRevocationTombstone>,
    issued_at: u64,
    fresh_until: u64,
    issuer_key_id: String,
    signature: Vec<u8>,
}

impl OwnerSiteRosterSnapshot {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn injected_for_harness(
        scope: OwnerSiteRosterScope,
        generation: OwnerSiteAuthorityGeneration,
        bindings: Vec<OwnerSiteRosterBinding>,
        tombstones: Vec<OwnerSiteRevocationTombstone>,
        issued_at: u64,
        fresh_until: u64,
        issuer_key_id: &str,
        signature: Vec<u8>,
    ) -> Result<Self, OwnerSiteAuthorityError> {
        if fresh_until <= issued_at {
            return Err(OwnerSiteAuthorityError::InvalidFreshness);
        }
        if signature.is_empty() {
            return Err(OwnerSiteAuthorityError::MissingRosterSignature);
        }
        let issuer_key_id = validated_component(issuer_key_id)
            .map_err(|_| OwnerSiteAuthorityError::InvalidIssuer)?;

        for binding in &bindings {
            if binding.scope != scope || !binding.enrolled_at.is_nested_in_or_before(generation) {
                return Err(OwnerSiteAuthorityError::BindingScopeOrGenerationMismatch);
            }
        }
        for tombstone in &tombstones {
            if !tombstone.revoked_at.is_nested_in_or_before(generation) {
                return Err(OwnerSiteAuthorityError::TombstoneAfterSnapshot);
            }
        }
        for (index, binding) in bindings.iter().enumerate() {
            if bindings[index + 1..]
                .iter()
                .any(|other| other.binding_id() == binding.binding_id())
            {
                return Err(OwnerSiteAuthorityError::DuplicateBindingId);
            }
            if tombstones
                .iter()
                .any(|tombstone| tombstone.binding_id == binding.binding_id())
            {
                return Err(OwnerSiteAuthorityError::RevokedBindingStillActive);
            }
        }
        for (index, tombstone) in tombstones.iter().enumerate() {
            if tombstones[index + 1..]
                .iter()
                .any(|other| other.binding_id == tombstone.binding_id)
            {
                return Err(OwnerSiteAuthorityError::DuplicateTombstone);
            }
        }

        Ok(Self {
            version: OWNER_SITE_ROSTER_VERSION,
            scope,
            generation,
            bindings,
            tombstones,
            issued_at,
            fresh_until,
            issuer_key_id,
            signature,
        })
    }

    #[must_use]
    pub(crate) fn generation(&self) -> OwnerSiteAuthorityGeneration {
        self.generation
    }

    #[must_use]
    fn is_fresh_at(&self, observed_at: u64) -> bool {
        self.version == OWNER_SITE_ROSTER_VERSION
            && self.issued_at <= observed_at
            && observed_at < self.fresh_until
            && !self.issuer_key_id.is_empty()
            && !self.signature.is_empty()
    }

    #[must_use]
    fn resolve_exact(
        &self,
        intent: &OwnerSiteIntent,
        principal: &OwnerSiteRemotePrincipal,
        claimed_binding_id: OwnerSiteBindingId,
        claimed_binding_digest: OwnerSiteBindingDigest,
        claimed_channel_auth_key_id: &OwnerSiteChannelAuthKeyId,
        claimed_action_pop_key_id: &OwnerSiteActionPopKeyId,
    ) -> Option<OwnerSiteResolvedBinding> {
        if !self.scope.matches_intent(intent) {
            return None;
        }
        let mut matches = self
            .bindings
            .iter()
            .filter(|binding| {
                binding.binding_id() == claimed_binding_id
                    && binding.binding_digest() == claimed_binding_digest
                    && binding.channel_auth.key_id == *claimed_channel_auth_key_id
                    && binding.action_pop.key_id == *claimed_action_pop_key_id
            })
            .filter_map(|binding| binding.resolves(intent, principal));
        let resolved = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(resolved)
    }

    /// Checks only local monotonicity between two already-verified candidate
    /// snapshots. It does not persist a watermark or verify either signature.
    #[cfg(test)]
    pub(crate) fn is_strict_successor_of(
        &self,
        previous: &Self,
    ) -> Result<(), OwnerSiteAuthorityError> {
        if self.scope != previous.scope {
            return Err(OwnerSiteAuthorityError::SnapshotScopeMismatch);
        }
        if self
            .generation
            .is_same_epoch_with_different_digest(previous.generation)
        {
            return Err(OwnerSiteAuthorityError::GenerationDigestConflict);
        }
        if !self.generation.is_after(previous.generation) {
            return Err(OwnerSiteAuthorityError::NonMonotonicGeneration);
        }
        for tombstone in &previous.tombstones {
            if !self.tombstones.contains(tombstone) {
                return Err(OwnerSiteAuthorityError::TombstoneDropped);
            }
        }
        if self.bindings.iter().any(|binding| {
            previous
                .tombstones
                .iter()
                .any(|tombstone| tombstone.binding_id == binding.binding_id())
        }) {
            return Err(OwnerSiteAuthorityError::TombstonedBindingResurrected);
        }
        Ok(())
    }
}

/// A server-only authority observation used by the capability shape.
///
/// `Unavailable`, `Stale`, `Mismatch`, and `Revoked` are explicit fail-closed
/// outcomes. The sole positive variant is test-only and cannot be acquired by
/// production routing, CIDR classification, a name, or `ConnectInfo`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSiteAuthoritySnapshot {
    #[cfg(test)]
    Unavailable,
    #[cfg(test)]
    Stale,
    #[cfg(test)]
    Mismatch,
    #[cfg(test)]
    Revoked,
    #[cfg(test)]
    InjectedForHarness(OwnerSiteHarnessAuthority),
}

impl OwnerSiteAuthoritySnapshot {
    #[must_use]
    pub(crate) fn admits_pre_effect(&self, intent: &OwnerSiteIntent) -> bool {
        #[cfg(test)]
        {
            matches!(self, Self::InjectedForHarness(authority) if authority.admits(intent))
        }
        #[cfg(not(test))]
        {
            let _ = (self, intent);
            false
        }
    }
}

/// Test-only injection of a fully typed but non-production authority view.
///
/// This fixture exists to make route-real fail-closed tests prove the future
/// shape. It does not assert that a connection belongs to `participant_npub`;
/// that A2/provider boundary is deliberately absent until reviewed.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerSiteHarnessAuthority {
    principal: OwnerSiteRemotePrincipal,
    roster: OwnerSiteRosterSnapshot,
    claimed_binding_id: OwnerSiteBindingId,
    claimed_binding_digest: OwnerSiteBindingDigest,
    claimed_channel_auth_key_id: OwnerSiteChannelAuthKeyId,
    claimed_action_pop_key_id: OwnerSiteActionPopKeyId,
    observed_at: u64,
}

#[cfg(test)]
impl OwnerSiteHarnessAuthority {
    pub(crate) fn injected_for_harness(
        principal: OwnerSiteRemotePrincipal,
        roster: OwnerSiteRosterSnapshot,
        claimed_binding_id: OwnerSiteBindingId,
        claimed_binding_digest: OwnerSiteBindingDigest,
        claimed_channel_auth_key_id: OwnerSiteChannelAuthKeyId,
        claimed_action_pop_key_id: OwnerSiteActionPopKeyId,
        observed_at: u64,
    ) -> Result<Self, OwnerSiteAuthorityError> {
        if !roster.is_fresh_at(observed_at) {
            return Err(OwnerSiteAuthorityError::SnapshotNotFresh);
        }
        Ok(Self {
            principal,
            roster,
            claimed_binding_id,
            claimed_binding_digest,
            claimed_channel_auth_key_id,
            claimed_action_pop_key_id,
            observed_at,
        })
    }

    #[must_use]
    fn admits(&self, intent: &OwnerSiteIntent) -> bool {
        self.roster.is_fresh_at(self.observed_at)
            && self
                .roster
                .resolve_exact(
                    intent,
                    &self.principal,
                    self.claimed_binding_id,
                    self.claimed_binding_digest,
                    &self.claimed_channel_auth_key_id,
                    &self.claimed_action_pop_key_id,
                )
                .is_some()
    }
}

/// Rejections while constructing the pre-effect authority shapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSiteAuthorityError {
    ZeroGeneration,
    ZeroBindingId,
    ZeroBindingDigest,
    MemberDeviceBindingRejected,
    ChannelAndActionKeysNotDistinct,
    InvalidFreshness,
    MissingRosterSignature,
    InvalidIssuer,
    BindingScopeOrGenerationMismatch,
    TombstoneAfterSnapshot,
    DuplicateBindingId,
    RevokedBindingStillActive,
    DuplicateTombstone,
    SnapshotScopeMismatch,
    NonMonotonicGeneration,
    GenerationDigestConflict,
    TombstoneDropped,
    TombstonedBindingResurrected,
    SnapshotNotFresh,
}

#[cfg(test)]
pub(crate) fn active_authority_fixture(
    household_id: &str,
    resource: OwnerSiteResource,
) -> Result<(String, OwnerSiteAuthoritySnapshot), OwnerSiteAuthorityError> {
    use household_rs::keys::{IdentityKey, P256Keypair};

    let member = P256Keypair::generate();
    let device = P256Keypair::generate();
    let channel_auth = P256Keypair::generate();
    let action_pop = P256Keypair::generate();
    let participant_npub = "npub1owneralpha";
    let member_device = MemberDeviceBinding::sign(
        &member,
        device.public(),
        participant_npub.to_string(),
        1_000,
    )
    .map_err(|_| OwnerSiteAuthorityError::MemberDeviceBindingRejected)?;
    let actor_id = member_device.member_id.clone();
    let scope = OwnerSiteRosterScope::injected_for_harness(household_id, "owner-site-mesh")
        .map_err(|_| OwnerSiteAuthorityError::BindingScopeOrGenerationMismatch)?;
    let generation = OwnerSiteAuthorityGeneration::injected_for_harness(1, [0x41; 32])?;
    let binding_id = OwnerSiteBindingId::injected_for_harness([0x01; 32])?;
    let binding_digest = OwnerSiteBindingDigest::injected_for_harness([0x51; 32])?;
    let channel_auth =
        OwnerSiteChannelAuthKey::injected_for_harness("channel-auth-alpha", channel_auth.public())
            .map_err(|_| OwnerSiteAuthorityError::BindingScopeOrGenerationMismatch)?;
    let action_pop =
        OwnerSiteActionPopKey::injected_for_harness("action-pop-alpha", action_pop.public())
            .map_err(|_| OwnerSiteAuthorityError::BindingScopeOrGenerationMismatch)?;
    let channel_auth_key_id = channel_auth.key_id.clone();
    let action_pop_key_id = action_pop.key_id.clone();
    let binding = OwnerSiteRosterBinding::injected_for_harness(
        binding_id,
        binding_digest,
        scope.clone(),
        member_device,
        OwnerSiteMembershipRole::Owner,
        resource,
        channel_auth,
        action_pop,
        generation,
    )?;
    let roster = OwnerSiteRosterSnapshot::injected_for_harness(
        scope,
        generation,
        vec![binding],
        Vec::new(),
        1_000,
        1_060,
        "owner-key-alpha",
        vec![0xa5; 64],
    )?;
    let principal = OwnerSiteRemotePrincipal::injected_for_harness(participant_npub)
        .map_err(|_| OwnerSiteAuthorityError::BindingScopeOrGenerationMismatch)?;
    let authority = OwnerSiteHarnessAuthority::injected_for_harness(
        principal,
        roster,
        binding_id,
        binding_digest,
        channel_auth_key_id,
        action_pop_key_id,
        1_001,
    )?;
    Ok((
        actor_id,
        OwnerSiteAuthoritySnapshot::InjectedForHarness(authority),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::keys::{IdentityKey, P256Keypair};

    fn resource() -> OwnerSiteResource {
        OwnerSiteResource::from_route_claw("picoclaw").expect("resource")
    }

    fn roster_scope() -> OwnerSiteRosterScope {
        OwnerSiteRosterScope::injected_for_harness("household-alpha", "owner-site-mesh")
            .expect("roster scope")
    }

    fn generation(epoch: u64, fill: u8) -> OwnerSiteAuthorityGeneration {
        OwnerSiteAuthorityGeneration::injected_for_harness(epoch, [fill; 32])
            .expect("nonzero generation")
    }

    fn signed_member_device(npub: &str) -> MemberDeviceBinding {
        let member = P256Keypair::generate();
        let device = P256Keypair::generate();
        MemberDeviceBinding::sign(&member, device.public(), npub.to_string(), 1_000)
            .expect("signed member-device binding")
    }

    fn binding(id_fill: u8, enrolled_at: OwnerSiteAuthorityGeneration) -> OwnerSiteRosterBinding {
        let channel_auth = P256Keypair::generate();
        let action_pop = P256Keypair::generate();
        OwnerSiteRosterBinding::injected_for_harness(
            OwnerSiteBindingId::injected_for_harness([id_fill; 32]).expect("binding id"),
            OwnerSiteBindingDigest::injected_for_harness([id_fill.wrapping_add(0x40); 32])
                .expect("binding digest"),
            roster_scope(),
            signed_member_device("npub1owneralpha"),
            OwnerSiteMembershipRole::Owner,
            resource(),
            OwnerSiteChannelAuthKey::injected_for_harness(
                "channel-auth-alpha",
                channel_auth.public(),
            )
            .expect("channel auth key"),
            OwnerSiteActionPopKey::injected_for_harness("action-pop-alpha", action_pop.public())
                .expect("action pop key"),
            enrolled_at,
        )
        .expect("roster binding")
    }

    fn snapshot(
        generation: OwnerSiteAuthorityGeneration,
        bindings: Vec<OwnerSiteRosterBinding>,
        tombstones: Vec<OwnerSiteRevocationTombstone>,
    ) -> OwnerSiteRosterSnapshot {
        OwnerSiteRosterSnapshot::injected_for_harness(
            roster_scope(),
            generation,
            bindings,
            tombstones,
            1_000,
            1_060,
            "owner-key-alpha",
            vec![0xa5; 64],
        )
        .expect("roster snapshot")
    }

    #[test]
    fn member_device_binding_must_verify_before_it_enters_owner_site_roster_shape() {
        let generation = generation(1, 0x11);
        let mut forged = signed_member_device("npub1owneralpha");
        forged.participant_npub = "npub1forged".to_string();

        assert_eq!(
            OwnerSiteRosterBinding::injected_for_harness(
                OwnerSiteBindingId::injected_for_harness([0x01; 32]).expect("binding id"),
                OwnerSiteBindingDigest::injected_for_harness([0x51; 32]).expect("binding digest"),
                roster_scope(),
                forged,
                OwnerSiteMembershipRole::Owner,
                resource(),
                OwnerSiteChannelAuthKey::injected_for_harness(
                    "channel-auth-alpha",
                    P256Keypair::generate().public(),
                )
                .expect("channel auth key"),
                OwnerSiteActionPopKey::injected_for_harness(
                    "action-pop-alpha",
                    P256Keypair::generate().public(),
                )
                .expect("action pop key"),
                generation,
            ),
            Err(OwnerSiteAuthorityError::MemberDeviceBindingRejected)
        );
    }

    #[test]
    fn channel_auth_and_action_pop_are_distinct_typed_keys() {
        let generation = generation(1, 0x12);
        let same_key = P256Keypair::generate();
        assert_eq!(
            OwnerSiteRosterBinding::injected_for_harness(
                OwnerSiteBindingId::injected_for_harness([0x02; 32]).expect("binding id"),
                OwnerSiteBindingDigest::injected_for_harness([0x52; 32]).expect("binding digest"),
                roster_scope(),
                signed_member_device("npub1owneralpha"),
                OwnerSiteMembershipRole::Owner,
                resource(),
                OwnerSiteChannelAuthKey::injected_for_harness(
                    "channel-auth-alpha",
                    same_key.public(),
                )
                .expect("channel auth key"),
                OwnerSiteActionPopKey::injected_for_harness("action-pop-alpha", same_key.public(),)
                    .expect("action pop key"),
                generation,
            ),
            Err(OwnerSiteAuthorityError::ChannelAndActionKeysNotDistinct)
        );
    }

    #[test]
    fn exact_roster_resolution_requires_binding_digest_npub_and_both_key_ids() {
        let generation = generation(1, 0x14);
        let member = P256Keypair::generate();
        let device = P256Keypair::generate();
        let member_device = MemberDeviceBinding::sign(
            &member,
            device.public(),
            "npub1owneralpha".to_string(),
            1_000,
        )
        .expect("member-device binding");
        let actor_id = member_device.member_id.clone();
        let channel_auth = P256Keypair::generate();
        let action_pop = P256Keypair::generate();
        let channel_auth = OwnerSiteChannelAuthKey::injected_for_harness(
            "channel-auth-alpha",
            channel_auth.public(),
        )
        .expect("channel auth key");
        let action_pop =
            OwnerSiteActionPopKey::injected_for_harness("action-pop-alpha", action_pop.public())
                .expect("action pop key");
        let expected_channel_auth = channel_auth.key_id.clone();
        let expected_action_pop = action_pop.key_id.clone();
        let expected_channel_auth_public = channel_auth.public_key.clone();
        let expected_action_pop_public = action_pop.public_key.clone();
        let binding_id = OwnerSiteBindingId::injected_for_harness([0x04; 32]).expect("binding id");
        let binding_digest =
            OwnerSiteBindingDigest::injected_for_harness([0x54; 32]).expect("binding digest");
        let binding = OwnerSiteRosterBinding::injected_for_harness(
            binding_id,
            binding_digest,
            roster_scope(),
            member_device,
            OwnerSiteMembershipRole::Owner,
            resource(),
            channel_auth,
            action_pop,
            generation,
        )
        .expect("owner binding");
        let roster = snapshot(generation, vec![binding], Vec::new());
        let intent =
            OwnerSiteIntent::injected_for_harness("household-alpha", &actor_id, resource())
                .expect("intent");
        let principal =
            OwnerSiteRemotePrincipal::injected_for_harness("npub1owneralpha").expect("principal");

        let resolved = roster
            .resolve_exact(
                &intent,
                &principal,
                binding_id,
                binding_digest,
                &expected_channel_auth,
                &expected_action_pop,
            )
            .expect("exact roster resolution");
        assert_eq!(
            resolved.channel_auth_key().verifying_key(),
            &expected_channel_auth_public
        );
        assert_eq!(
            resolved.action_pop_key().verifying_key(),
            &expected_action_pop_public
        );
        let wrong_digest =
            OwnerSiteBindingDigest::injected_for_harness([0x55; 32]).expect("wrong digest");
        assert!(
            roster
                .resolve_exact(
                    &intent,
                    &principal,
                    binding_id,
                    wrong_digest,
                    &expected_channel_auth,
                    &expected_action_pop,
                )
                .is_none()
        );
        let wrong_principal =
            OwnerSiteRemotePrincipal::injected_for_harness("npub1otherowner").expect("principal");
        assert!(
            roster
                .resolve_exact(
                    &intent,
                    &wrong_principal,
                    binding_id,
                    binding_digest,
                    &expected_channel_auth,
                    &expected_action_pop,
                )
                .is_none()
        );
        let wrong_channel = OwnerSiteChannelAuthKeyId::injected_for_harness("other-channel")
            .expect("wrong channel id");
        assert!(
            roster
                .resolve_exact(
                    &intent,
                    &principal,
                    binding_id,
                    binding_digest,
                    &wrong_channel,
                    &expected_action_pop,
                )
                .is_none()
        );
        let wrong_action =
            OwnerSiteActionPopKeyId::injected_for_harness("other-action").expect("wrong action id");
        assert!(
            roster
                .resolve_exact(
                    &intent,
                    &principal,
                    binding_id,
                    binding_digest,
                    &expected_channel_auth,
                    &wrong_action,
                )
                .is_none()
        );
    }

    #[test]
    fn member_role_does_not_resolve_an_owner_site_intent() {
        let generation = generation(1, 0x13);
        let member = P256Keypair::generate();
        let device = P256Keypair::generate();
        let member_device = MemberDeviceBinding::sign(
            &member,
            device.public(),
            "npub1memberalpha".to_string(),
            1_000,
        )
        .expect("member-device binding");
        let actor_id = member_device.member_id.clone();
        let channel_auth = P256Keypair::generate();
        let action_pop = P256Keypair::generate();
        let binding = OwnerSiteRosterBinding::injected_for_harness(
            OwnerSiteBindingId::injected_for_harness([0x03; 32]).expect("binding id"),
            OwnerSiteBindingDigest::injected_for_harness([0x53; 32]).expect("binding digest"),
            roster_scope(),
            member_device,
            OwnerSiteMembershipRole::Member,
            resource(),
            OwnerSiteChannelAuthKey::injected_for_harness(
                "channel-auth-alpha",
                channel_auth.public(),
            )
            .expect("channel auth key"),
            OwnerSiteActionPopKey::injected_for_harness("action-pop-alpha", action_pop.public())
                .expect("action pop key"),
            generation,
        )
        .expect("member binding shape");
        let intent =
            OwnerSiteIntent::injected_for_harness("household-alpha", &actor_id, resource())
                .expect("owner-site intent");
        let principal =
            OwnerSiteRemotePrincipal::injected_for_harness("npub1memberalpha").expect("principal");

        assert!(binding.resolves(&intent, &principal).is_none());
    }

    #[test]
    fn zero_generation_and_rollback_are_rejected() {
        assert_eq!(
            OwnerSiteAuthorityGeneration::injected_for_harness(0, [0x00; 32]),
            Err(OwnerSiteAuthorityError::ZeroGeneration)
        );

        let current_generation = generation(2, 0x22);
        let current = snapshot(
            current_generation,
            vec![binding(0x02, current_generation)],
            vec![],
        );
        assert_eq!(current.generation(), current_generation);
        let replay_generation = generation(2, 0x23);
        let replay = snapshot(
            replay_generation,
            vec![binding(0x03, replay_generation)],
            vec![],
        );
        assert_eq!(
            replay.is_strict_successor_of(&current),
            Err(OwnerSiteAuthorityError::GenerationDigestConflict)
        );
        let lower_generation = generation(1, 0x24);
        let lower = snapshot(
            lower_generation,
            vec![binding(0x04, lower_generation)],
            vec![],
        );
        assert_eq!(
            lower.is_strict_successor_of(&current),
            Err(OwnerSiteAuthorityError::NonMonotonicGeneration)
        );
    }

    #[test]
    fn nested_generations_reject_same_epoch_with_a_different_digest() {
        let snapshot_generation = generation(7, 0xa1);
        let conflicting_generation = generation(7, 0xb1);

        assert_eq!(
            OwnerSiteRosterSnapshot::injected_for_harness(
                roster_scope(),
                snapshot_generation,
                vec![binding(0x21, conflicting_generation)],
                Vec::new(),
                1_000,
                1_060,
                "owner-key-alpha",
                vec![0xa5; 64],
            ),
            Err(OwnerSiteAuthorityError::BindingScopeOrGenerationMismatch),
            "a conflicting same-epoch binding must never become active"
        );

        let revoked_binding = binding(0x22, generation(6, 0xa2));
        let conflicting_tombstone = OwnerSiteRevocationTombstone::injected_for_harness(
            revoked_binding.binding_id(),
            conflicting_generation,
        );
        assert_eq!(
            OwnerSiteRosterSnapshot::injected_for_harness(
                roster_scope(),
                snapshot_generation,
                Vec::new(),
                vec![conflicting_tombstone],
                1_000,
                1_060,
                "owner-key-alpha",
                vec![0xa5; 64],
            ),
            Err(OwnerSiteAuthorityError::TombstoneAfterSnapshot),
            "a conflicting same-epoch tombstone must never be accepted"
        );
    }

    #[test]
    fn tombstone_wins_and_reenrollment_needs_a_new_binding_at_a_later_epoch() {
        let enrolled = generation(1, 0x31);
        let active = binding(0x01, enrolled);
        let revoked = generation(2, 0x32);
        let tombstone =
            OwnerSiteRevocationTombstone::injected_for_harness(active.binding_id(), revoked);

        assert_eq!(
            OwnerSiteRosterSnapshot::injected_for_harness(
                roster_scope(),
                revoked,
                vec![active.clone()],
                vec![tombstone],
                1_000,
                1_060,
                "owner-key-alpha",
                vec![0xa5; 64],
            ),
            Err(OwnerSiteAuthorityError::RevokedBindingStillActive)
        );

        let reenrolled = generation(3, 0x33);
        let replacement = binding(0x02, reenrolled);
        let next = snapshot(reenrolled, vec![replacement], vec![tombstone]);
        let prior = snapshot(revoked, Vec::new(), vec![tombstone]);
        assert_eq!(next.is_strict_successor_of(&prior), Ok(()));
    }

    #[test]
    fn successors_preserve_tombstones_and_never_resurrect_a_binding_id() {
        let enrolled = generation(1, 0x61);
        let old = binding(0x11, enrolled);
        let revoked = generation(2, 0x62);
        let tombstone =
            OwnerSiteRevocationTombstone::injected_for_harness(old.binding_id(), revoked);
        let prior = snapshot(revoked, Vec::new(), vec![tombstone]);

        let after_revoke = generation(3, 0x63);
        let dropped = snapshot(after_revoke, Vec::new(), Vec::new());
        assert_eq!(
            dropped.is_strict_successor_of(&prior),
            Err(OwnerSiteAuthorityError::TombstoneDropped)
        );

        // The constructor itself refuses an active reuse of the tombstoned id;
        // a later epoch cannot resurrect it.
        assert_eq!(
            OwnerSiteRosterSnapshot::injected_for_harness(
                roster_scope(),
                after_revoke,
                vec![binding(0x11, after_revoke)],
                vec![tombstone],
                1_000,
                1_060,
                "owner-key-alpha",
                vec![0xa5; 64],
            ),
            Err(OwnerSiteAuthorityError::RevokedBindingStillActive)
        );
    }

    #[test]
    fn only_fresh_typed_harness_authority_can_admit_an_exact_intent() {
        let resource = resource();
        let (actor_id, authority) =
            active_authority_fixture("household-alpha", resource.clone()).expect("fixture");
        let intent = OwnerSiteIntent::injected_for_harness("household-alpha", &actor_id, resource)
            .expect("intent");
        assert!(authority.admits_pre_effect(&intent));
        let wrong_network = OwnerSiteIntent::injected_for_harness_with_request(
            "household-alpha",
            "other-network",
            &actor_id,
            OwnerSiteResource::from_route_claw("picoclaw").expect("resource"),
            crate::owner_site_capability::OwnerSiteCanonicalRequest::injected_for_harness(
                crate::owner_site_capability::OwnerSiteRequestMethod::Post,
                "/api/v1/household/claws/{name}/owner-site/preflight",
                [0x42; 32],
            )
            .expect("request"),
        )
        .expect("wrong-network intent");
        assert!(!authority.admits_pre_effect(&wrong_network));
        assert!(!OwnerSiteAuthoritySnapshot::Unavailable.admits_pre_effect(&intent));
        assert!(!OwnerSiteAuthoritySnapshot::Stale.admits_pre_effect(&intent));
        assert!(!OwnerSiteAuthoritySnapshot::Mismatch.admits_pre_effect(&intent));
        assert!(!OwnerSiteAuthoritySnapshot::Revoked.admits_pre_effect(&intent));
    }
}
