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

use household_rs::{HouseholdId, MachineCert, MemberDeviceBinding, P256PublicKey};

use crate::owner_site_capability::{OwnerSiteCanonicalRequest, OwnerSiteIntent, OwnerSiteResource};
#[cfg(test)]
use crate::owner_site_capability::{
    OwnerSiteIntentError, validated_component, validated_server_identifier,
};
use crate::owner_site_challenge::{
    OwnerSiteChannelEpoch, OwnerSiteChannelId, OwnerSiteWebSocketInstance,
};
use crate::owner_site_promotion::OwnerSitePromotedChannel;

/// Version reserved for the future signed owner-site roster envelope.
///
/// No parser, signer, verifier, persistence, or provider accepts this shape in
/// this PR. Keeping the version private to server types prevents a provisional
/// HTTP or A2 encoding from becoming a protocol commitment.
pub(crate) const OWNER_SITE_ROSTER_VERSION: u8 = 1;

/// Server-local state after A2 has authenticated both sides and confirmed C3.
///
/// This is the complete immutable identity/authority tuple that a later
/// linearizer must resolve.  It is deliberately not serializable, clonable,
/// default-constructible, or convertible from another value.  Production has
/// no constructor in this slice; the only constructor is a synthetic crate
/// test fixture below.
pub(crate) struct PendingFinished {
    household: HouseholdId,
    exact_resource: OwnerSiteResource,
    exact_route: OwnerSiteCanonicalRequest,
    machine_cert: MachineCert,
    device_binding: MemberDeviceBinding,
    principal_d: OwnerSiteRemotePrincipal,
    ws_instance: OwnerSiteWebSocketInstance,
    channel_id: OwnerSiteChannelId,
    channel_epoch: OwnerSiteChannelEpoch,
    channel_binding: [u8; 32],
    authz_epoch: NonZeroU64,
    roster_digest: [u8; 32],
    fresh_until: u64,
    provider_generation: u64,
    cancellation_generation: u64,
}

impl std::fmt::Debug for PendingFinished {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PendingFinished(REDACTED)")
    }
}

impl PendingFinished {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn injected_for_harness(
        household: HouseholdId,
        exact_resource: OwnerSiteResource,
        exact_route: OwnerSiteCanonicalRequest,
        machine_cert: MachineCert,
        device_binding: MemberDeviceBinding,
        principal_d: OwnerSiteRemotePrincipal,
        ws_instance: OwnerSiteWebSocketInstance,
        channel_id: OwnerSiteChannelId,
        channel_epoch: OwnerSiteChannelEpoch,
        channel_binding: [u8; 32],
        authz_epoch: u64,
        roster_digest: [u8; 32],
        fresh_until: u64,
        provider_generation: u64,
        cancellation_generation: u64,
    ) -> Result<Self, OwnerSiteAuthorityError> {
        let authz_epoch =
            NonZeroU64::new(authz_epoch).ok_or(OwnerSiteAuthorityError::ZeroGeneration)?;
        Ok(Self {
            household,
            exact_resource,
            exact_route,
            machine_cert,
            device_binding,
            principal_d,
            ws_instance,
            channel_id,
            channel_epoch,
            channel_binding,
            authz_epoch,
            roster_digest,
            fresh_until,
            provider_generation,
            cancellation_generation,
        })
    }

    #[must_use]
    fn generation_vector(&self) -> OwnerSiteGenerationVector {
        OwnerSiteGenerationVector {
            authz_epoch: self.authz_epoch.get(),
            roster_digest: self.roster_digest,
            provider_generation: self.provider_generation,
            cancellation_generation: self.cancellation_generation,
        }
    }
}

/// Non-forgeable app-layer proof that one exact A2 channel is authenticated
/// and confidential.
///
/// The type is intentionally defined but not wired to any production session,
/// mint, route, or promotion boundary in this slice.
pub(crate) struct AuthenticatedConfidentialChannel {
    _seal: AuthenticatedConfidentialChannelSeal,
    ws_instance: OwnerSiteWebSocketInstance,
    channel_id: OwnerSiteChannelId,
    channel_epoch: OwnerSiteChannelEpoch,
    channel_binding: [u8; 32],
}

struct AuthenticatedConfidentialChannelSeal;

impl std::fmt::Debug for AuthenticatedConfidentialChannel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthenticatedConfidentialChannel(REDACTED)")
    }
}

impl AuthenticatedConfidentialChannel {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        ws_instance: OwnerSiteWebSocketInstance,
        channel_id: OwnerSiteChannelId,
        channel_epoch: OwnerSiteChannelEpoch,
        channel_binding: [u8; 32],
    ) -> Self {
        Self {
            _seal: AuthenticatedConfidentialChannelSeal,
            ws_instance,
            channel_id,
            channel_epoch,
            channel_binding,
        }
    }

    #[cfg(test)]
    #[must_use]
    fn matches_pending(&self, pending: &PendingFinished) -> bool {
        self.ws_instance == pending.ws_instance
            && self.channel_id == pending.channel_id
            && self.channel_epoch == pending.channel_epoch
            && self.channel_binding == pending.channel_binding
    }
}

/// Type-level representation of a channel waiting for the later linearizer.
pub(crate) struct Pending {
    pending_finished: PendingFinished,
    channel: AuthenticatedConfidentialChannel,
}

impl Pending {
    #[cfg(test)]
    pub(crate) fn injected_for_harness(
        pending_finished: PendingFinished,
        channel: AuthenticatedConfidentialChannel,
    ) -> Result<Self, OwnerSiteAuthorityError> {
        if !channel.matches_pending(&pending_finished) {
            return Err(OwnerSiteAuthorityError::ChannelProofMismatch);
        }
        Ok(Self {
            pending_finished,
            channel,
        })
    }

    fn begin_closing(self) -> Closing {
        Closing { pending: self }
    }
}

/// Type-level promoted state.  Its carrier has no construction path here.
pub(crate) struct Promoted {
    channel: OwnerSitePromotedChannel,
}

/// Type-level state after a future single-use permit reserves one backend.
pub(crate) struct Dialing {
    promoted: Promoted,
}

/// Type-level state for a future fenced byte pump.
pub(crate) struct Pumping {
    dialing: Dialing,
}

/// Pure terminal path available to an unpromoted channel in this slice.
pub(crate) struct Closing {
    pending: Pending,
}

impl Closing {
    fn finish(self) -> Closed {
        let Self { pending } = self;
        let Pending {
            pending_finished,
            channel,
        } = pending;
        let _ = (pending_finished, channel);
        Closed {
            _seal: ClosedStateSeal,
        }
    }
}

/// Type-level revoke state reserved for the later persisted linearizer.
pub(crate) struct Revoking {
    _seal: RevokingStateSeal,
}

struct RevokingStateSeal;

/// Idempotent terminal state.  Closing it again cannot recreate authority.
pub(crate) struct Closed {
    _seal: ClosedStateSeal,
}

struct ClosedStateSeal;

impl Closed {
    #[must_use]
    fn close(self) -> Self {
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerSiteStateKind {
    Pending,
    Promoted,
    Dialing,
    Pumping,
    Closing,
    Revoking,
    Closed,
}

/// Pure topology predicate for the deliberately non-promoting first slice.
#[must_use]
const fn owner_site_transition_is_allowed(
    from: OwnerSiteStateKind,
    to: OwnerSiteStateKind,
) -> bool {
    matches!(
        (from, to),
        (OwnerSiteStateKind::Pending, OwnerSiteStateKind::Closing)
            | (
                OwnerSiteStateKind::Closing
                    | OwnerSiteStateKind::Closed
                    | OwnerSiteStateKind::Revoking,
                OwnerSiteStateKind::Closed
            )
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnerSiteGenerationVector {
    authz_epoch: u64,
    roster_digest: [u8; 32],
    provider_generation: u64,
    cancellation_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerSiteGenerationComparison {
    Exact,
    AuthorityChanged,
    ProviderChanged,
    CancellationChanged,
}

/// Pure generation comparison; it reads no provider, clock, store, or socket.
#[must_use]
fn compare_owner_site_generations(
    expected: OwnerSiteGenerationVector,
    observed: OwnerSiteGenerationVector,
) -> OwnerSiteGenerationComparison {
    if expected.cancellation_generation != observed.cancellation_generation {
        OwnerSiteGenerationComparison::CancellationChanged
    } else if expected.authz_epoch != observed.authz_epoch
        || expected.roster_digest != observed.roster_digest
    {
        OwnerSiteGenerationComparison::AuthorityChanged
    } else if expected.provider_generation != observed.provider_generation {
        OwnerSiteGenerationComparison::ProviderChanged
    } else {
        OwnerSiteGenerationComparison::Exact
    }
}

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

    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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

    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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

    #[must_use]
    pub(crate) fn key_id(&self) -> &OwnerSiteChannelAuthKeyId {
        &self.key_id
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

    #[must_use]
    pub(crate) fn key_id(&self) -> &OwnerSiteActionPopKeyId {
        &self.key_id
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

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
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

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
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

    #[must_use]
    pub(crate) fn binding_id(&self) -> OwnerSiteBindingId {
        self.binding_id
    }

    #[must_use]
    pub(crate) fn binding_digest(&self) -> OwnerSiteBindingDigest {
        self.binding_digest
    }

    #[must_use]
    pub(crate) fn participant_npub(&self) -> &str {
        &self.participant_npub
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

    #[cfg(test)]
    #[must_use]
    pub(crate) fn fresh_until_for_harness(&self) -> u64 {
        self.fresh_until
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_fresh_for_ake_harness(&self, observed_at: u64) -> bool {
        self.is_fresh_at(observed_at)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resolve_for_ake_harness(
        &self,
        intent: &OwnerSiteIntent,
        principal: &OwnerSiteRemotePrincipal,
        claimed_binding_id: OwnerSiteBindingId,
        claimed_binding_digest: OwnerSiteBindingDigest,
        claimed_channel_auth_key_id: &OwnerSiteChannelAuthKeyId,
        claimed_action_pop_key_id: &OwnerSiteActionPopKeyId,
    ) -> Option<OwnerSiteResolvedBinding> {
        self.resolve_exact(
            intent,
            principal,
            claimed_binding_id,
            claimed_binding_digest,
            claimed_channel_auth_key_id,
            claimed_action_pop_key_id,
        )
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
    ChannelProofMismatch,
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

// ===== DP2 Fatia-2: promotion linearizer, one-shot claim, and sealed witness =====

/// Opaque 32-byte one-shot promotion claim, minted by CSPRNG at registration
/// and never accepted from wire (§4).
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct OwnerSitePromotionClaimId([u8; 32]);

impl std::fmt::Debug for OwnerSitePromotionClaimId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnerSitePromotionClaimId(REDACTED)")
    }
}

impl OwnerSitePromotionClaimId {
    #[must_use]
    fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    #[must_use]
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The current authority observation OWNED by the linearizer. Production has no
/// admitting provider (`owner_site_ake` `admits_resource == false`) and no route
/// that sets this, so in production it is never populated and the linearizer is
/// unreachable (K0-PASS doubly inert). Tests populate it via the harness seam.
#[derive(Clone, Debug)]
struct OwnerSiteAuthorityObservation {
    household: String,
    authz_epoch: u64,
    roster_digest: [u8; 32],
    provider_generation: u64,
    cancellation_generation: u64,
    household_root: [u8; 33],
    observed_at: u64,
}

/// Sealed, move-only promotion witness (§7). Constructible ONLY by the
/// linearizer, and only after the resolution has been durably persisted. It has
/// no public/`pub(crate)` constructor, no clone/copy/serde/default, and never
/// leaves by reusable reference; it owns the material that authorized the
/// transition and is the sole value that makes `VerifiedMeshPeer`/`DialPermit`
/// reachable.
#[allow(dead_code)]
pub(crate) struct OwnerSitePromotionWitness {
    pending: Pending,
    claim: OwnerSitePromotionClaimId,
    seal: OwnerSitePromotionWitnessSeal,
}

struct OwnerSitePromotionWitnessSeal;

impl std::fmt::Debug for OwnerSitePromotionWitness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnerSitePromotionWitness(REDACTED)")
    }
}

/// By-ownership promotion input: the full `Pending` plus its claim, sealed
/// inside the authority module (§4). Never built from a raw tuple; only
/// `register_pending` constructs it.
#[allow(dead_code)]
pub(crate) struct OwnerSitePromotionInput {
    pending: Pending,
    claim: OwnerSitePromotionClaimId,
}

impl std::fmt::Debug for OwnerSitePromotionInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnerSitePromotionInput(REDACTED)")
    }
}

/// The seven rechecks, each an individually provable outcome (§8).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSiteRecheck {
    AuthorityExact,
    CancellationFence,
    ProviderGeneration,
    Freshness,
    ChannelIdentity,
    AuthenticatedIdentity,
    OneShotClaim,
}

/// Typed rejection. Every variant fails closed: no witness, peer, or permit,
/// and no partial state change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSitePromotionRejection {
    StoreUnavailable,
    NoLiveAuthority,
    Recheck(OwnerSiteRecheck),
    StorePersist,
    DuplicateRegistration,
}

impl From<crate::owner_site_resolution_store::OwnerSiteResolutionStoreError>
    for OwnerSitePromotionRejection
{
    fn from(error: crate::owner_site_resolution_store::OwnerSiteResolutionStoreError) -> Self {
        use crate::owner_site_resolution_store::OwnerSiteResolutionStoreError as StoreError;
        match error {
            StoreError::Unavailable => Self::StoreUnavailable,
            StoreError::DuplicateKey | StoreError::DuplicateClaim => Self::DuplicateRegistration,
            _ => Self::StorePersist,
        }
    }
}

/// The single synchronized promotion linearizer (§7). Every mutation of the
/// resolution store and the owned authority observation passes through one
/// `Mutex`; there are no independent locks whose composition could expose half
/// a transaction.
pub(crate) struct OwnerSitePromotionLinearizer {
    inner: std::sync::Mutex<OwnerSitePromotionLinearizerInner>,
}

struct OwnerSitePromotionLinearizerInner {
    store: crate::owner_site_resolution_store::OwnerSiteResolutionStore,
    authority: Option<OwnerSiteAuthorityObservation>,
}

/// Derive the resolution key from the sealed `PendingFinished` private fields.
fn owner_site_resolution_key(
    pending_finished: &PendingFinished,
) -> crate::owner_site_resolution_store::OwnerSiteResolutionKeyV1 {
    crate::owner_site_resolution_store::OwnerSiteResolutionKeyV1 {
        household: pending_finished.household.0.clone(),
        ws_instance: *pending_finished.ws_instance.as_bytes(),
        channel_id: *pending_finished.channel_id.as_bytes(),
        channel_epoch: pending_finished.channel_epoch.get(),
        channel_binding: pending_finished.channel_binding,
    }
}

impl OwnerSitePromotionLinearizer {
    /// Open the linearizer over the durable resolution store. No authority is
    /// observed yet; in production nothing ever populates it.
    pub(crate) fn open(
        state_dir: &std::path::Path,
    ) -> Result<Self, OwnerSitePromotionRejection> {
        let store =
            crate::owner_site_resolution_store::OwnerSiteResolutionStore::open(state_dir)?;
        Ok(Self {
            inner: std::sync::Mutex::new(OwnerSitePromotionLinearizerInner {
                store,
                authority: None,
            }),
        })
    }

    /// TEST-ONLY authority seam. Production has no admitting provider, so this
    /// is the only path that ever makes the linearizer reachable; it advances
    /// the durable authority watermark inside the same lock.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observe_authority_for_harness(
        &self,
        household: &str,
        authz_epoch: u64,
        roster_digest: [u8; 32],
        provider_generation: u64,
        cancellation_generation: u64,
        household_root: [u8; 33],
        observed_at: u64,
    ) -> Result<(), OwnerSitePromotionRejection> {
        let mut inner = self.inner.lock().expect("linearizer mutex poisoned");
        inner.store.observe_authority(
            household,
            authz_epoch,
            roster_digest,
            provider_generation,
            cancellation_generation,
        )?;
        inner.authority = Some(OwnerSiteAuthorityObservation {
            household: household.to_string(),
            authz_epoch,
            roster_digest,
            provider_generation,
            cancellation_generation,
            household_root,
            observed_at,
        });
        Ok(())
    }

    /// Register one sealed `Pending` (§7.1): derive its key from private fields,
    /// mint a CSPRNG claim, persist the `Pending` record, and return an owned
    /// input. No variant accepts the 15 fields raw.
    pub(crate) fn register_pending(
        &self,
        pending: Pending,
    ) -> Result<OwnerSitePromotionInput, OwnerSitePromotionRejection> {
        let mut inner = self.inner.lock().expect("linearizer mutex poisoned");
        let key = owner_site_resolution_key(&pending.pending_finished);
        let claim = OwnerSitePromotionClaimId::generate();
        let pending_finished = &pending.pending_finished;
        inner.store.register_pending(
            key,
            *claim.as_bytes(),
            pending_finished.authz_epoch.get(),
            pending_finished.roster_digest,
            pending_finished.provider_generation,
            pending_finished.cancellation_generation,
        )?;
        Ok(OwnerSitePromotionInput { pending, claim })
    }

    /// The one atomic promotion path (§7.3–7.9). Runs the seven rechecks inside
    /// the critical section with no lock release and no `await`, CAS
    /// `Pending -> Promoted`, consumes the claim, persists, and only then
    /// produces the sealed witness. Any failure leaves zero carrier/state.
    pub(crate) fn authorize(
        &self,
        input: OwnerSitePromotionInput,
    ) -> Result<OwnerSitePromotionWitness, OwnerSitePromotionRejection> {
        let mut inner = self.inner.lock().expect("linearizer mutex poisoned");
        let OwnerSitePromotionInput { pending, claim } = input;
        let key = owner_site_resolution_key(&pending.pending_finished);
        let authority = inner
            .authority
            .clone()
            .ok_or(OwnerSitePromotionRejection::NoLiveAuthority)?;
        let pending_finished = &pending.pending_finished;

        // (1) Authority exact — captured (household, authz_epoch, roster_digest)
        // equal the current authority coordinate.
        if pending_finished.household.0 != authority.household
            || pending_finished.authz_epoch.get() != authority.authz_epoch
            || pending_finished.roster_digest != authority.roster_digest
        {
            return Err(OwnerSitePromotionRejection::Recheck(
                OwnerSiteRecheck::AuthorityExact,
            ));
        }
        // (2) Cancellation fence — captured equals current and the durable
        // watermark has not advanced past it (no later revoke/tombstone).
        let watermark = inner.store.watermark(
            &pending_finished.household.0,
            pending_finished.authz_epoch.get(),
            pending_finished.roster_digest,
        );
        if pending_finished.cancellation_generation != authority.cancellation_generation
            || watermark.is_some_and(|(_, cancel)| cancel > pending_finished.cancellation_generation)
        {
            return Err(OwnerSitePromotionRejection::Recheck(
                OwnerSiteRecheck::CancellationFence,
            ));
        }
        // (3) Provider generation.
        if pending_finished.provider_generation != authority.provider_generation {
            return Err(OwnerSitePromotionRejection::Recheck(
                OwnerSiteRecheck::ProviderGeneration,
            ));
        }
        // (4) Freshness — not expired at the observed clock.
        if authority.observed_at >= pending_finished.fresh_until {
            return Err(OwnerSitePromotionRejection::Recheck(
                OwnerSiteRecheck::Freshness,
            ));
        }
        // (5) Channel identity (§8.5) — this key resolves to a unique live
        // (non-Closed) record. Per the store's key-uniqueness invariant a key
        // maps to at most one record, so "the unique live record" reduces to
        // "a live record exists". State (Pending vs Promoted/Revoking), claim
        // belonging, one-shot consumption and saturation are all recheck (7),
        // enforced by the store `promote` CAS below; a Closed or absent key
        // fails here.
        if inner.store.live_record(&key).is_none() {
            return Err(OwnerSitePromotionRejection::Recheck(
                OwnerSiteRecheck::ChannelIdentity,
            ));
        }
        // (6) Authenticated identity — machine cert chains to the household root
        // and the device binding still matches principal_D.
        if household_rs::machine_cert::verify_against_household_root(
            &pending_finished.machine_cert,
            &authority.household_root,
        )
        .is_err()
            || pending_finished.device_binding.participant_npub
                != pending_finished.principal_d.participant_npub()
        {
            return Err(OwnerSitePromotionRejection::Recheck(
                OwnerSiteRecheck::AuthenticatedIdentity,
            ));
        }
        // (7) One-shot claim — present, belongs to the key, unconsumed. The
        // store CAS `Pending -> Promoted` + claim-consume is the atomic image.
        inner
            .store
            .promote(&key, claim.as_bytes())
            .map_err(|_| OwnerSitePromotionRejection::Recheck(OwnerSiteRecheck::OneShotClaim))?;

        // Persistence succeeded; only now is the witness produced.
        Ok(OwnerSitePromotionWitness {
            pending,
            claim,
            seal: OwnerSitePromotionWitnessSeal,
        })
    }

    /// Revoke a promoted channel in the mandatory order (§9): persist the
    /// cancellation advance and mark `Revoking`, publish the fence and release
    /// the linearizer without `await`, drain (empty in this slice — no dial or
    /// pump, so no network I/O is introduced to "demonstrate" it), then reenter
    /// and confirm `Closed`. The channel is consumed by ownership; its retained
    /// witness supplies the exact key without a rebind.
    // The channel is consumed by ownership (§7.11/§9): revoke destroys the
    // promoted channel so it can never be revoked twice; taking it by value is
    // the enforcement, even though the body only reads its retained key.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn revoke(
        &self,
        channel: crate::owner_site_promotion::OwnerSitePromotedChannel,
        cancellation_generation: u64,
    ) -> Result<(), OwnerSitePromotionRejection> {
        let key = owner_site_resolution_key(&channel.witness.pending.pending_finished);
        {
            let mut inner = self.inner.lock().expect("linearizer mutex poisoned");
            inner.store.begin_revoke(&key, cancellation_generation)?;
        }
        // Fence published; linearizer released. Drain is empty in this slice.
        {
            let mut inner = self.inner.lock().expect("linearizer mutex poisoned");
            inner.store.confirm_closed(&key)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::keys::{IdentityKey, P256Keypair};
    use household_rs::machine_cert::SignOptions;
    use household_rs::{Platform, derive_household_id};

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

    fn pending_finished_fixture() -> (PendingFinished, AuthenticatedConfidentialChannel) {
        let household_root = P256Keypair::generate();
        let machine = P256Keypair::generate();
        let household = derive_household_id(&household_root.public());
        let machine_cert = MachineCert::sign(
            &household_root,
            &machine.public(),
            &SignOptions {
                hh_id: household.clone(),
                hostname: "pending-secret-host".to_owned(),
                platform: Platform::Macos,
                joined_at: 1_000,
            },
        )
        .expect("machine certificate");
        let device_binding = signed_member_device("npub1pendingsecret");
        let principal_d = OwnerSiteRemotePrincipal::injected_for_harness("npub1pendingsecret")
            .expect("remote principal");
        let exact_resource =
            OwnerSiteResource::from_route_claw("pending-secret-claw").expect("resource");
        let exact_route =
            crate::owner_site_capability::OwnerSiteCanonicalRequest::injected_for_harness(
                crate::owner_site_capability::OwnerSiteRequestMethod::Post,
                "/api/v1/household/claws/{name}/owner-site/preflight",
                [0x31; 32],
            )
            .expect("canonical route");
        let ws_instance = OwnerSiteWebSocketInstance::injected_for_harness([0x21; 32]);
        let channel_id = OwnerSiteChannelId::injected_for_harness([0x22; 32]);
        let channel_epoch = OwnerSiteChannelEpoch::injected_for_harness(7).expect("channel epoch");
        let channel_binding = [0x23; 32];
        let channel = AuthenticatedConfidentialChannel::injected_for_harness(
            ws_instance,
            channel_id,
            channel_epoch,
            channel_binding,
        );
        let pending = PendingFinished::injected_for_harness(
            household,
            exact_resource,
            exact_route,
            machine_cert,
            device_binding,
            principal_d,
            ws_instance,
            channel_id,
            channel_epoch,
            channel_binding,
            9,
            [0x24; 32],
            1_060,
            11,
            13,
        )
        .expect("synthetic pending state");
        (pending, channel)
    }

    #[test]
    fn pending_finished_debug_is_redacted_and_does_not_leak_tuple_material() {
        let (pending, channel) = pending_finished_fixture();
        let pending_debug = format!("{pending:?}");
        let channel_debug = format!("{channel:?}");

        assert_eq!(pending_debug, "PendingFinished(REDACTED)");
        assert_eq!(channel_debug, "AuthenticatedConfidentialChannel(REDACTED)");
        for secret in [
            "pending-secret-host",
            "npub1pendingsecret",
            "pending-secret-claw",
            "/api/v1/household/claws",
        ] {
            assert!(!pending_debug.contains(secret));
            assert!(!channel_debug.contains(secret));
        }
    }

    #[test]
    fn generation_comparison_is_pure_and_distinguishes_every_fence() {
        let (pending, _channel) = pending_finished_fixture();
        let expected = pending.generation_vector();
        assert_eq!(
            compare_owner_site_generations(expected, expected),
            OwnerSiteGenerationComparison::Exact
        );

        let authority_changed = OwnerSiteGenerationVector {
            roster_digest: [0x99; 32],
            ..expected
        };
        assert_eq!(
            compare_owner_site_generations(expected, authority_changed),
            OwnerSiteGenerationComparison::AuthorityChanged
        );
        let provider_changed = OwnerSiteGenerationVector {
            provider_generation: expected.provider_generation + 1,
            ..expected
        };
        assert_eq!(
            compare_owner_site_generations(expected, provider_changed),
            OwnerSiteGenerationComparison::ProviderChanged
        );
        let cancellation_changed = OwnerSiteGenerationVector {
            cancellation_generation: expected.cancellation_generation + 1,
            ..expected
        };
        assert_eq!(
            compare_owner_site_generations(expected, cancellation_changed),
            OwnerSiteGenerationComparison::CancellationChanged
        );
    }

    #[test]
    fn pending_can_only_close_and_promotion_is_unreachable_in_this_slice() {
        assert!(owner_site_transition_is_allowed(
            OwnerSiteStateKind::Pending,
            OwnerSiteStateKind::Closing
        ));
        assert!(owner_site_transition_is_allowed(
            OwnerSiteStateKind::Closing,
            OwnerSiteStateKind::Closed
        ));
        assert!(owner_site_transition_is_allowed(
            OwnerSiteStateKind::Closed,
            OwnerSiteStateKind::Closed
        ));
        assert!(!owner_site_transition_is_allowed(
            OwnerSiteStateKind::Pending,
            OwnerSiteStateKind::Promoted
        ));
        assert!(!owner_site_transition_is_allowed(
            OwnerSiteStateKind::Pending,
            OwnerSiteStateKind::Dialing
        ));
        assert!(!owner_site_transition_is_allowed(
            OwnerSiteStateKind::Pending,
            OwnerSiteStateKind::Pumping
        ));

        // Merely naming the future carrier states proves their types compile;
        // no value or construction path for any of them exists in this slice.
        let future_state_types = [
            std::any::type_name::<Promoted>(),
            std::any::type_name::<Dialing>(),
            std::any::type_name::<Pumping>(),
            std::any::type_name::<Revoking>(),
        ];
        assert!(future_state_types.iter().all(|name| !name.is_empty()));

        let (mismatched_pending, _channel) = pending_finished_fixture();
        let mismatched_channel = AuthenticatedConfidentialChannel::injected_for_harness(
            mismatched_pending.ws_instance,
            OwnerSiteChannelId::injected_for_harness([0xff; 32]),
            mismatched_pending.channel_epoch,
            mismatched_pending.channel_binding,
        );
        assert!(matches!(
            Pending::injected_for_harness(mismatched_pending, mismatched_channel),
            Err(OwnerSiteAuthorityError::ChannelProofMismatch)
        ));

        let (pending_finished, channel) = pending_finished_fixture();
        let pending = Pending::injected_for_harness(pending_finished, channel)
            .expect("matching channel proof");
        let closed = pending.begin_closing().finish();
        let _still_closed = closed.close();
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

    // ===== Fatia-2 linearizer: happy path + individual recheck negatives =====

    #[allow(clippy::type_complexity)]
    fn linearizer_fixture() -> (
        tempfile::TempDir,
        OwnerSitePromotionLinearizer,
        Pending,
        String,
        [u8; 33],
    ) {
        let household_root = P256Keypair::generate();
        let machine = P256Keypair::generate();
        let household = derive_household_id(&household_root.public());
        let machine_cert = MachineCert::sign(
            &household_root,
            &machine.public(),
            &SignOptions {
                hh_id: household.clone(),
                hostname: "linearizer-host".to_owned(),
                platform: Platform::Macos,
                joined_at: 1_000,
            },
        )
        .expect("machine certificate");
        let device_binding = signed_member_device("npub1linearizer");
        let principal_d = OwnerSiteRemotePrincipal::injected_for_harness("npub1linearizer")
            .expect("remote principal");
        let exact_resource =
            OwnerSiteResource::from_route_claw("linearizer-claw").expect("resource");
        let exact_route =
            crate::owner_site_capability::OwnerSiteCanonicalRequest::injected_for_harness(
                crate::owner_site_capability::OwnerSiteRequestMethod::Post,
                "/api/v1/household/claws/{name}/owner-site/preflight",
                [0x31; 32],
            )
            .expect("canonical route");
        let ws_instance = OwnerSiteWebSocketInstance::injected_for_harness([0x21; 32]);
        let channel_id = OwnerSiteChannelId::injected_for_harness([0x22; 32]);
        let channel_epoch = OwnerSiteChannelEpoch::injected_for_harness(7).expect("channel epoch");
        let channel_binding = [0x23; 32];
        let channel = AuthenticatedConfidentialChannel::injected_for_harness(
            ws_instance,
            channel_id,
            channel_epoch,
            channel_binding,
        );
        let pending_finished = PendingFinished::injected_for_harness(
            household.clone(),
            exact_resource,
            exact_route,
            machine_cert,
            device_binding,
            principal_d,
            ws_instance,
            channel_id,
            channel_epoch,
            channel_binding,
            9,
            [0x24; 32],
            1_060,
            11,
            13,
        )
        .expect("synthetic pending state");
        let pending = Pending::injected_for_harness(pending_finished, channel).expect("pending");
        let root = *household_root.public().as_bytes();
        let dir = tempfile::tempdir().expect("tempdir");
        let linearizer = OwnerSitePromotionLinearizer::open(dir.path()).expect("open linearizer");
        (dir, linearizer, pending, household.0, root)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_promotion(
        authz_epoch: u64,
        roster_digest: [u8; 32],
        provider_generation: u64,
        cancellation_generation: u64,
        household_root: Option<[u8; 33]>,
        observed_at: u64,
    ) -> Result<OwnerSitePromotionWitness, OwnerSitePromotionRejection> {
        let (_dir, linearizer, pending, household, root) = linearizer_fixture();
        let root = household_root.unwrap_or(root);
        linearizer
            .observe_authority_for_harness(
                &household,
                authz_epoch,
                roster_digest,
                provider_generation,
                cancellation_generation,
                root,
                observed_at,
            )
            .expect("observe authority");
        let input = linearizer.register_pending(pending).expect("register pending");
        linearizer.authorize(input)
    }

    #[test]
    fn fatia2_happy_path_promotes_and_yields_witness() {
        let result = run_promotion(9, [0x24; 32], 11, 13, None, 1_001);
        assert!(matches!(result, Ok(_)), "happy path must promote: {result:?}");
    }

    #[test]
    fn fatia2_recheck_authority_exact_negative() {
        assert!(matches!(
            run_promotion(10, [0x24; 32], 11, 13, None, 1_001),
            Err(OwnerSitePromotionRejection::Recheck(OwnerSiteRecheck::AuthorityExact))
        ));
        assert!(matches!(
            run_promotion(9, [0x99; 32], 11, 13, None, 1_001),
            Err(OwnerSitePromotionRejection::Recheck(OwnerSiteRecheck::AuthorityExact))
        ));
    }

    #[test]
    fn fatia2_recheck_cancellation_fence_negative() {
        assert!(matches!(
            run_promotion(9, [0x24; 32], 11, 14, None, 1_001),
            Err(OwnerSitePromotionRejection::Recheck(OwnerSiteRecheck::CancellationFence))
        ));
    }

    #[test]
    fn fatia2_recheck_provider_generation_negative() {
        assert!(matches!(
            run_promotion(9, [0x24; 32], 12, 13, None, 1_001),
            Err(OwnerSitePromotionRejection::Recheck(OwnerSiteRecheck::ProviderGeneration))
        ));
    }

    #[test]
    fn fatia2_recheck_freshness_negative() {
        assert!(matches!(
            run_promotion(9, [0x24; 32], 11, 13, None, 1_060),
            Err(OwnerSitePromotionRejection::Recheck(OwnerSiteRecheck::Freshness))
        ));
    }

    #[test]
    fn fatia2_recheck_authenticated_identity_negative() {
        let wrong_root = *P256Keypair::generate().public().as_bytes();
        assert!(matches!(
            run_promotion(9, [0x24; 32], 11, 13, Some(wrong_root), 1_001),
            Err(OwnerSitePromotionRejection::Recheck(OwnerSiteRecheck::AuthenticatedIdentity))
        ));
    }

    #[test]
    fn fatia2_authorize_without_observed_authority_fails_closed() {
        let (_dir, linearizer, pending, _household, _root) = linearizer_fixture();
        let input = linearizer.register_pending(pending).expect("register pending");
        assert!(matches!(
            linearizer.authorize(input),
            Err(OwnerSitePromotionRejection::NoLiveAuthority)
        ));
    }

    #[test]
    fn fatia2_promote_boundary_yields_promoted_channel() {
        let (_dir, linearizer, pending, household, root) = linearizer_fixture();
        linearizer
            .observe_authority_for_harness(&household, 9, [0x24; 32], 11, 13, root, 1_001)
            .expect("observe authority");
        let input = linearizer.register_pending(pending).expect("register pending");
        let request = crate::owner_site_promotion::OwnerSitePromotionRequest(input);
        let result =
            crate::owner_site_promotion::OwnerSitePromotionBoundary::promote(&linearizer, request);
        assert!(matches!(result, Ok(_)), "promote must yield a channel: {result:?}");
    }

    #[test]
    fn fatia2_revoke_promoted_channel_closes() {
        let (_dir, linearizer, pending, household, root) = linearizer_fixture();
        linearizer
            .observe_authority_for_harness(&household, 9, [0x24; 32], 11, 13, root, 1_001)
            .expect("observe authority");
        let input = linearizer.register_pending(pending).expect("register pending");
        let request = crate::owner_site_promotion::OwnerSitePromotionRequest(input);
        let channel =
            crate::owner_site_promotion::OwnerSitePromotionBoundary::promote(&linearizer, request)
                .expect("promote");
        // Revoke follows the §9 order (persist advance -> Revoking -> release ->
        // empty drain -> confirm Closed) and consumes the channel by ownership.
        linearizer.revoke(channel, 14).expect("revoke closes the channel");
    }

    #[test]
    fn fatia2_recheck_channel_identity_negative() {
        let (_dir, linearizer, pending, household, root) = linearizer_fixture();
        linearizer
            .observe_authority_for_harness(&household, 9, [0x24; 32], 11, 13, root, 1_001)
            .expect("observe authority");
        // The key is never registered, so it has no live record. Rechecks 1-4
        // pass; recheck (5) rejects with ChannelIdentity and mutates nothing.
        // (Two live records for one key are unreachable by the store's
        // key-uniqueness invariant, proved separately in the store tests, so the
        // absent/Closed case is the sufficient and correct negative.)
        let key = owner_site_resolution_key(&pending.pending_finished);
        let input = OwnerSitePromotionInput {
            pending,
            claim: OwnerSitePromotionClaimId([0xEE; 32]),
        };
        assert!(matches!(
            linearizer.authorize(input),
            Err(OwnerSitePromotionRejection::Recheck(
                OwnerSiteRecheck::ChannelIdentity
            ))
        ));
        // Zero carrier (Err, no witness) and zero mutation: no record was
        // created and the claim was never registered or consumed.
        let inner = linearizer.inner.lock().expect("linearizer mutex");
        assert!(
            inner.store.live_record(&key).is_none(),
            "a gate-5 rejection must not create a live record"
        );
        assert!(
            !inner.store.is_claim_present(&[0xEE; 32]),
            "a gate-5 rejection must not register or consume the claim"
        );
    }

    #[test]
    fn fatia2_recheck_one_shot_claim_negative() {
        let (_dir, linearizer, pending, household, root) = linearizer_fixture();
        linearizer
            .observe_authority_for_harness(&household, 9, [0x24; 32], 11, 13, root, 1_001)
            .expect("observe authority");
        let key = owner_site_resolution_key(&pending.pending_finished);
        // A live `Pending` record exists (recheck 5 passes), but the input's
        // claim does not belong to the key. Recheck (7)'s store `promote` CAS
        // rejects it as OneShotClaim, with no witness and no state change.
        let mut input = linearizer.register_pending(pending).expect("register pending");
        let registered_claim = *input.claim.as_bytes();
        input.claim = OwnerSitePromotionClaimId([0xEE; 32]);
        assert_ne!(
            [0xEE; 32], registered_claim,
            "the divergent test claim must differ from the registered claim"
        );
        assert!(matches!(
            linearizer.authorize(input),
            Err(OwnerSitePromotionRejection::Recheck(
                OwnerSiteRecheck::OneShotClaim
            ))
        ));
        // Zero carrier (Err, no witness) and zero mutation: the record stays a
        // live `Pending`, its registered claim is intact, and the divergent
        // claim was never consumed.
        let inner = linearizer.inner.lock().expect("linearizer mutex");
        let record = inner
            .store
            .live_record(&key)
            .expect("the registered record stays live");
        assert_eq!(
            record.state(),
            crate::owner_site_resolution_store::OwnerSiteResolutionState::Pending,
            "a gate-7 rejection must leave the record Pending"
        );
        assert_eq!(
            record.claim_id(),
            &registered_claim,
            "a gate-7 rejection must leave the registered claim intact"
        );
        assert!(
            !inner.store.is_claim_present(&[0xEE; 32]),
            "the divergent claim must never be consumed"
        );
    }
}
