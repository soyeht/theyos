//! Inert owner-present foundation for the Product A mobile Claw VPN DEV flow.
//!
//! This module deliberately has no route, handler, `AppState`, environment,
//! relying-party, Mesh-C, mint, host, or network integration. Its symbols are
//! private to the module, so production code cannot construct authority from
//! these types. A later reviewed slice must explicitly open the boundary.

use std::{
    fmt,
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use household_rs::{
    machine_cert::PersonId,
    owner_approval_v2::{
        MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID, MOBILE_CLAW_VPN_DEV_E2E_MAX_APPROVAL_TTL_SECS,
        MobileClawVpnDevE2eExecutionTupleV1, OwnerApprovalContextV2,
    },
};
use rand::{CryptoRng, RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const CONFIG_DIGEST_DOMAIN: &[u8] = b"theyos-mobile-claw-vpn-owner-present-config-v1\0";
const MEMBER_SCOPE_DOMAIN: &[u8] = b"theyos-mobile-claw-vpn-owner-present-member-v1\0";
const AUTHORITY_SNAPSHOT_DOMAIN: &[u8] = b"theyos-mobile-claw-vpn-owner-present-authority-v1\0";
const RESERVATION_HASH_DOMAIN: &[u8] = b"theyos-mobile-claw-vpn-owner-present-reservation-v1\0";
const CHALLENGE_HASH_DOMAIN: &[u8] = b"theyos-mobile-claw-vpn-owner-present-challenge-v1\0";
const PROOF_TOKEN_HASH_DOMAIN: &[u8] = b"theyos-mobile-claw-vpn-owner-present-proof-token-v1\0";
const CANONICAL_CONFIG_VERSION: u16 = 1;
const OPAQUE_SECRET_LEN: usize = 32;
const MAX_RANDOM_ATTEMPTS: usize = 8;
const MAX_CONFIG_ID_LEN: usize = 128;
const ABSOLUTE_MAX_STORE_ENTRIES: usize = 1_024;

#[derive(Clone, Copy)]
struct ClockReading {
    monotonic: Instant,
    wall: Duration,
}

trait FoundationClock: Send + Sync {
    fn read(&self) -> Result<ClockReading, FoundationError>;
}

struct SystemClock;

impl FoundationClock for SystemClock {
    fn read(&self) -> Result<ClockReading, FoundationError> {
        // Capture monotonic first: scheduler delay before the wall sample can
        // only shorten the derived deadline, never extend signed expiry.
        let monotonic = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| FoundationError::InvalidClock)?;
        Ok(ClockReading { monotonic, wall })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClawSelector {
    ClawM,
    ClawL,
}

impl ClawSelector {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ClawM => "Claw-M",
            Self::ClawL => "Claw-L",
        }
    }
}

impl TryFrom<&str> for ClawSelector {
    type Error = FoundationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Claw-M" => Ok(Self::ClawM),
            "Claw-L" => Ok(Self::ClawL),
            _ => Err(FoundationError::UnknownSelector),
        }
    }
}

#[derive(Clone, Copy)]
struct TrustedConfigInput<'a> {
    generation: u64,
    bundle_id: &'a str,
    device_id: &'a str,
    claw_m_id: &'a str,
    claw_l_id: &'a str,
}

#[derive(Clone)]
struct TrustedConfig {
    inner: Arc<TrustedConfigInner>,
}

struct TrustedConfigInner {
    generation: u64,
    device_id: String,
    claw_m_id: String,
    claw_l_id: String,
    digest: [u8; 32],
}

impl fmt::Debug for TrustedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedConfig")
            .field("version", &CANONICAL_CONFIG_VERSION)
            .field("generation", &self.inner.generation)
            .field("digest", &"<redacted>")
            .field("identifiers", &"<redacted>")
            .finish()
    }
}

impl TrustedConfig {
    fn try_new(input: TrustedConfigInput<'_>) -> Result<Self, FoundationError> {
        if input.generation == 0 {
            return Err(FoundationError::InvalidConfig("generation"));
        }
        if input.bundle_id != MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID {
            return Err(FoundationError::InvalidConfig("bundle_id"));
        }
        validate_config_id(input.device_id, ConfigIdKind::Device)?;
        validate_config_id(input.claw_m_id, ConfigIdKind::Claw)?;
        validate_config_id(input.claw_l_id, ConfigIdKind::Claw)?;
        if input.claw_m_id == input.claw_l_id {
            return Err(FoundationError::InvalidConfig("duplicate_claw_id"));
        }
        if input.device_id == input.claw_m_id || input.device_id == input.claw_l_id {
            return Err(FoundationError::InvalidConfig("device_claw_collision"));
        }

        let digest = config_digest(&input)?;
        Ok(Self {
            inner: Arc::new(TrustedConfigInner {
                generation: input.generation,
                device_id: input.device_id.to_string(),
                claw_m_id: input.claw_m_id.to_string(),
                claw_l_id: input.claw_l_id.to_string(),
                digest,
            }),
        })
    }

    fn resolve(&self, selector: ClawSelector) -> ConfigSelection {
        let claw_id = match selector {
            ClawSelector::ClawM => &self.inner.claw_m_id,
            ClawSelector::ClawL => &self.inner.claw_l_id,
        };
        ConfigSelection {
            selector,
            generation: self.inner.generation,
            config_digest: self.inner.digest,
            device_id: self.inner.device_id.clone(),
            claw_id: claw_id.clone(),
        }
    }
}

#[derive(Clone)]
struct ConfigSelection {
    selector: ClawSelector,
    generation: u64,
    config_digest: [u8; 32],
    device_id: String,
    claw_id: String,
}

impl fmt::Debug for ConfigSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigSelection")
            .field("selector", &self.selector)
            .field("generation", &self.generation)
            .field("config_digest", &"<redacted>")
            .field("identifiers", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct MemberScope([u8; 32]);

impl fmt::Debug for MemberScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemberScope(<redacted>)")
    }
}

impl MemberScope {
    fn from_server_derived(member_id: &str) -> Result<Self, FoundationError> {
        validate_phase0_id(member_id).map_err(|_| FoundationError::InvalidBinding)?;
        Ok(Self(domain_hash(MEMBER_SCOPE_DOMAIN, member_id.as_bytes())))
    }

    fn ct_eq_choice(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[derive(Clone)]
struct OwnerAuthoritySnapshot {
    owner_p_id: PersonId,
    head_sequence: u64,
    head_hash: [u8; 32],
    credential_set_digest: [u8; 32],
}

impl fmt::Debug for OwnerAuthoritySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerAuthoritySnapshot")
            .field("owner", &"<redacted>")
            .field("authority_head", &"<redacted>")
            .field("credential_set", &"<redacted>")
            .finish()
    }
}

impl OwnerAuthoritySnapshot {
    fn digest(&self) -> Result<[u8; 32], FoundationError> {
        if !PersonId::is_well_formed(&self.owner_p_id.0) {
            return Err(FoundationError::InvalidBinding);
        }
        let mut hasher = Sha256::new();
        hasher.update(AUTHORITY_SNAPSHOT_DOMAIN);
        update_len_prefixed(&mut hasher, self.owner_p_id.0.as_bytes())?;
        hasher.update(self.head_sequence.to_be_bytes());
        hasher.update(self.head_hash);
        hasher.update(self.credential_set_digest);
        Ok(hasher.finalize().into())
    }
}

#[derive(Clone)]
struct StoredBinding {
    member_scope: MemberScope,
    config_generation: u64,
    config_digest: [u8; 32],
    tuple_canonical: Arc<[u8]>,
    tuple_digest: [u8; 32],
    context_canonical: Arc<[u8]>,
    context_digest: [u8; 32],
    authority_digest: [u8; 32],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl fmt::Debug for StoredBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredBinding")
            .field("member", &"<redacted>")
            .field("config_generation", &self.config_generation)
            .field("config", &"<redacted>")
            .field("tuple", &"<redacted>")
            .field("context", &"<redacted>")
            .field("authority", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl StoredBinding {
    fn from_trusted_state(
        member_id: &str,
        selection: &ConfigSelection,
        tuple: &MobileClawVpnDevE2eExecutionTupleV1,
        context: &OwnerApprovalContextV2,
        authority: &OwnerAuthoritySnapshot,
    ) -> Result<Self, FoundationError> {
        tuple
            .validate_shape()
            .map_err(|_| FoundationError::InvalidBinding)?;
        context
            .validate_shape()
            .map_err(|_| FoundationError::InvalidBinding)?;

        if tuple.member_id != member_id
            || tuple.bundle_id != MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID
            || tuple.device_alias != "Device-D"
            || tuple.claw_alias != selection.selector.as_str()
            || tuple.device_id != selection.device_id
            || tuple.claw_id != selection.claw_id
            || context.hh_id != tuple.hh_id
            || context.owner_p_id != authority.owner_p_id
            || context.issued_at != tuple.issued_at
            || context.expires_at != tuple.expires_at
        {
            return Err(FoundationError::InvalidBinding);
        }
        let execution_hash = tuple
            .execution_hash()
            .map_err(|_| FoundationError::InvalidBinding)?;
        if context
            .mobile_claw_vpn_execution_hash
            .as_ref()
            .map(|value| value.as_slice())
            != Some(execution_hash.as_slice())
        {
            return Err(FoundationError::InvalidBinding);
        }

        let tuple_canonical = tuple
            .to_canonical_bytes()
            .map_err(|_| FoundationError::InvalidBinding)?;
        let context_canonical = context
            .to_canonical_bytes()
            .map_err(|_| FoundationError::InvalidBinding)?;
        let member_scope = MemberScope::from_server_derived(member_id)?;
        let authority_digest = authority.digest()?;

        Ok(Self {
            member_scope,
            config_generation: selection.generation,
            config_digest: selection.config_digest,
            tuple_digest: domain_hash(b"tuple\0", &tuple_canonical),
            tuple_canonical: Arc::from(tuple_canonical),
            context_digest: domain_hash(b"context\0", &context_canonical),
            context_canonical: Arc::from(context_canonical),
            authority_digest,
            issued_at_unix_seconds: context.issued_at,
            expires_at_unix_seconds: context.expires_at,
        })
    }

    fn matches(&self, other: &Self) -> bool {
        let fixed = self.member_scope.ct_eq_choice(&other.member_scope)
            & self.config_generation.ct_eq(&other.config_generation)
            & self.config_digest.ct_eq(&other.config_digest)
            & self.tuple_digest.ct_eq(&other.tuple_digest)
            & self.context_digest.ct_eq(&other.context_digest)
            & self.authority_digest.ct_eq(&other.authority_digest)
            & self
                .issued_at_unix_seconds
                .ct_eq(&other.issued_at_unix_seconds)
            & self
                .expires_at_unix_seconds
                .ct_eq(&other.expires_at_unix_seconds);
        bool::from(fixed)
            && self.tuple_canonical.as_ref() == other.tuple_canonical.as_ref()
            && self.context_canonical.as_ref() == other.context_canonical.as_ref()
    }

    fn matches_caller(&self, caller: &CallerScope) -> bool {
        bool::from(self.member_scope.ct_eq_choice(&caller.member_scope))
    }
}

// Start state is consumed when the pending record is committed. It cannot be
// retained and replayed as point-of-use freshness evidence.
struct StartServerBinding {
    stored: StoredBinding,
}

impl StartServerBinding {
    fn from_trusted_state(
        member_id: &str,
        selection: &ConfigSelection,
        tuple: &MobileClawVpnDevE2eExecutionTupleV1,
        context: &OwnerApprovalContextV2,
        authority: &OwnerAuthoritySnapshot,
    ) -> Result<Self, FoundationError> {
        Ok(Self {
            stored: StoredBinding::from_trusted_state(
                member_id, selection, tuple, context, authority,
            )?,
        })
    }
}

struct PointOfUseMarker;

// The mutable marker makes the permit lexical: it cannot outlive the one
// synchronous rederivation invocation that received it. The remaining fields
// bind that invocation to one concrete store entry and authenticated member.
struct PointOfUsePermit<'permit> {
    _invocation: &'permit mut PointOfUseMarker,
    _not_send_or_sync: PhantomData<Rc<()>>,
    store_identity: usize,
    entry_id: u64,
    member_scope: MemberScope,
}

struct FreshServerBinding<'permit> {
    stored: StoredBinding,
    permit: PointOfUsePermit<'permit>,
}

impl<'permit> FreshServerBinding<'permit> {
    fn from_trusted_state(
        permit: PointOfUsePermit<'permit>,
        member_id: &str,
        selection: &ConfigSelection,
        tuple: &MobileClawVpnDevE2eExecutionTupleV1,
        context: &OwnerApprovalContextV2,
        authority: &OwnerAuthoritySnapshot,
    ) -> Result<Self, FoundationError> {
        let stored =
            StoredBinding::from_trusted_state(member_id, selection, tuple, context, authority)?;
        if !bool::from(stored.member_scope.ct_eq_choice(&permit.member_scope)) {
            return Err(FoundationError::Rejected);
        }
        Ok(Self { stored, permit })
    }

    fn into_stored_for(
        self,
        store_identity: usize,
        entry_id: u64,
        member_scope: &MemberScope,
    ) -> Result<StoredBinding, FoundationError> {
        if self.permit.store_identity != store_identity
            || self.permit.entry_id != entry_id
            || !bool::from(self.permit.member_scope.ct_eq_choice(member_scope))
        {
            return Err(FoundationError::Rejected);
        }
        Ok(self.stored)
    }
}

// The final endpoint is token-only. This scope contains only identity derived
// from the authenticated bearer. Config, tuple, context, and authority are
// reconstructed by the server after the irreversible claim; their drift must
// burn rather than turn into a pre-claim lookup miss.
#[derive(Clone)]
struct CallerScope {
    member_scope: MemberScope,
}

impl CallerScope {
    fn from_server_derived_member(member_id: &str) -> Result<Self, FoundationError> {
        Ok(Self {
            member_scope: MemberScope::from_server_derived(member_id)?,
        })
    }
}

impl fmt::Debug for CallerScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallerScope(<redacted>)")
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy)]
struct StoreLimits {
    max_entries: usize,
    max_live_per_member: usize,
    max_reservation_ttl: Duration,
    max_proof_ttl: Duration,
}

impl StoreLimits {
    fn try_new(
        max_entries: usize,
        max_live_per_member: usize,
        max_reservation_ttl: Duration,
        max_proof_ttl: Duration,
    ) -> Result<Self, FoundationError> {
        let protocol_max = Duration::from_secs(MOBILE_CLAW_VPN_DEV_E2E_MAX_APPROVAL_TTL_SECS);
        if max_entries == 0
            || max_entries > ABSOLUTE_MAX_STORE_ENTRIES
            || max_live_per_member == 0
            || max_live_per_member > max_entries
            || max_reservation_ttl.is_zero()
            || max_proof_ttl.is_zero()
            || max_reservation_ttl > protocol_max
            || max_proof_ttl > protocol_max
        {
            return Err(FoundationError::InvalidLimits);
        }
        Ok(Self {
            max_entries,
            max_live_per_member,
            max_reservation_ttl,
            max_proof_ttl,
        })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ReservationHandle([u8; OPAQUE_SECRET_LEN]);

impl fmt::Debug for ReservationHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReservationHandle(<redacted>)")
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ChallengeHandle([u8; OPAQUE_SECRET_LEN]);

impl ChallengeHandle {
    fn from_server_random(bytes: [u8; OPAQUE_SECRET_LEN]) -> Result<Self, FoundationError> {
        if bytes.ct_eq(&[0; OPAQUE_SECRET_LEN]).into() {
            return Err(FoundationError::InvalidBinding);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for ChallengeHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChallengeHandle(<redacted>)")
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ProofToken([u8; OPAQUE_SECRET_LEN]);

impl ProofToken {
    fn as_bytes(&self) -> &[u8; OPAQUE_SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for ProofToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProofToken(<redacted>)")
    }
}

// Only this post-tombstone type may feed the later Mesh transaction. It is
// deliberately still not a Mesh freshness proof: the transaction must check
// member_devices, the full (member, device, claw) grant, and availability
// under the shared Mesh lock.
#[must_use = "a revalidated capability must be consumed by the later transaction"]
struct RevalidatedCapability {
    binding: StoredBinding,
    deadline: Instant,
    signed_wall_expiry: Duration,
}

impl fmt::Debug for RevalidatedCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RevalidatedCapability(<redacted>)")
    }
}

#[derive(Clone)]
struct CapabilityStore {
    inner: Arc<Mutex<StoreInner>>,
    clock: Arc<dyn FoundationClock>,
}

impl fmt::Debug for CapabilityStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.debug_struct("CapabilityStore")
            .field("status", &inner.status())
            .finish_non_exhaustive()
    }
}

impl CapabilityStore {
    fn new(limits: StoreLimits) -> Self {
        Self::with_clock(limits, Arc::new(SystemClock))
    }

    fn with_clock(limits: StoreLimits, clock: Arc<dyn FoundationClock>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(StoreInner {
                limits,
                next_entry_id: 1,
                entries: Vec::new(),
                last_clock: None,
            })),
            clock,
        }
    }

    fn lock_operation(&self) -> Result<MutexGuard<'_, StoreInner>, FoundationError> {
        self.inner.lock().map_err(|_| FoundationError::Poisoned)
    }

    fn lock_at_current_time(
        &self,
    ) -> Result<(MutexGuard<'_, StoreInner>, ClockReading), FoundationError> {
        let mut inner = self.lock_operation()?;
        let reading = self.clock.read()?;
        inner.observe_clock(reading)?;
        Ok((inner, reading))
    }

    fn identity(&self) -> usize {
        Arc::as_ptr(&self.inner).cast::<()>() as usize
    }

    fn reserve(
        &self,
        caller: &CallerScope,
        ttl: Duration,
    ) -> Result<ReservationHandle, FoundationError> {
        let mut rng = OsRng;
        self.reserve_with_rng(caller, ttl, &mut rng)
    }

    fn reserve_with_rng<R: CryptoRng + RngCore>(
        &self,
        caller: &CallerScope,
        ttl: Duration,
        rng: &mut R,
    ) -> Result<ReservationHandle, FoundationError> {
        let (mut inner, now) = self.lock_at_current_time()?;
        inner.prune_expired(now);
        inner.validate_reservation_capacity(&caller.member_scope, ttl)?;
        let deadline = now
            .monotonic
            .checked_add(ttl)
            .ok_or(FoundationError::InvalidDeadline)?;
        let entry_id = inner.next_entry_id;
        inner.next_entry_id = inner
            .next_entry_id
            .checked_add(1)
            .ok_or(FoundationError::CapacityExhausted)?;

        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let mut secret = [0u8; OPAQUE_SECRET_LEN];
            rng.fill_bytes(&mut secret);
            if bool::from(secret.ct_eq(&[0; OPAQUE_SECRET_LEN])) {
                secret.zeroize();
                continue;
            }
            let reservation_hash = domain_hash(RESERVATION_HASH_DOMAIN, &secret);
            if inner
                .lookup_hash_ct(LookupKind::AnyReservation, &reservation_hash)
                .index
                .is_some()
            {
                secret.zeroize();
                continue;
            }
            inner.entries.push(StoreEntry {
                entry_id,
                member_scope: caller.member_scope.clone(),
                reservation_hash,
                challenge_hash: None,
                proof_token_hash: None,
                deadline,
                signed_wall_expiry: None,
                state: EntryState::Reserved,
            });
            return Ok(ReservationHandle(secret));
        }
        Err(FoundationError::EntropyCollision)
    }

    fn release_reserved(&self, reservation: &ReservationHandle) -> Result<(), FoundationError> {
        let target = domain_hash(RESERVATION_HASH_DOMAIN, &reservation.0);
        let (mut inner, now) = self.lock_at_current_time()?;
        inner.prune_expired(now);
        let lookup = inner.lookup_hash_ct(LookupKind::Reserved, &target);
        let index = lookup.unique_index()?;
        inner.entries.swap_remove(index);
        Ok(())
    }

    fn commit_pending(
        &self,
        reservation: &ReservationHandle,
        challenge: &ChallengeHandle,
        binding: StartServerBinding,
    ) -> Result<(), FoundationError> {
        let binding = binding.stored;
        let reservation_hash = domain_hash(RESERVATION_HASH_DOMAIN, &reservation.0);
        let challenge_hash = domain_hash(CHALLENGE_HASH_DOMAIN, &challenge.0);
        let (mut inner, now) = self.lock_at_current_time()?;
        inner.prune_expired(now);
        let lookup = inner.lookup_hash_ct(LookupKind::Reserved, &reservation_hash);
        let index = lookup.unique_index()?;
        if !bool::from(
            inner.entries[index]
                .member_scope
                .ct_eq_choice(&binding.member_scope),
        ) {
            return Err(FoundationError::Rejected);
        }
        let signed_issued_at = Duration::from_secs(binding.issued_at_unix_seconds);
        let signed_expires_at = Duration::from_secs(binding.expires_at_unix_seconds);
        if signed_issued_at > now.wall || signed_expires_at <= now.wall {
            return Err(FoundationError::Expired);
        }
        let signed_remaining = signed_expires_at
            .checked_sub(now.wall)
            .ok_or(FoundationError::InvalidDeadline)?;
        let signed_deadline = now
            .monotonic
            .checked_add(signed_remaining)
            .ok_or(FoundationError::InvalidDeadline)?;
        let pending_deadline = inner.entries[index].deadline.min(signed_deadline);
        if inner
            .lookup_hash_ct(LookupKind::AnyChallenge, &challenge_hash)
            .index
            .is_some()
        {
            return Err(FoundationError::Rejected);
        }
        inner.entries[index].transition(EntryState::Pending { binding })?;
        inner.entries[index].deadline = pending_deadline;
        inner.entries[index].signed_wall_expiry = Some(signed_expires_at);
        inner.entries[index].challenge_hash = Some(challenge_hash);
        Ok(())
    }

    fn claim_finishing(
        &self,
        challenge: &ChallengeHandle,
        caller: &CallerScope,
    ) -> Result<FinishingClaim, FoundationError> {
        let challenge_hash = domain_hash(CHALLENGE_HASH_DOMAIN, &challenge.0);
        let (mut inner, now) = self.lock_at_current_time()?;
        inner.prune_expired(now);
        let lookup = inner.lookup_hash_ct(LookupKind::PendingChallenge, &challenge_hash);
        let index = lookup.unique_index()?;
        inner.entries[index].expire_live_at(now)?;
        let EntryState::Pending {
            binding: stored, ..
        } = &inner.entries[index].state
        else {
            return Err(FoundationError::Rejected);
        };
        if !stored.matches_caller(caller) {
            return Err(FoundationError::Rejected);
        }
        let binding = stored.clone();
        let entry_id = inner.entries[index].entry_id;
        let member_scope = stored.member_scope.clone();
        inner.entries[index].transition(EntryState::Finishing { binding })?;
        Ok(FinishingClaim {
            store: self.clone(),
            entry_id,
            member_scope,
            active: true,
        })
    }

    // Taking ownership makes the caller surrender the bearer value even on a
    // rejected attempt; `ProofToken` zeroizes its plaintext in `Drop`.
    #[allow(clippy::needless_pass_by_value)]
    fn consume_proof<F>(
        &self,
        token: ProofToken,
        caller: &CallerScope,
        rederive: F,
    ) -> Result<RevalidatedCapability, FoundationError>
    where
        F: for<'permit> FnOnce(
            PointOfUsePermit<'permit>,
        ) -> Result<FreshServerBinding<'permit>, FoundationError>,
    {
        let token_hash = domain_hash(PROOF_TOKEN_HASH_DOMAIN, token.as_bytes());
        let (stored, entry_id, member_scope, deadline, signed_wall_expiry) = {
            let (mut inner, now) = self.lock_at_current_time()?;
            inner.prune_expired(now);
            let lookup = inner.lookup_hash_ct(LookupKind::ProofToken, &token_hash);
            let index = lookup.unique_index()?;
            inner.entries[index].expire_live_at(now)?;
            let EntryState::ProofIssued {
                binding: stored, ..
            } = &inner.entries[index].state
            else {
                return Err(FoundationError::Rejected);
            };
            if !stored.matches_caller(caller) {
                return Err(FoundationError::Rejected);
            }
            let stored = stored.clone();
            let entry_id = inner.entries[index].entry_id;
            let member_scope = stored.member_scope.clone();
            let deadline = inner.entries[index].deadline;
            let signed_wall_expiry = inner.entries[index].signed_wall_expiry;
            inner.entries[index].transition(EntryState::Burned)?;
            (stored, entry_id, member_scope, deadline, signed_wall_expiry)
        };
        let signed_wall_expiry = signed_wall_expiry.ok_or(FoundationError::InvalidDeadline)?;

        let mut invocation = PointOfUseMarker;
        let fresh = rederive(PointOfUsePermit {
            _invocation: &mut invocation,
            _not_send_or_sync: PhantomData,
            store_identity: self.identity(),
            entry_id,
            member_scope: member_scope.clone(),
        })?;
        let current = fresh.into_stored_for(self.identity(), entry_id, &member_scope)?;
        if !stored.matches(&current) {
            return Err(FoundationError::Rejected);
        }
        let (_inner, now) = self.lock_at_current_time()?;
        if now.monotonic >= deadline || now.wall >= signed_wall_expiry {
            return Err(FoundationError::Expired);
        }
        Ok(RevalidatedCapability {
            binding: stored,
            deadline,
            signed_wall_expiry,
        })
    }

    fn status(&self) -> Result<StoreStatus, FoundationError> {
        let (mut inner, now) = self.lock_at_current_time()?;
        inner.prune_expired(now);
        Ok(inner.status())
    }

    fn prune_expired(&self) -> Result<(), FoundationError> {
        let (mut inner, now) = self.lock_at_current_time()?;
        inner.prune_expired(now);
        Ok(())
    }

    fn burn_finishing_sync(&self, entry_id: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = inner
            .entries
            .iter_mut()
            .find(|entry| entry.entry_id == entry_id)
            && matches!(entry.state, EntryState::Finishing { .. })
        {
            // Finishing -> Burned is guaranteed by the transition table. A
            // failure here would indicate memory corruption, so leave the
            // entry in Finishing rather than silently inventing a transition.
            let _ = entry.transition(EntryState::Burned);
        }
    }
}

#[must_use = "dropping an unfinished claim burns it synchronously"]
struct FinishingClaim {
    store: CapabilityStore,
    entry_id: u64,
    member_scope: MemberScope,
    active: bool,
}

impl fmt::Debug for FinishingClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FinishingClaim(<redacted>)")
    }
}

impl FinishingClaim {
    fn issue_proof<F>(self, ttl: Duration, rederive: F) -> Result<ProofToken, FoundationError>
    where
        F: for<'permit> FnOnce(
            PointOfUsePermit<'permit>,
        ) -> Result<FreshServerBinding<'permit>, FoundationError>,
    {
        let mut rng = OsRng;
        self.issue_proof_with_rng(ttl, rederive, &mut rng)
    }

    fn issue_proof_with_rng<F, R>(
        mut self,
        ttl: Duration,
        rederive: F,
        rng: &mut R,
    ) -> Result<ProofToken, FoundationError>
    where
        F: for<'permit> FnOnce(
            PointOfUsePermit<'permit>,
        ) -> Result<FreshServerBinding<'permit>, FoundationError>,
        R: CryptoRng + RngCore,
    {
        {
            let (mut inner, now) = self.store.lock_at_current_time()?;
            if ttl.is_zero() || ttl > inner.limits.max_proof_ttl {
                return Err(FoundationError::InvalidDeadline);
            }
            let index = inner
                .entries
                .iter()
                .position(|entry| entry.entry_id == self.entry_id)
                .ok_or(FoundationError::Rejected)?;
            inner.entries[index].expire_live_at(now)?;
            if !matches!(inner.entries[index].state, EntryState::Finishing { .. }) {
                return Err(FoundationError::Rejected);
            }
        }

        let mut invocation = PointOfUseMarker;
        let fresh = rederive(PointOfUsePermit {
            _invocation: &mut invocation,
            _not_send_or_sync: PhantomData,
            store_identity: self.store.identity(),
            entry_id: self.entry_id,
            member_scope: self.member_scope.clone(),
        })?;
        let current =
            fresh.into_stored_for(self.store.identity(), self.entry_id, &self.member_scope)?;

        // This second sample is the point-of-transition check. Even a
        // synchronous trusted-state read may cross signed expiry.
        let (mut inner, now) = self.store.lock_at_current_time()?;
        let index = inner
            .entries
            .iter()
            .position(|entry| entry.entry_id == self.entry_id)
            .ok_or(FoundationError::Rejected)?;
        inner.entries[index].expire_live_at(now)?;
        let EntryState::Finishing { binding } = &inner.entries[index].state else {
            return Err(FoundationError::Rejected);
        };
        if !binding.matches(&current) {
            return Err(FoundationError::Rejected);
        }
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let mut secret = Zeroizing::new([0u8; OPAQUE_SECRET_LEN]);
            rng.fill_bytes(secret.as_mut());
            let zero_secret = bool::from(secret.ct_eq(&[0; OPAQUE_SECRET_LEN]));
            let token_hash = domain_hash(PROOF_TOKEN_HASH_DOMAIN, secret.as_ref());
            let collision = inner
                .lookup_hash_ct(LookupKind::AnyProofToken, &token_hash)
                .index
                .is_some();
            let EntryState::Finishing { binding } = &inner.entries[index].state else {
                return Err(FoundationError::Rejected);
            };
            let binding = binding.clone();

            // Entropy acquisition, hashing, and the bounded collision scan can
            // all be preempted. Re-sample both clocks under the same mutex and
            // enforce signed expiry immediately before every transition or
            // retry.
            let transition_now = self.store.clock.read()?;
            inner.observe_clock(transition_now)?;
            inner.entries[index].expire_live_at(transition_now)?;
            if zero_secret || collision {
                continue;
            }
            if !matches!(inner.entries[index].state, EntryState::Finishing { .. }) {
                return Err(FoundationError::Rejected);
            }
            let ttl_deadline = transition_now
                .monotonic
                .checked_add(ttl)
                .ok_or(FoundationError::InvalidDeadline)?;
            let proof_deadline = inner.entries[index].deadline.min(ttl_deadline);
            inner.entries[index].deadline = proof_deadline;
            inner.entries[index].transition(EntryState::ProofIssued { binding })?;
            inner.entries[index].proof_token_hash = Some(token_hash);
            self.active = false;
            return Ok(ProofToken(*secret));
        }
        Err(FoundationError::EntropyCollision)
    }

    fn burn(mut self) {
        self.store.burn_finishing_sync(self.entry_id);
        self.active = false;
    }
}

impl Drop for FinishingClaim {
    fn drop(&mut self) {
        if self.active {
            self.store.burn_finishing_sync(self.entry_id);
        }
    }
}

struct StoreInner {
    limits: StoreLimits,
    next_entry_id: u64,
    entries: Vec<StoreEntry>,
    last_clock: Option<ClockReading>,
}

impl StoreInner {
    fn observe_clock(&mut self, reading: ClockReading) -> Result<(), FoundationError> {
        if let Some(last) = self.last_clock
            && (reading.monotonic < last.monotonic || reading.wall < last.wall)
        {
            return Err(FoundationError::ClockRegressed);
        }
        self.last_clock = Some(reading);
        Ok(())
    }

    fn validate_reservation_capacity(
        &self,
        member_scope: &MemberScope,
        ttl: Duration,
    ) -> Result<(), FoundationError> {
        if ttl.is_zero() || ttl > self.limits.max_reservation_ttl {
            return Err(FoundationError::InvalidDeadline);
        }
        if self.entries.len() >= self.limits.max_entries {
            return Err(FoundationError::StoreFull);
        }
        let member_live = self
            .entries
            .iter()
            .filter(|entry| {
                entry.state.is_live() && bool::from(entry.member_scope.ct_eq_choice(member_scope))
            })
            .count();
        if member_live >= self.limits.max_live_per_member {
            return Err(FoundationError::MemberFull);
        }
        Ok(())
    }

    fn prune_expired(&mut self, now: ClockReading) {
        let mut retained = Vec::with_capacity(self.entries.len());
        for mut entry in self.entries.drain(..) {
            match entry.state {
                EntryState::Burned if now.monotonic <= entry.deadline => {
                    retained.push(entry);
                }
                EntryState::Burned => {}
                EntryState::Reserved if now.monotonic >= entry.deadline => {}
                EntryState::Pending { .. }
                | EntryState::Finishing { .. }
                | EntryState::ProofIssued { .. }
                    if entry.is_live_expired(now) =>
                {
                    let _ = entry.transition(EntryState::Burned);
                    entry.deadline = now.monotonic;
                    retained.push(entry);
                }
                EntryState::Reserved
                | EntryState::Pending { .. }
                | EntryState::Finishing { .. }
                | EntryState::ProofIssued { .. } => retained.push(entry),
            }
        }
        self.entries = retained;
    }

    fn lookup_hash_ct(&self, kind: LookupKind, target: &[u8; 32]) -> CtLookup {
        let mut found = Choice::from(0);
        let mut duplicate = Choice::from(0);
        let mut selected = 0u64;
        let mut comparisons = 0usize;
        for (index, entry) in self.entries.iter().enumerate() {
            let (candidate, eligible) = entry.hash_for(kind);
            let equal = candidate.ct_eq(target) & eligible;
            let select = equal & !found;
            selected = u64::conditional_select(&selected, &(index as u64), select);
            duplicate |= found & equal;
            found |= equal;
            comparisons += 1;
        }
        let index = if bool::from(found) {
            usize::try_from(selected).ok()
        } else {
            None
        };
        CtLookup {
            index,
            duplicate: bool::from(duplicate),
            comparisons,
        }
    }

    fn status(&self) -> StoreStatus {
        let mut status = StoreStatus {
            total: self.entries.len(),
            ..StoreStatus::default()
        };
        for entry in &self.entries {
            match entry.state {
                EntryState::Reserved => status.reserved += 1,
                EntryState::Pending { .. } => status.pending += 1,
                EntryState::Finishing { .. } => status.finishing += 1,
                EntryState::ProofIssued { .. } => status.proof_issued += 1,
                EntryState::Burned => status.burned += 1,
            }
        }
        status
    }
}

struct StoreEntry {
    entry_id: u64,
    member_scope: MemberScope,
    reservation_hash: [u8; 32],
    challenge_hash: Option<[u8; 32]>,
    proof_token_hash: Option<[u8; 32]>,
    deadline: Instant,
    signed_wall_expiry: Option<Duration>,
    state: EntryState,
}

enum EntryState {
    Reserved,
    Pending { binding: StoredBinding },
    Finishing { binding: StoredBinding },
    ProofIssued { binding: StoredBinding },
    Burned,
}

impl EntryState {
    const fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Reserved
                | Self::Pending { .. }
                | Self::Finishing { .. }
                | Self::ProofIssued { .. }
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryStateKind {
    Reserved,
    Pending,
    Finishing,
    ProofIssued,
    Burned,
}

impl EntryStateKind {
    const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Reserved, Self::Pending)
                | (Self::Pending, Self::Finishing | Self::Burned)
                | (Self::Finishing, Self::ProofIssued | Self::Burned)
                | (Self::ProofIssued, Self::Burned)
        )
    }
}

impl EntryState {
    const fn kind(&self) -> EntryStateKind {
        match self {
            Self::Reserved => EntryStateKind::Reserved,
            Self::Pending { .. } => EntryStateKind::Pending,
            Self::Finishing { .. } => EntryStateKind::Finishing,
            Self::ProofIssued { .. } => EntryStateKind::ProofIssued,
            Self::Burned => EntryStateKind::Burned,
        }
    }
}

#[derive(Clone, Copy)]
enum LookupKind {
    AnyReservation,
    Reserved,
    AnyChallenge,
    PendingChallenge,
    AnyProofToken,
    ProofToken,
}

impl StoreEntry {
    fn is_live_expired(&self, now: ClockReading) -> bool {
        match self.state {
            EntryState::Reserved => now.monotonic >= self.deadline,
            EntryState::Pending { .. }
            | EntryState::Finishing { .. }
            | EntryState::ProofIssued { .. } => {
                now.monotonic >= self.deadline
                    || self
                        .signed_wall_expiry
                        .is_none_or(|expiry| now.wall >= expiry)
            }
            EntryState::Burned => false,
        }
    }

    fn expire_live_at(&mut self, now: ClockReading) -> Result<(), FoundationError> {
        if !self.is_live_expired(now) {
            return Ok(());
        }
        match self.state {
            EntryState::Reserved => Err(FoundationError::Expired),
            EntryState::Pending { .. }
            | EntryState::Finishing { .. }
            | EntryState::ProofIssued { .. } => {
                self.transition(EntryState::Burned)?;
                self.deadline = now.monotonic;
                Err(FoundationError::Expired)
            }
            EntryState::Burned => Err(FoundationError::Rejected),
        }
    }

    fn transition(&mut self, next: EntryState) -> Result<(), FoundationError> {
        if !self.state.kind().can_transition_to(next.kind()) {
            return Err(FoundationError::InvalidTransition);
        }
        self.state = next;
        Ok(())
    }

    fn hash_for(&self, kind: LookupKind) -> (&[u8; 32], Choice) {
        static ZERO: [u8; 32] = [0; 32];
        match kind {
            LookupKind::AnyReservation => (&self.reservation_hash, Choice::from(1)),
            LookupKind::Reserved if matches!(self.state, EntryState::Reserved) => {
                (&self.reservation_hash, Choice::from(1))
            }
            LookupKind::AnyChallenge => self
                .challenge_hash
                .as_ref()
                .map_or((&ZERO, Choice::from(0)), |hash| (hash, Choice::from(1))),
            LookupKind::PendingChallenge => match (&self.state, &self.challenge_hash) {
                (EntryState::Pending { .. }, Some(hash)) => (hash, Choice::from(1)),
                _ => (&ZERO, Choice::from(0)),
            },
            LookupKind::AnyProofToken => self
                .proof_token_hash
                .as_ref()
                .map_or((&ZERO, Choice::from(0)), |hash| (hash, Choice::from(1))),
            LookupKind::ProofToken => match (&self.state, &self.proof_token_hash) {
                (EntryState::ProofIssued { .. }, Some(hash)) => (hash, Choice::from(1)),
                _ => (&ZERO, Choice::from(0)),
            },
            LookupKind::Reserved => (&ZERO, Choice::from(0)),
        }
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
struct StoreStatus {
    total: usize,
    reserved: usize,
    pending: usize,
    finishing: usize,
    proof_issued: usize,
    burned: usize,
}

impl fmt::Debug for StoreStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreStatus")
            .field("total", &self.total)
            .field("reserved", &self.reserved)
            .field("pending", &self.pending)
            .field("finishing", &self.finishing)
            .field("proof_issued", &self.proof_issued)
            .field("burned", &self.burned)
            .finish()
    }
}

struct CtLookup {
    index: Option<usize>,
    duplicate: bool,
    comparisons: usize,
}

impl CtLookup {
    fn unique_index(self) -> Result<usize, FoundationError> {
        match (self.index, self.duplicate) {
            (Some(index), false) => Ok(index),
            _ => Err(FoundationError::Rejected),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum FoundationError {
    #[error("owner-present config is invalid: {0}")]
    InvalidConfig(&'static str),
    #[error("owner-present selector is unknown")]
    UnknownSelector,
    #[error("owner-present trusted binding is invalid")]
    InvalidBinding,
    #[error("owner-present store limits are invalid")]
    InvalidLimits,
    #[error("owner-present deadline is invalid")]
    InvalidDeadline,
    #[error("owner-present clock is invalid")]
    InvalidClock,
    #[error("owner-present clock regressed")]
    ClockRegressed,
    #[error("owner-present store is full")]
    StoreFull,
    #[error("owner-present member quota is full")]
    MemberFull,
    #[error("owner-present capacity counter is exhausted")]
    CapacityExhausted,
    #[error("owner-present operation was rejected")]
    Rejected,
    #[error("owner-present entry expired")]
    Expired,
    #[error("owner-present entropy collision")]
    EntropyCollision,
    #[error("owner-present store lock is poisoned")]
    Poisoned,
    #[error("owner-present state transition is invalid")]
    InvalidTransition,
}

#[derive(Clone, Copy)]
enum ConfigIdKind {
    Device,
    Claw,
}

fn validate_config_id(value: &str, kind: ConfigIdKind) -> Result<(), FoundationError> {
    if value.is_empty()
        || value.len() > MAX_CONFIG_ID_LEN
        || !value.bytes().enumerate().all(|(index, byte)| {
            let leading = index == 0;
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (!leading && matches!(byte, b'-' | b'_' | b'.' | b':'))
        })
    {
        return Err(FoundationError::InvalidConfig(match kind {
            ConfigIdKind::Device => "device_id",
            ConfigIdKind::Claw => "claw_id",
        }));
    }
    validate_phase0_id(value).map_err(|_| match kind {
        ConfigIdKind::Device => FoundationError::InvalidConfig("device_id"),
        ConfigIdKind::Claw => FoundationError::InvalidConfig("claw_id"),
    })
}

fn validate_phase0_id(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.trim() != value {
        return Err(());
    }
    Ok(())
}

fn config_digest(input: &TrustedConfigInput<'_>) -> Result<[u8; 32], FoundationError> {
    let mut hasher = Sha256::new();
    hasher.update(CONFIG_DIGEST_DOMAIN);
    hasher.update(CANONICAL_CONFIG_VERSION.to_be_bytes());
    hasher.update(input.generation.to_be_bytes());
    update_len_prefixed(&mut hasher, input.bundle_id.as_bytes())?;
    update_len_prefixed(&mut hasher, b"Device-D")?;
    update_len_prefixed(&mut hasher, input.device_id.as_bytes())?;
    update_len_prefixed(&mut hasher, b"Claw-M")?;
    update_len_prefixed(&mut hasher, input.claw_m_id.as_bytes())?;
    update_len_prefixed(&mut hasher, b"Claw-L")?;
    update_len_prefixed(&mut hasher, input.claw_l_id.as_bytes())?;
    Ok(hasher.finalize().into())
}

fn update_len_prefixed(hasher: &mut Sha256, value: &[u8]) -> Result<(), FoundationError> {
    let len = u32::try_from(value.len()).map_err(|_| FoundationError::InvalidBinding)?;
    hasher.update(len.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn domain_hash(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::atomic::{AtomicUsize, Ordering},
        thread,
    };

    use household_rs::{
        ids::HouseholdId,
        owner_approval_v2::{
            MobileClawVpnDevE2eApprovalContextInput, MobileClawVpnDevE2eExecutionTupleInput,
        },
    };

    use super::*;

    struct PanicRng;

    impl RngCore for PanicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("synthetic rng panic");
        }

        fn next_u64(&mut self) -> u64 {
            panic!("synthetic rng panic");
        }

        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            panic!("synthetic rng panic");
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for PanicRng {}

    #[derive(Clone)]
    struct ManualClock {
        state: Arc<Mutex<ManualClockState>>,
    }

    struct ManualClockState {
        reading: ClockReading,
        fail_reads: bool,
    }

    impl ManualClock {
        fn new(unix_seconds: u64) -> Self {
            Self {
                state: Arc::new(Mutex::new(ManualClockState {
                    reading: ClockReading {
                        monotonic: Instant::now(),
                        wall: Duration::from_secs(unix_seconds),
                    },
                    fail_reads: false,
                })),
            }
        }

        fn advance(&self, duration: Duration) {
            let mut state = self.state.lock().unwrap();
            state.reading.monotonic = state.reading.monotonic.checked_add(duration).unwrap();
            state.reading.wall = state.reading.wall.checked_add(duration).unwrap();
        }

        fn advance_monotonic(&self, duration: Duration) {
            let mut state = self.state.lock().unwrap();
            state.reading.monotonic = state.reading.monotonic.checked_add(duration).unwrap();
        }

        fn advance_wall(&self, duration: Duration) {
            let mut state = self.state.lock().unwrap();
            state.reading.wall = state.reading.wall.checked_add(duration).unwrap();
        }

        fn regress(&self, duration: Duration) {
            let mut state = self.state.lock().unwrap();
            state.reading.monotonic = state.reading.monotonic.checked_sub(duration).unwrap();
            state.reading.wall = state.reading.wall.checked_sub(duration).unwrap();
        }

        fn set_fail_reads(&self, fail_reads: bool) {
            self.state.lock().unwrap().fail_reads = fail_reads;
        }
    }

    impl FoundationClock for ManualClock {
        fn read(&self) -> Result<ClockReading, FoundationError> {
            let state = self
                .state
                .lock()
                .map_err(|_| FoundationError::InvalidClock)?;
            if state.fail_reads {
                return Err(FoundationError::InvalidClock);
            }
            Ok(state.reading)
        }
    }

    #[derive(Clone, Copy)]
    struct RngStep {
        byte: u8,
        wall_advance: Duration,
        monotonic_advance: Duration,
    }

    struct ClockAdvancingRng {
        clock: ManualClock,
        steps: Vec<RngStep>,
        next_step: usize,
        calls: Arc<AtomicUsize>,
    }

    impl ClockAdvancingRng {
        fn new(clock: ManualClock, steps: Vec<RngStep>, calls: Arc<AtomicUsize>) -> Self {
            Self {
                clock,
                steps,
                next_step: 0,
                calls,
            }
        }

        fn fill_from_next_step(&mut self, dest: &mut [u8]) {
            let step = self.steps[self.next_step];
            self.next_step += 1;
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !step.wall_advance.is_zero() {
                self.clock.advance_wall(step.wall_advance);
            }
            if !step.monotonic_advance.is_zero() {
                self.clock.advance_monotonic(step.monotonic_advance);
            }
            dest.fill(step.byte);
        }
    }

    impl RngCore for ClockAdvancingRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_from_next_step(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_from_next_step(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.fill_from_next_step(dest);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ClockAdvancingRng {}

    fn config() -> TrustedConfig {
        TrustedConfig::try_new(TrustedConfigInput {
            generation: 7,
            bundle_id: MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID,
            device_id: "device-alpha",
            claw_m_id: "claw-m-alpha",
            claw_l_id: "claw-l-alpha",
        })
        .unwrap()
    }

    fn limits(max_entries: usize, max_per_member: usize) -> StoreLimits {
        StoreLimits::try_new(
            max_entries,
            max_per_member,
            Duration::from_secs(120),
            Duration::from_secs(30),
        )
        .unwrap()
    }

    fn test_store(limits: StoreLimits) -> CapabilityStore {
        store_with_clock(limits).0
    }

    fn store_with_clock(limits: StoreLimits) -> (CapabilityStore, ManualClock) {
        let clock = ManualClock::new(1_000);
        (
            CapabilityStore::with_clock(limits, Arc::new(clock.clone())),
            clock,
        )
    }

    fn household_id() -> HouseholdId {
        HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap()
    }

    #[derive(Clone)]
    struct BindingFixture {
        member_id: String,
        selector: ClawSelector,
        tuple_marker: u8,
        replay_marker: u8,
        config_generation: u64,
        authority_head_sequence: u64,
        authority_head_marker: u8,
        credential_marker: u8,
        issued_at: u64,
        expires_at: u64,
    }

    impl BindingFixture {
        fn new(member_id: &str, selector: ClawSelector, marker: u8) -> Self {
            Self::with_times(member_id, selector, marker, 1_000, 1_060)
        }

        fn with_times(
            member_id: &str,
            selector: ClawSelector,
            marker: u8,
            issued_at: u64,
            expires_at: u64,
        ) -> Self {
            Self {
                member_id: member_id.to_string(),
                selector,
                tuple_marker: marker,
                replay_marker: 0xaa,
                config_generation: 7,
                authority_head_sequence: 9,
                authority_head_marker: 0x88,
                credential_marker: 0x99,
                issued_at,
                expires_at,
            }
        }

        fn trusted_parts(
            &self,
        ) -> (
            ConfigSelection,
            MobileClawVpnDevE2eExecutionTupleV1,
            OwnerApprovalContextV2,
            OwnerAuthoritySnapshot,
        ) {
            let config = TrustedConfig::try_new(TrustedConfigInput {
                generation: self.config_generation,
                bundle_id: MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID,
                device_id: "device-alpha",
                claw_m_id: "claw-m-alpha",
                claw_l_id: "claw-l-alpha",
            })
            .unwrap();
            let selection = config.resolve(self.selector);
            let tuple =
                MobileClawVpnDevE2eExecutionTupleV1::new(MobileClawVpnDevE2eExecutionTupleInput {
                    hh_id: household_id(),
                    engine_audience: [self.tuple_marker; 32],
                    member_id: self.member_id.clone(),
                    attempt_id: "11111111-1111-4111-8111-111111111111".to_string(),
                    readiness_run_id: "22222222-2222-4222-8222-222222222222".to_string(),
                    source_artifact_git_sha1: [0x33; 20],
                    execution_manifest_sha256: [0x44; 32],
                    device_binding: [0x55; 32],
                    execution_run_id: "33333333-3333-4333-8333-333333333333".to_string(),
                    execution_claim_sha256: [0x66; 32],
                    device_id: selection.device_id.clone(),
                    claw_id: selection.claw_id.clone(),
                    device_alias: "Device-D".to_string(),
                    claw_alias: self.selector.as_str().to_string(),
                    issued_at: self.issued_at,
                    expires_at: self.expires_at,
                    server_nonce: [0x77; 32],
                });
            let authority = OwnerAuthoritySnapshot {
                owner_p_id: PersonId("p_owner-alpha".to_string()),
                head_sequence: self.authority_head_sequence,
                head_hash: [self.authority_head_marker; 32],
                credential_set_digest: [self.credential_marker; 32],
            };
            let context = OwnerApprovalContextV2::mobile_claw_vpn_dev_e2e_execute(
                MobileClawVpnDevE2eApprovalContextInput {
                    owner_p_id: authority.owner_p_id.clone(),
                    execution: &tuple,
                    replay_nonce: [self.replay_marker; 32],
                },
            )
            .unwrap();
            (selection, tuple, context, authority)
        }

        fn start(&self) -> StartServerBinding {
            let (selection, tuple, context, authority) = self.trusted_parts();
            StartServerBinding::from_trusted_state(
                &self.member_id,
                &selection,
                &tuple,
                &context,
                &authority,
            )
            .unwrap()
        }

        fn fresh<'permit>(
            &self,
            permit: PointOfUsePermit<'permit>,
        ) -> Result<FreshServerBinding<'permit>, FoundationError> {
            let (selection, tuple, context, authority) = self.trusted_parts();
            FreshServerBinding::from_trusted_state(
                permit,
                &self.member_id,
                &selection,
                &tuple,
                &context,
                &authority,
            )
        }

        fn stored(&self) -> StoredBinding {
            self.start().stored
        }

        fn caller(&self) -> CallerScope {
            CallerScope::from_server_derived_member(&self.member_id).unwrap()
        }
    }

    fn pending(
        store: &CapabilityStore,
        fixture: &BindingFixture,
        challenge_byte: u8,
    ) -> (ReservationHandle, ChallengeHandle) {
        let caller = fixture.caller();
        let reservation = store.reserve(&caller, Duration::from_secs(60)).unwrap();
        let challenge = ChallengeHandle::from_server_random([challenge_byte; 32]).unwrap();
        store
            .commit_pending(&reservation, &challenge, fixture.start())
            .unwrap();
        (reservation, challenge)
    }

    fn issued(store: &CapabilityStore, fixture: &BindingFixture, challenge_byte: u8) -> ProofToken {
        let (_, challenge) = pending(store, fixture, challenge_byte);
        store
            .claim_finishing(&challenge, &fixture.caller())
            .unwrap()
            .issue_proof(Duration::from_secs(20), |permit| fixture.fresh(permit))
            .unwrap()
    }

    #[test]
    fn selector_and_config_are_closed_canonical_and_redacted() {
        assert_eq!(
            ClawSelector::try_from("Claw-M").unwrap(),
            ClawSelector::ClawM
        );
        assert_eq!(
            ClawSelector::try_from("Claw-L").unwrap(),
            ClawSelector::ClawL
        );
        for rejected in ["claw-m", "Claw-A", "", "Claw-M "] {
            assert_eq!(
                ClawSelector::try_from(rejected),
                Err(FoundationError::UnknownSelector)
            );
        }

        let baseline = config();
        let same = config();
        assert_eq!(baseline.inner.digest, same.inner.digest);
        let changed = TrustedConfig::try_new(TrustedConfigInput {
            generation: 8,
            bundle_id: MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID,
            device_id: "device-alpha",
            claw_m_id: "claw-m-alpha",
            claw_l_id: "claw-l-alpha",
        })
        .unwrap();
        assert_ne!(baseline.inner.digest, changed.inner.digest);
        for (device_id, claw_m_id, claw_l_id) in [
            ("device-beta", "claw-m-alpha", "claw-l-alpha"),
            ("device-alpha", "claw-m-beta", "claw-l-alpha"),
            ("device-alpha", "claw-m-alpha", "claw-l-beta"),
        ] {
            let mutated = TrustedConfig::try_new(TrustedConfigInput {
                generation: 7,
                bundle_id: MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID,
                device_id,
                claw_m_id,
                claw_l_id,
            })
            .unwrap();
            assert_ne!(baseline.inner.digest, mutated.inner.digest);
        }
        let debug = format!("{baseline:?}");
        assert!(!debug.contains("device-alpha"));
        assert!(!debug.contains("claw-m-alpha"));
        assert!(!debug.contains(&hex::encode(baseline.inner.digest)));
    }

    #[test]
    fn config_rejects_invalid_bundle_ids_duplicates_and_collisions() {
        let cases = [
            TrustedConfigInput {
                generation: 0,
                bundle_id: MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID,
                device_id: "device-alpha",
                claw_m_id: "claw-m-alpha",
                claw_l_id: "claw-l-alpha",
            },
            TrustedConfigInput {
                generation: 1,
                bundle_id: "com.example.app",
                device_id: "device-alpha",
                claw_m_id: "claw-m-alpha",
                claw_l_id: "claw-l-alpha",
            },
            TrustedConfigInput {
                generation: 1,
                bundle_id: MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID,
                device_id: "Device-Alpha",
                claw_m_id: "claw-m-alpha",
                claw_l_id: "claw-l-alpha",
            },
            TrustedConfigInput {
                generation: 1,
                bundle_id: MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID,
                device_id: "device-alpha",
                claw_m_id: "claw-alpha",
                claw_l_id: "claw-alpha",
            },
            TrustedConfigInput {
                generation: 1,
                bundle_id: MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID,
                device_id: "claw-m-alpha",
                claw_m_id: "claw-m-alpha",
                claw_l_id: "claw-l-alpha",
            },
        ];
        for case in cases {
            assert!(TrustedConfig::try_new(case).is_err());
        }
    }

    #[test]
    fn store_limits_have_a_hard_global_bound() {
        assert!(matches!(
            StoreLimits::try_new(
                ABSOLUTE_MAX_STORE_ENTRIES + 1,
                1,
                Duration::from_secs(60),
                Duration::from_secs(30),
            ),
            Err(FoundationError::InvalidLimits)
        ));
    }

    #[test]
    fn trusted_binding_rejects_member_selector_context_and_authority_drift() {
        let config = config();
        let selection = config.resolve(ClawSelector::ClawM);
        let tuple =
            MobileClawVpnDevE2eExecutionTupleV1::new(MobileClawVpnDevE2eExecutionTupleInput {
                hh_id: household_id(),
                engine_audience: [0x11; 32],
                member_id: "member-alpha".to_string(),
                attempt_id: "11111111-1111-4111-8111-111111111111".to_string(),
                readiness_run_id: "22222222-2222-4222-8222-222222222222".to_string(),
                source_artifact_git_sha1: [0x22; 20],
                execution_manifest_sha256: [0x33; 32],
                device_binding: [0x44; 32],
                execution_run_id: "33333333-3333-4333-8333-333333333333".to_string(),
                execution_claim_sha256: [0x55; 32],
                device_id: selection.device_id.clone(),
                claw_id: selection.claw_id.clone(),
                device_alias: "Device-D".to_string(),
                claw_alias: "Claw-M".to_string(),
                issued_at: 1_000,
                expires_at: 1_060,
                server_nonce: [0x66; 32],
            });
        let authority = OwnerAuthoritySnapshot {
            owner_p_id: PersonId("p_owner-alpha".to_string()),
            head_sequence: 1,
            head_hash: [0x77; 32],
            credential_set_digest: [0x88; 32],
        };
        let context = OwnerApprovalContextV2::mobile_claw_vpn_dev_e2e_execute(
            MobileClawVpnDevE2eApprovalContextInput {
                owner_p_id: authority.owner_p_id.clone(),
                execution: &tuple,
                replay_nonce: [0x99; 32],
            },
        )
        .unwrap();

        let authority_digest = authority.digest().unwrap();
        for mutated in [
            OwnerAuthoritySnapshot {
                head_sequence: 2,
                ..authority.clone()
            },
            OwnerAuthoritySnapshot {
                head_hash: [0x78; 32],
                ..authority.clone()
            },
            OwnerAuthoritySnapshot {
                credential_set_digest: [0x89; 32],
                ..authority.clone()
            },
        ] {
            assert_ne!(mutated.digest().unwrap(), authority_digest);
        }

        assert!(
            StoredBinding::from_trusted_state(
                "member-beta",
                &selection,
                &tuple,
                &context,
                &authority,
            )
            .is_err()
        );
        let wrong_selection = config.resolve(ClawSelector::ClawL);
        assert!(
            StoredBinding::from_trusted_state(
                "member-alpha",
                &wrong_selection,
                &tuple,
                &context,
                &authority,
            )
            .is_err()
        );
        let wrong_authority = OwnerAuthoritySnapshot {
            owner_p_id: PersonId("p_owner-beta".to_string()),
            ..authority.clone()
        };
        assert!(
            StoredBinding::from_trusted_state(
                "member-alpha",
                &selection,
                &tuple,
                &context,
                &wrong_authority,
            )
            .is_err()
        );
    }

    #[test]
    fn transition_table_is_one_way_and_reserved_release_is_narrow() {
        let kinds = [
            EntryStateKind::Reserved,
            EntryStateKind::Pending,
            EntryStateKind::Finishing,
            EntryStateKind::ProofIssued,
            EntryStateKind::Burned,
        ];
        let allowed = [
            (EntryStateKind::Reserved, EntryStateKind::Pending),
            (EntryStateKind::Pending, EntryStateKind::Finishing),
            (EntryStateKind::Pending, EntryStateKind::Burned),
            (EntryStateKind::Finishing, EntryStateKind::ProofIssued),
            (EntryStateKind::Finishing, EntryStateKind::Burned),
            (EntryStateKind::ProofIssued, EntryStateKind::Burned),
        ];
        for from in kinds {
            for to in kinds {
                assert_eq!(
                    from.can_transition_to(to),
                    allowed.contains(&(from, to)),
                    "unexpected transition {from:?} -> {to:?}"
                );
            }
        }

        let store = test_store(limits(8, 4));
        let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x10);
        let reservation = store
            .reserve(&binding.caller(), Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            store.lock_operation().unwrap().entries[0].signed_wall_expiry,
            None
        );
        assert_eq!(store.status().unwrap().reserved, 1);
        store.release_reserved(&reservation).unwrap();
        assert_eq!(store.status().unwrap().total, 0);

        let (reservation, challenge) = pending(&store, &binding, 0x11);
        assert_eq!(
            store.lock_operation().unwrap().entries[0].signed_wall_expiry,
            Some(Duration::from_secs(1_060))
        );
        assert_eq!(store.status().unwrap().pending, 1);
        assert_eq!(
            store.release_reserved(&reservation),
            Err(FoundationError::Rejected)
        );
        let claim = store
            .claim_finishing(&challenge, &binding.caller())
            .unwrap();
        assert_eq!(store.status().unwrap().finishing, 1);
        drop(claim);
        assert_eq!(
            store.status().unwrap(),
            StoreStatus {
                total: 1,
                burned: 1,
                ..StoreStatus::default()
            }
        );
        assert!(matches!(
            store.claim_finishing(&challenge, &binding.caller()),
            Err(FoundationError::Rejected)
        ));
    }

    #[test]
    fn finishing_drop_explicit_error_and_unwind_burn_synchronously() {
        for mode in ["drop", "explicit", "panic"] {
            let store = test_store(limits(4, 2));
            let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x20);
            let (_, challenge) = pending(&store, &binding, 0x21);
            match mode {
                "drop" => drop(
                    store
                        .claim_finishing(&challenge, &binding.caller())
                        .unwrap(),
                ),
                "explicit" => store
                    .claim_finishing(&challenge, &binding.caller())
                    .unwrap()
                    .burn(),
                "panic" => {
                    let unwind = catch_unwind(AssertUnwindSafe(|| {
                        let _claim = store
                            .claim_finishing(&challenge, &binding.caller())
                            .unwrap();
                        panic!("synthetic unwind");
                    }));
                    assert!(unwind.is_err());
                }
                _ => unreachable!(),
            }
            let status = store.status().unwrap();
            assert_eq!(status.finishing, 0);
            assert_eq!(status.burned, 1);
        }
    }

    #[test]
    fn point_of_use_rederivation_error_and_panic_burn_outside_store_lock() {
        for mode in ["error", "panic"] {
            let store = test_store(limits(4, 2));
            let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x21);
            let (_, challenge) = pending(&store, &binding, 0x22);
            let claim = store
                .claim_finishing(&challenge, &binding.caller())
                .unwrap();
            match mode {
                "error" => assert!(matches!(
                    claim.issue_proof(Duration::from_secs(20), |_permit| {
                        Err(FoundationError::InvalidBinding)
                    }),
                    Err(FoundationError::InvalidBinding)
                )),
                "panic" => {
                    let unwind = catch_unwind(AssertUnwindSafe(|| {
                        let _ = claim.issue_proof(Duration::from_secs(20), |_permit| {
                            panic!("synthetic trusted-state panic")
                        });
                    }));
                    assert!(unwind.is_err());
                }
                _ => unreachable!(),
            }
            assert!(
                store.inner.lock().is_ok(),
                "closure must run outside the mutex"
            );
            assert_eq!(store.status().unwrap().burned, 1);
        }
    }

    #[test]
    fn point_of_use_permit_is_bound_to_the_claimed_entry() {
        let store = test_store(limits(4, 2));
        let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x23);
        let (_, challenge) = pending(&store, &binding, 0x24);
        let claim = store
            .claim_finishing(&challenge, &binding.caller())
            .unwrap();
        assert!(matches!(
            claim.issue_proof(Duration::from_secs(20), |mut permit| {
                permit.entry_id = permit.entry_id.checked_add(1).unwrap();
                binding.fresh(permit)
            }),
            Err(FoundationError::Rejected)
        ));
        assert_eq!(store.status().unwrap().burned, 1);
    }

    #[test]
    fn panic_while_store_lock_is_held_still_burns_before_unwind_returns() {
        let store = test_store(limits(4, 2));
        let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x22);
        let (_, challenge) = pending(&store, &binding, 0x23);
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let claim = store
                .claim_finishing(&challenge, &binding.caller())
                .unwrap();
            let mut rng = PanicRng;
            let _ = claim.issue_proof_with_rng(
                Duration::from_secs(20),
                |permit| binding.fresh(permit),
                &mut rng,
            );
        }));
        assert!(unwind.is_err());
        let inner = match store.inner.lock() {
            Ok(_) => panic!("the synthetic panic must poison the mutex"),
            Err(poisoned) => poisoned.into_inner(),
        };
        assert_eq!(inner.status().finishing, 0);
        assert_eq!(inner.status().burned, 1);
    }

    #[test]
    fn clock_failure_after_finishing_claim_burns_synchronously() {
        let (store, clock) = store_with_clock(limits(4, 2));
        let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x24);
        let (_, challenge) = pending(&store, &binding, 0x25);
        let claim = store
            .claim_finishing(&challenge, &binding.caller())
            .unwrap();
        clock.set_fail_reads(true);
        assert!(matches!(
            claim.issue_proof(Duration::from_secs(20), |permit| binding.fresh(permit)),
            Err(FoundationError::InvalidClock)
        ));
        clock.set_fail_reads(false);
        let status = store.status().unwrap();
        assert_eq!(status.finishing, 0);
        assert_eq!(status.burned, 1);
    }

    #[test]
    fn clock_regression_after_finishing_claim_burns_synchronously() {
        let (store, clock) = store_with_clock(limits(4, 2));
        let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x26);
        let (_, challenge) = pending(&store, &binding, 0x27);
        let claim = store
            .claim_finishing(&challenge, &binding.caller())
            .unwrap();
        clock.regress(Duration::from_secs(1));
        assert!(matches!(
            claim.issue_proof(Duration::from_secs(20), |permit| binding.fresh(permit)),
            Err(FoundationError::ClockRegressed)
        ));
        clock.advance(Duration::from_secs(1));
        let status = store.status().unwrap();
        assert_eq!(status.finishing, 0);
        assert_eq!(status.burned, 1);
    }

    #[test]
    fn wrong_member_preserves_but_finish_freshness_mismatch_burns() {
        let store = test_store(limits(8, 4));
        let expected = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x30);
        let wrong_member = BindingFixture::new("member-beta", ClawSelector::ClawM, 0x30);
        let mut wrong_head = expected.clone();
        wrong_head.authority_head_sequence += 1;
        let (_, challenge) = pending(&store, &expected, 0x31);

        assert!(matches!(
            store.claim_finishing(&challenge, &wrong_member.caller()),
            Err(FoundationError::Rejected)
        ));
        assert_eq!(
            store.status().unwrap(),
            StoreStatus {
                total: 1,
                pending: 1,
                ..StoreStatus::default()
            }
        );

        let claim = store
            .claim_finishing(&challenge, &expected.caller())
            .unwrap();
        let closure_calls = Arc::new(AtomicUsize::new(0));
        let calls = closure_calls.clone();
        let status_store = store.clone();
        assert!(matches!(
            claim.issue_proof(Duration::from_secs(20), move |permit| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(status_store.status().unwrap().finishing, 1);
                wrong_head.fresh(permit)
            }),
            Err(FoundationError::Rejected)
        ));
        assert_eq!(closure_calls.load(Ordering::SeqCst), 1);
        let status = store.status().unwrap();
        assert_eq!(status.pending, 0);
        assert_eq!(status.proof_issued, 0);
        assert_eq!(store.status().unwrap().burned, 1);
    }

    #[test]
    fn wrong_member_preserves_proof_but_legitimate_consume_burns_before_freshness_checks() {
        for drift in ["config", "tuple", "context", "authority", "credential"] {
            let store = test_store(limits(8, 4));
            let expected = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x32);
            let wrong_member = BindingFixture::new("member-beta", ClawSelector::ClawM, 0x32);
            let mut current = expected.clone();
            match drift {
                "config" => current.config_generation += 1,
                "tuple" => current.tuple_marker ^= 1,
                "context" => current.replay_marker ^= 1,
                "authority" => current.authority_head_sequence += 1,
                "credential" => current.credential_marker ^= 1,
                _ => unreachable!(),
            }
            assert!(!expected.stored().matches(&current.stored()));
            let token = issued(&store, &expected, 0x33);
            let duplicate = ProofToken(*token.as_bytes());

            let wrong_calls = Arc::new(AtomicUsize::new(0));
            let observed_wrong_calls = wrong_calls.clone();
            assert!(matches!(
                store.consume_proof(duplicate, &wrong_member.caller(), move |_permit| {
                    wrong_calls.fetch_add(1, Ordering::SeqCst);
                    panic!("wrong-member must not receive a point-of-use permit")
                }),
                Err(FoundationError::Rejected)
            ));
            assert_eq!(observed_wrong_calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                store.status().unwrap(),
                StoreStatus {
                    total: 1,
                    proof_issued: 1,
                    ..StoreStatus::default()
                }
            );

            let status_store = store.clone();
            assert!(matches!(
                store.consume_proof(token, &expected.caller(), move |permit| {
                    assert_eq!(status_store.status().unwrap().burned, 1);
                    current.fresh(permit)
                }),
                Err(FoundationError::Rejected)
            ));
            let status = store.status().unwrap();
            assert_eq!(status.proof_issued, 0);
            assert_eq!(status.burned, 1);
        }
    }

    #[test]
    fn proof_is_hash_only_single_use_and_response_loss_cannot_reissue() {
        let store = test_store(limits(8, 4));
        let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x40);
        let (_, challenge) = pending(&store, &binding, 0x41);
        let token = store
            .claim_finishing(&challenge, &binding.caller())
            .unwrap()
            .issue_proof(Duration::from_secs(20), |permit| binding.fresh(permit))
            .unwrap();
        let raw = *token.as_bytes();
        let expected_hash = domain_hash(PROOF_TOKEN_HASH_DOMAIN, &raw);
        {
            let inner = store.lock_operation().unwrap();
            let EntryState::ProofIssued { .. } = &inner.entries[0].state else {
                panic!("expected proof state");
            };
            assert_eq!(inner.entries[0].proof_token_hash, Some(expected_hash));
            assert_ne!(inner.entries[0].proof_token_hash, Some(raw));
        }
        let debug = format!("{store:?} {token:?}");
        assert!(!debug.contains(&hex::encode(raw)));
        assert!(!debug.contains("member-alpha"));

        drop(token);
        assert!(matches!(
            store.claim_finishing(&challenge, &binding.caller()),
            Err(FoundationError::Rejected)
        ));
        assert_eq!(store.status().unwrap().proof_issued, 1);
    }

    #[test]
    fn same_token_concurrency_has_exactly_one_atomic_consumer() {
        let store = test_store(limits(8, 4));
        let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x50);
        let token = issued(&store, &binding, 0x51);
        let raw = *token.as_bytes();
        drop(token);

        let calls = Arc::new(AtomicUsize::new(0));
        let left_store = store.clone();
        let left_scope = binding.caller();
        let left_binding = binding.clone();
        let left_calls = calls.clone();
        let left = thread::spawn(move || {
            left_store.consume_proof(ProofToken(raw), &left_scope, move |permit| {
                left_calls.fetch_add(1, Ordering::SeqCst);
                left_binding.fresh(permit)
            })
        });
        let right_store = store.clone();
        let right_scope = binding.caller();
        let right_binding = binding.clone();
        let right_calls = calls.clone();
        let right = thread::spawn(move || {
            right_store.consume_proof(ProofToken(raw), &right_scope, move |permit| {
                right_calls.fetch_add(1, Ordering::SeqCst);
                right_binding.fresh(permit)
            })
        });
        let successes =
            usize::from(left.join().unwrap().is_ok()) + usize::from(right.join().unwrap().is_ok());
        assert_eq!(successes, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.status().unwrap().burned, 1);
    }

    #[test]
    fn duplicate_challenge_is_rejected_before_and_after_first_claim() {
        let store = test_store(limits(8, 4));
        let first = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x60);
        let second = BindingFixture::new("member-beta", ClawSelector::ClawL, 0x61);
        let (_, challenge) = pending(&store, &first, 0x62);
        let reservation = store
            .reserve(&second.caller(), Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            store.commit_pending(&reservation, &challenge, second.start()),
            Err(FoundationError::Rejected)
        );
        let status = store.status().unwrap();
        assert_eq!(status.pending, 1);
        assert_eq!(status.reserved, 1);
        store.release_reserved(&reservation).unwrap();

        drop(store.claim_finishing(&challenge, &first.caller()).unwrap());
        let replacement = BindingFixture::new("member-beta", ClawSelector::ClawL, 0x63);
        let reservation = store
            .reserve(&replacement.caller(), Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            store.commit_pending(&reservation, &challenge, replacement.start()),
            Err(FoundationError::Rejected)
        );
        assert_eq!(store.status().unwrap().burned, 1);
        assert_eq!(store.status().unwrap().reserved, 1);
    }

    #[test]
    fn quotas_deadlines_expiry_and_restart_are_fail_closed() {
        let (store, clock) = store_with_clock(limits(2, 1));
        let alpha = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x70);
        let beta = BindingFixture::new("member-beta", ClawSelector::ClawL, 0x71);
        let alpha_reservation = store
            .reserve(&alpha.caller(), Duration::from_secs(10))
            .unwrap();
        assert!(matches!(
            store.reserve(&alpha.caller(), Duration::from_secs(10)),
            Err(FoundationError::MemberFull)
        ));
        let beta_reservation = store
            .reserve(&beta.caller(), Duration::from_secs(10))
            .unwrap();
        assert!(matches!(
            store.reserve(
                &CallerScope::from_server_derived_member("member-gamma").unwrap(),
                Duration::from_secs(10),
            ),
            Err(FoundationError::StoreFull)
        ));
        assert_eq!(store.status().unwrap().total, 2);
        assert!(matches!(
            store.reserve(&alpha.caller(), Duration::MAX),
            Err(FoundationError::InvalidDeadline)
        ));

        clock.advance(Duration::from_secs(10));
        store.prune_expired().unwrap();
        assert_eq!(store.status().unwrap().total, 0);

        let restarted = test_store(limits(2, 1));
        assert_eq!(
            restarted.release_reserved(&alpha_reservation),
            Err(FoundationError::Rejected)
        );
        assert_eq!(
            restarted.release_reserved(&beta_reservation),
            Err(FoundationError::Rejected)
        );
    }

    #[test]
    fn finishing_expiry_burns_before_cleanup_can_remove_it() {
        let (store, clock) = store_with_clock(limits(4, 2));
        let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x80);
        let reservation = store
            .reserve(&binding.caller(), Duration::from_secs(1))
            .unwrap();
        let challenge = ChallengeHandle::from_server_random([0x81; 32]).unwrap();
        store
            .commit_pending(&reservation, &challenge, binding.start())
            .unwrap();
        let claim = store
            .claim_finishing(&challenge, &binding.caller())
            .unwrap();
        clock.advance(Duration::from_secs(1));
        store.prune_expired().unwrap();
        assert_eq!(store.status().unwrap().burned, 1);
        drop(claim);
        assert_eq!(store.status().unwrap().burned, 1);
        clock.advance(Duration::from_secs(1));
        store.prune_expired().unwrap();
        assert_eq!(store.status().unwrap().total, 0);
    }

    #[test]
    fn signed_expiry_clamps_reservation_and_rejects_exact_expiry() {
        let (store, clock) = store_with_clock(limits(4, 2));
        let binding =
            BindingFixture::with_times("member-alpha", ClawSelector::ClawM, 0x82, 1_000, 1_001);
        let (_, challenge) = pending(&store, &binding, 0x83);
        clock.advance(Duration::from_secs(1));
        assert!(matches!(
            store.claim_finishing(&challenge, &binding.caller()),
            Err(FoundationError::Rejected)
        ));
        let status = store.status().unwrap();
        assert_eq!(status.pending, 0);
        assert_eq!(status.burned, 1);

        let exact_store = test_store(limits(4, 2));
        let exact =
            BindingFixture::with_times("member-alpha", ClawSelector::ClawM, 0x84, 999, 1_000);
        let reservation = exact_store
            .reserve(&exact.caller(), Duration::from_secs(60))
            .unwrap();
        let challenge = ChallengeHandle::from_server_random([0x85; 32]).unwrap();
        assert!(matches!(
            exact_store.commit_pending(&reservation, &challenge, exact.start()),
            Err(FoundationError::Expired)
        ));
        assert_eq!(exact_store.status().unwrap().reserved, 1);
    }

    #[test]
    fn wall_only_expiry_burns_every_live_phase_without_rederivation() {
        let (pending_store, pending_clock) = store_with_clock(limits(4, 2));
        let pending_binding =
            BindingFixture::with_times("member-alpha", ClawSelector::ClawM, 0x90, 1_000, 1_001);
        let (_, pending_challenge) = pending(&pending_store, &pending_binding, 0x91);
        pending_clock.advance_wall(Duration::from_secs(1));
        assert!(matches!(
            pending_store.claim_finishing(&pending_challenge, &pending_binding.caller()),
            Err(FoundationError::Rejected | FoundationError::Expired)
        ));
        assert_eq!(pending_store.status().unwrap().burned, 1);

        let (finishing_store, finishing_clock) = store_with_clock(limits(4, 2));
        let finishing_binding =
            BindingFixture::with_times("member-alpha", ClawSelector::ClawM, 0x92, 1_000, 1_001);
        let (_, finishing_challenge) = pending(&finishing_store, &finishing_binding, 0x93);
        let claim = finishing_store
            .claim_finishing(&finishing_challenge, &finishing_binding.caller())
            .unwrap();
        finishing_clock.advance_wall(Duration::from_secs(1));
        let finishing_calls = Arc::new(AtomicUsize::new(0));
        let observed_finishing_calls = finishing_calls.clone();
        assert!(matches!(
            claim.issue_proof(Duration::from_secs(20), move |_permit| {
                finishing_calls.fetch_add(1, Ordering::SeqCst);
                panic!("expired Finishing must not rederive trusted state")
            }),
            Err(FoundationError::Expired)
        ));
        assert_eq!(observed_finishing_calls.load(Ordering::SeqCst), 0);
        assert_eq!(finishing_store.status().unwrap().burned, 1);

        let (proof_store, proof_clock) = store_with_clock(limits(4, 2));
        let proof_binding =
            BindingFixture::with_times("member-alpha", ClawSelector::ClawM, 0x94, 1_000, 1_001);
        let token = issued(&proof_store, &proof_binding, 0x95);
        proof_clock.advance_wall(Duration::from_secs(2));
        let proof_calls = Arc::new(AtomicUsize::new(0));
        let observed_proof_calls = proof_calls.clone();
        assert!(matches!(
            proof_store.consume_proof(token, &proof_binding.caller(), move |_permit| {
                proof_calls.fetch_add(1, Ordering::SeqCst);
                panic!("expired ProofIssued must not rederive trusted state")
            }),
            Err(FoundationError::Rejected | FoundationError::Expired)
        ));
        assert_eq!(observed_proof_calls.load(Ordering::SeqCst), 0);
        assert_eq!(proof_store.status().unwrap().burned, 1);
    }

    #[test]
    fn monotonic_only_deadline_burns_pending_and_proof_with_wall_frozen() {
        let (pending_store, pending_clock) = store_with_clock(limits(4, 2));
        let pending_binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x96);
        let reservation = pending_store
            .reserve(&pending_binding.caller(), Duration::from_secs(1))
            .unwrap();
        let challenge = ChallengeHandle::from_server_random([0x97; 32]).unwrap();
        pending_store
            .commit_pending(&reservation, &challenge, pending_binding.start())
            .unwrap();
        pending_clock.advance_monotonic(Duration::from_secs(1));
        assert!(matches!(
            pending_store.claim_finishing(&challenge, &pending_binding.caller()),
            Err(FoundationError::Rejected | FoundationError::Expired)
        ));
        assert_eq!(pending_store.status().unwrap().burned, 1);

        let (proof_store, proof_clock) = store_with_clock(limits(4, 2));
        let proof_binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x98);
        let token = issued(&proof_store, &proof_binding, 0x99);
        proof_clock.advance_monotonic(Duration::from_secs(20));
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = calls.clone();
        assert!(matches!(
            proof_store.consume_proof(token, &proof_binding.caller(), move |_permit| {
                calls.fetch_add(1, Ordering::SeqCst);
                panic!("expired ProofIssued must not rederive trusted state")
            }),
            Err(FoundationError::Rejected | FoundationError::Expired)
        ));
        assert_eq!(observed_calls.load(Ordering::SeqCst), 0);
        assert_eq!(proof_store.status().unwrap().burned, 1);
    }

    #[test]
    fn expiry_crossed_inside_rederivation_burns_before_proof_or_effect() {
        let (finish_store, finish_clock) = store_with_clock(limits(4, 2));
        let finish_binding =
            BindingFixture::with_times("member-alpha", ClawSelector::ClawM, 0x9a, 1_000, 1_001);
        let (_, challenge) = pending(&finish_store, &finish_binding, 0x9b);
        let claim = finish_store
            .claim_finishing(&challenge, &finish_binding.caller())
            .unwrap();
        let finish_calls = Arc::new(AtomicUsize::new(0));
        let observed_finish_calls = finish_calls.clone();
        assert!(matches!(
            claim.issue_proof(Duration::from_secs(20), move |permit| {
                finish_calls.fetch_add(1, Ordering::SeqCst);
                finish_clock.advance_wall(Duration::from_secs(1));
                finish_binding.fresh(permit)
            }),
            Err(FoundationError::Expired)
        ));
        assert_eq!(observed_finish_calls.load(Ordering::SeqCst), 1);
        assert_eq!(finish_store.status().unwrap().burned, 1);

        let (consume_store, consume_clock) = store_with_clock(limits(4, 2));
        let consume_binding =
            BindingFixture::with_times("member-alpha", ClawSelector::ClawM, 0x9c, 1_000, 1_001);
        let token = issued(&consume_store, &consume_binding, 0x9d);
        let consume_calls = Arc::new(AtomicUsize::new(0));
        let observed_consume_calls = consume_calls.clone();
        let consume_status_store = consume_store.clone();
        assert!(matches!(
            consume_store.consume_proof(token, &consume_binding.caller(), move |permit| {
                consume_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(consume_status_store.status().unwrap().burned, 1);
                consume_clock.advance_wall(Duration::from_secs(1));
                consume_binding.fresh(permit)
            }),
            Err(FoundationError::Expired)
        ));
        assert_eq!(observed_consume_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rng_wall_or_monotonic_advance_cannot_cross_proof_issue_deadline() {
        let (wall_store, wall_clock) = store_with_clock(limits(4, 2));
        let wall_binding =
            BindingFixture::with_times("member-alpha", ClawSelector::ClawM, 0xa0, 1_000, 1_001);
        let (_, wall_challenge) = pending(&wall_store, &wall_binding, 0xa1);
        let wall_claim = wall_store
            .claim_finishing(&wall_challenge, &wall_binding.caller())
            .unwrap();
        let wall_calls = Arc::new(AtomicUsize::new(0));
        let mut wall_rng = ClockAdvancingRng::new(
            wall_clock,
            vec![RngStep {
                byte: 0xa2,
                wall_advance: Duration::from_secs(1),
                monotonic_advance: Duration::ZERO,
            }],
            wall_calls.clone(),
        );
        assert!(matches!(
            wall_claim.issue_proof_with_rng(
                Duration::from_secs(20),
                |permit| wall_binding.fresh(permit),
                &mut wall_rng,
            ),
            Err(FoundationError::Expired)
        ));
        assert_eq!(wall_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wall_store.status().unwrap().proof_issued, 0);
        assert_eq!(wall_store.status().unwrap().burned, 1);

        let (monotonic_store, monotonic_clock) = store_with_clock(limits(4, 2));
        let monotonic_binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0xa3);
        let reservation = monotonic_store
            .reserve(&monotonic_binding.caller(), Duration::from_secs(1))
            .unwrap();
        let monotonic_challenge = ChallengeHandle::from_server_random([0xa4; 32]).unwrap();
        monotonic_store
            .commit_pending(
                &reservation,
                &monotonic_challenge,
                monotonic_binding.start(),
            )
            .unwrap();
        let monotonic_claim = monotonic_store
            .claim_finishing(&monotonic_challenge, &monotonic_binding.caller())
            .unwrap();
        let monotonic_calls = Arc::new(AtomicUsize::new(0));
        let mut monotonic_rng = ClockAdvancingRng::new(
            monotonic_clock,
            vec![RngStep {
                byte: 0xa5,
                wall_advance: Duration::ZERO,
                monotonic_advance: Duration::from_secs(1),
            }],
            monotonic_calls.clone(),
        );
        assert!(matches!(
            monotonic_claim.issue_proof_with_rng(
                Duration::from_secs(20),
                |permit| monotonic_binding.fresh(permit),
                &mut monotonic_rng,
            ),
            Err(FoundationError::Expired)
        ));
        assert_eq!(monotonic_calls.load(Ordering::SeqCst), 1);
        assert_eq!(monotonic_store.status().unwrap().proof_issued, 0);
        assert_eq!(monotonic_store.status().unwrap().burned, 1);

        let (live_store, live_clock) = store_with_clock(limits(4, 2));
        let live_binding =
            BindingFixture::with_times("member-alpha", ClawSelector::ClawM, 0xac, 1_000, 1_002);
        let (_, live_challenge) = pending(&live_store, &live_binding, 0xad);
        let live_claim = live_store
            .claim_finishing(&live_challenge, &live_binding.caller())
            .unwrap();
        let live_calls = Arc::new(AtomicUsize::new(0));
        let mut live_rng = ClockAdvancingRng::new(
            live_clock,
            vec![RngStep {
                byte: 0xae,
                wall_advance: Duration::from_millis(500),
                monotonic_advance: Duration::from_millis(500),
            }],
            live_calls.clone(),
        );
        let live_token = live_claim
            .issue_proof_with_rng(
                Duration::from_secs(20),
                |permit| live_binding.fresh(permit),
                &mut live_rng,
            )
            .unwrap();
        assert_eq!(live_calls.load(Ordering::SeqCst), 1);
        assert_eq!(live_store.status().unwrap().proof_issued, 1);
        assert_eq!(live_store.status().unwrap().burned, 0);
        drop(live_token);
    }

    #[test]
    fn collision_retry_rechecks_expiry_after_every_rng_fill() {
        let (store, clock) = store_with_clock(limits(8, 4));
        let existing = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0xa6);
        let existing_token = issued(&store, &existing, 0xa7);
        let collision_secret = [0xa8; OPAQUE_SECRET_LEN];
        let collision_hash = domain_hash(PROOF_TOKEN_HASH_DOMAIN, &collision_secret);
        {
            let mut inner = store.lock_operation().unwrap();
            let existing_entry = inner
                .entries
                .iter_mut()
                .find(|entry| matches!(entry.state, EntryState::ProofIssued { .. }))
                .unwrap();
            existing_entry.proof_token_hash = Some(collision_hash);
        }
        drop(existing_token);

        let expiring =
            BindingFixture::with_times("member-beta", ClawSelector::ClawL, 0xa9, 1_000, 1_001);
        let (_, challenge) = pending(&store, &expiring, 0xaa);
        let claim = store
            .claim_finishing(&challenge, &expiring.caller())
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut rng = ClockAdvancingRng::new(
            clock,
            vec![
                RngStep {
                    byte: 0xa8,
                    wall_advance: Duration::ZERO,
                    monotonic_advance: Duration::ZERO,
                },
                RngStep {
                    byte: 0xab,
                    wall_advance: Duration::from_secs(2),
                    monotonic_advance: Duration::ZERO,
                },
            ],
            calls.clone(),
        );
        assert!(matches!(
            claim.issue_proof_with_rng(
                Duration::from_secs(20),
                |permit| expiring.fresh(permit),
                &mut rng,
            ),
            Err(FoundationError::Expired)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let status = store.status().unwrap();
        assert_eq!(status.proof_issued, 1);
        assert_eq!(status.burned, 1);
    }

    #[test]
    fn replay_after_tombstone_cleanup_never_rederives_or_revives() {
        let (store, clock) = store_with_clock(limits(4, 2));
        let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x9e);
        let token = issued(&store, &binding, 0x9f);
        let raw = *token.as_bytes();
        let _revalidated = store
            .consume_proof(token, &binding.caller(), |permit| binding.fresh(permit))
            .unwrap();
        assert_eq!(store.status().unwrap().burned, 1);

        clock.advance_wall(Duration::from_secs(60));
        clock.advance_monotonic(Duration::from_secs(21));
        store.prune_expired().unwrap();
        assert_eq!(store.status().unwrap().total, 0);

        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = calls.clone();
        assert!(matches!(
            store.consume_proof(ProofToken(raw), &binding.caller(), move |_permit| {
                calls.fetch_add(1, Ordering::SeqCst);
                panic!("an absent tombstone must not mint a point-of-use permit")
            }),
            Err(FoundationError::Rejected)
        ));
        assert_eq!(observed_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn regressed_clock_after_proof_issue_never_revives_or_extends_it() {
        let (store, clock) = store_with_clock(limits(4, 2));
        let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x86);
        let token = issued(&store, &binding, 0x87);
        let raw = *token.as_bytes();

        clock.advance(Duration::from_secs(5));
        assert_eq!(store.status().unwrap().proof_issued, 1);
        clock.regress(Duration::from_secs(1));
        assert!(matches!(
            store.consume_proof(ProofToken(raw), &binding.caller(), |permit| {
                binding.fresh(permit)
            }),
            Err(FoundationError::ClockRegressed)
        ));

        clock.advance(Duration::from_secs(1));
        assert_eq!(store.status().unwrap().proof_issued, 1);
        clock.advance(Duration::from_secs(15));
        assert!(matches!(
            store.consume_proof(token, &binding.caller(), |permit| binding.fresh(permit)),
            Err(FoundationError::Rejected)
        ));
        let status = store.status().unwrap();
        assert_eq!(status.proof_issued, 0);
        assert_eq!(status.burned, 1);
    }

    #[test]
    fn constant_time_lookup_visits_every_bounded_entry() {
        let store = test_store(limits(8, 8));
        let bindings = [
            BindingFixture::new("member-alpha", ClawSelector::ClawM, 0x90),
            BindingFixture::new("member-beta", ClawSelector::ClawL, 0x91),
            BindingFixture::new("member-gamma", ClawSelector::ClawM, 0x92),
        ];
        let mut hashes = Vec::new();
        for (binding, challenge_byte) in bindings.iter().zip([0xa0, 0xa1, 0xa2]) {
            let token = issued(&store, binding, challenge_byte);
            hashes.push(domain_hash(PROOF_TOKEN_HASH_DOMAIN, token.as_bytes()));
            drop(token);
        }
        let inner = store.lock_operation().unwrap();
        for target in [hashes[0], hashes[2], [0xff; 32]] {
            let lookup = inner.lookup_hash_ct(LookupKind::ProofToken, &target);
            assert_eq!(lookup.comparisons, inner.entries.len());
        }
    }

    #[test]
    fn consumed_token_hash_remains_reserved_until_tombstone_expiry() {
        let store = test_store(limits(4, 2));
        let binding = BindingFixture::new("member-alpha", ClawSelector::ClawM, 0xb0);
        let token = issued(&store, &binding, 0xb1);
        let token_hash = domain_hash(PROOF_TOKEN_HASH_DOMAIN, token.as_bytes());
        let revalidated = store
            .consume_proof(token, &binding.caller(), |permit| binding.fresh(permit))
            .unwrap();
        assert!(revalidated.binding.matches(&binding.stored()));
        assert!(revalidated.signed_wall_expiry > Duration::from_secs(1_000));
        let inner = store.lock_operation().unwrap();
        let lookup = inner.lookup_hash_ct(LookupKind::AnyProofToken, &token_hash);
        assert!(lookup.index.is_some());
        assert_eq!(lookup.comparisons, inner.entries.len());
    }
}
