//! Inert owner-present foundation for the Product A mobile Claw VPN DEV flow.
//!
//! This module deliberately has no route, handler, `AppState`, environment,
//! relying-party, Mesh-C, mint, host, or network integration. Its symbols are
//! private to the module, so production code cannot construct authority from
//! these types. A later reviewed slice must explicitly open the boundary.

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use household_rs::{
    claw_vpn_mobile_state::{ClawVpnMobileClawId, ClawVpnMobileDeviceId, ClawVpnMobileMemberId},
    machine_cert::PersonId,
    owner_approval_v2::{
        MOBILE_CLAW_VPN_DEV_E2E_BUNDLE_ID, MOBILE_CLAW_VPN_DEV_E2E_MAX_APPROVAL_TTL_SECS,
        MobileClawVpnDevE2eExecutionTupleV1, OwnerApprovalContextV2,
    },
};
use rand::{CryptoRng, RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
        ClawVpnMobileMemberId::try_new(member_id.to_string())
            .map_err(|_| FoundationError::InvalidBinding)?;
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
struct PendingBinding {
    member_scope: MemberScope,
    config_generation: u64,
    config_digest: [u8; 32],
    tuple_canonical: Arc<[u8]>,
    tuple_digest: [u8; 32],
    context_canonical: Arc<[u8]>,
    context_digest: [u8; 32],
    authority_digest: [u8; 32],
}

impl fmt::Debug for PendingBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingBinding")
            .field("member", &"<redacted>")
            .field("config_generation", &self.config_generation)
            .field("config", &"<redacted>")
            .field("tuple", &"<redacted>")
            .field("context", &"<redacted>")
            .field("authority", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl PendingBinding {
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
        })
    }

    fn matches(&self, other: &Self) -> bool {
        let fixed = self.member_scope.ct_eq_choice(&other.member_scope)
            & self.config_generation.ct_eq(&other.config_generation)
            & self.config_digest.ct_eq(&other.config_digest)
            & self.tuple_digest.ct_eq(&other.tuple_digest)
            & self.context_digest.ct_eq(&other.context_digest)
            & self.authority_digest.ct_eq(&other.authority_digest);
        bool::from(fixed)
            && self.tuple_canonical.as_ref() == other.tuple_canonical.as_ref()
            && self.context_canonical.as_ref() == other.context_canonical.as_ref()
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

// This value proves only that the exact static binding was consumed once. It
// is deliberately not a Mesh freshness proof: the later transaction must
// still check member_devices plus the full (member, device, claw) grant and
// availability under the shared Mesh lock.
struct ConsumedCapability {
    binding: PendingBinding,
}

impl fmt::Debug for ConsumedCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsumedCapability(<redacted>)")
    }
}

#[derive(Clone)]
struct CapabilityStore {
    inner: Arc<Mutex<StoreInner>>,
}

impl fmt::Debug for CapabilityStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.debug_struct("CapabilityStore")
            .field("status", &inner.status())
            .finish()
    }
}

impl CapabilityStore {
    fn new(limits: StoreLimits) -> Self {
        Self {
            inner: Arc::new(Mutex::new(StoreInner {
                limits,
                next_entry_id: 1,
                entries: Vec::new(),
            })),
        }
    }

    fn lock_operation(&self) -> Result<MutexGuard<'_, StoreInner>, FoundationError> {
        self.inner.lock().map_err(|_| FoundationError::Poisoned)
    }

    fn reserve(
        &self,
        member_scope: MemberScope,
        now: Instant,
        ttl: Duration,
    ) -> Result<ReservationHandle, FoundationError> {
        let mut rng = OsRng;
        self.reserve_with_rng(member_scope, now, ttl, &mut rng)
    }

    fn reserve_with_rng<R: CryptoRng + RngCore>(
        &self,
        member_scope: MemberScope,
        now: Instant,
        ttl: Duration,
        rng: &mut R,
    ) -> Result<ReservationHandle, FoundationError> {
        let mut inner = self.lock_operation()?;
        inner.prune_expired(now);
        inner.validate_reservation_capacity(&member_scope, ttl)?;
        let deadline = now
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
                member_scope,
                reservation_hash,
                challenge_hash: None,
                proof_token_hash: None,
                deadline,
                state: EntryState::Reserved,
            });
            return Ok(ReservationHandle(secret));
        }
        Err(FoundationError::EntropyCollision)
    }

    fn release_reserved(&self, reservation: &ReservationHandle) -> Result<(), FoundationError> {
        let target = domain_hash(RESERVATION_HASH_DOMAIN, &reservation.0);
        let mut inner = self.lock_operation()?;
        let lookup = inner.lookup_hash_ct(LookupKind::Reserved, &target);
        let index = lookup.unique_index()?;
        inner.entries.swap_remove(index);
        Ok(())
    }

    fn commit_pending(
        &self,
        reservation: &ReservationHandle,
        challenge: &ChallengeHandle,
        binding: PendingBinding,
        now: Instant,
    ) -> Result<(), FoundationError> {
        let reservation_hash = domain_hash(RESERVATION_HASH_DOMAIN, &reservation.0);
        let challenge_hash = domain_hash(CHALLENGE_HASH_DOMAIN, &challenge.0);
        let mut inner = self.lock_operation()?;
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
        if inner
            .lookup_hash_ct(LookupKind::AnyChallenge, &challenge_hash)
            .index
            .is_some()
        {
            return Err(FoundationError::Rejected);
        }
        inner.entries[index].transition(EntryState::Pending { binding })?;
        inner.entries[index].challenge_hash = Some(challenge_hash);
        Ok(())
    }

    fn claim_finishing(
        &self,
        challenge: &ChallengeHandle,
        expected: &PendingBinding,
        now: Instant,
    ) -> Result<FinishingClaim, FoundationError> {
        let challenge_hash = domain_hash(CHALLENGE_HASH_DOMAIN, &challenge.0);
        let mut inner = self.lock_operation()?;
        inner.prune_expired(now);
        let lookup = inner.lookup_hash_ct(LookupKind::PendingChallenge, &challenge_hash);
        let index = lookup.unique_index()?;
        if now >= inner.entries[index].deadline {
            inner.entries[index].transition(EntryState::Burned)?;
            return Err(FoundationError::Expired);
        }
        let EntryState::Pending {
            binding: stored, ..
        } = &inner.entries[index].state
        else {
            return Err(FoundationError::Rejected);
        };
        if !stored.matches(expected) {
            return Err(FoundationError::Rejected);
        }
        let binding = stored.clone();
        let entry_id = inner.entries[index].entry_id;
        inner.entries[index].transition(EntryState::Finishing { binding })?;
        Ok(FinishingClaim {
            store: self.clone(),
            entry_id,
            active: true,
        })
    }

    // Taking ownership makes the caller surrender the bearer value even on a
    // rejected attempt; `ProofToken` zeroizes its plaintext in `Drop`.
    #[allow(clippy::needless_pass_by_value)]
    fn consume_proof(
        &self,
        token: ProofToken,
        expected: &PendingBinding,
        now: Instant,
    ) -> Result<ConsumedCapability, FoundationError> {
        let token_hash = domain_hash(PROOF_TOKEN_HASH_DOMAIN, token.as_bytes());
        let mut inner = self.lock_operation()?;
        inner.prune_expired(now);
        let lookup = inner.lookup_hash_ct(LookupKind::ProofToken, &token_hash);
        let index = lookup.unique_index()?;
        let EntryState::ProofIssued {
            binding: stored, ..
        } = &inner.entries[index].state
        else {
            return Err(FoundationError::Rejected);
        };
        if !stored.matches(expected) {
            return Err(FoundationError::Rejected);
        }
        let binding = stored.clone();
        inner.entries[index].transition(EntryState::Burned)?;
        Ok(ConsumedCapability { binding })
    }

    fn status(&self) -> Result<StoreStatus, FoundationError> {
        Ok(self.lock_operation()?.status())
    }

    fn prune_expired(&self, now: Instant) -> Result<(), FoundationError> {
        self.lock_operation()?.prune_expired(now);
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
    active: bool,
}

impl fmt::Debug for FinishingClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FinishingClaim(<redacted>)")
    }
}

impl FinishingClaim {
    fn issue_proof(mut self, now: Instant, ttl: Duration) -> Result<ProofToken, FoundationError> {
        let mut rng = OsRng;
        let token = self.issue_proof_with_rng(now, ttl, &mut rng)?;
        self.active = false;
        Ok(token)
    }

    fn issue_proof_with_rng<R: CryptoRng + RngCore>(
        &mut self,
        now: Instant,
        ttl: Duration,
        rng: &mut R,
    ) -> Result<ProofToken, FoundationError> {
        let mut inner = self.store.lock_operation()?;
        if ttl.is_zero() || ttl > inner.limits.max_proof_ttl {
            return Err(FoundationError::InvalidDeadline);
        }
        let index = inner
            .entries
            .iter()
            .position(|entry| entry.entry_id == self.entry_id)
            .ok_or(FoundationError::Rejected)?;
        if now >= inner.entries[index].deadline {
            inner.entries[index].transition(EntryState::Burned)?;
            return Err(FoundationError::Expired);
        }
        if !matches!(inner.entries[index].state, EntryState::Finishing { .. }) {
            return Err(FoundationError::Rejected);
        }
        let ttl_deadline = now
            .checked_add(ttl)
            .ok_or(FoundationError::InvalidDeadline)?;
        let proof_deadline = inner.entries[index].deadline.min(ttl_deadline);

        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let mut secret = [0u8; OPAQUE_SECRET_LEN];
            rng.fill_bytes(&mut secret);
            if bool::from(secret.ct_eq(&[0; OPAQUE_SECRET_LEN])) {
                secret.zeroize();
                continue;
            }
            let token_hash = domain_hash(PROOF_TOKEN_HASH_DOMAIN, &secret);
            if inner
                .lookup_hash_ct(LookupKind::AnyProofToken, &token_hash)
                .index
                .is_some()
            {
                secret.zeroize();
                continue;
            }
            let EntryState::Finishing { binding } = &inner.entries[index].state else {
                secret.zeroize();
                return Err(FoundationError::Rejected);
            };
            let binding = binding.clone();
            inner.entries[index].deadline = proof_deadline;
            inner.entries[index].transition(EntryState::ProofIssued { binding })?;
            inner.entries[index].proof_token_hash = Some(token_hash);
            return Ok(ProofToken(secret));
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
}

impl StoreInner {
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

    fn prune_expired(&mut self, now: Instant) {
        let mut retained = Vec::with_capacity(self.entries.len());
        for mut entry in self.entries.drain(..) {
            if now < entry.deadline {
                retained.push(entry);
            } else if matches!(entry.state, EntryState::Finishing { .. }) {
                let _ = entry.transition(EntryState::Burned);
                retained.push(entry);
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
    state: EntryState,
}

enum EntryState {
    Reserved,
    Pending { binding: PendingBinding },
    Finishing { binding: PendingBinding },
    ProofIssued { binding: PendingBinding },
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
    match kind {
        ConfigIdKind::Device => ClawVpnMobileDeviceId::try_new(value.to_string())
            .map(|_| ())
            .map_err(|_| FoundationError::InvalidConfig("device_id")),
        ConfigIdKind::Claw => ClawVpnMobileClawId::try_new(value.to_string())
            .map(|_| ())
            .map_err(|_| FoundationError::InvalidConfig("claw_id")),
    }
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

    fn household_id() -> HouseholdId {
        HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap()
    }

    fn binding(member_id: &str, selector: ClawSelector, marker: u8) -> PendingBinding {
        let config = config();
        let selection = config.resolve(selector);
        let tuple =
            MobileClawVpnDevE2eExecutionTupleV1::new(MobileClawVpnDevE2eExecutionTupleInput {
                hh_id: household_id(),
                engine_audience: [marker; 32],
                member_id: member_id.to_string(),
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
                claw_alias: selector.as_str().to_string(),
                issued_at: 1_000,
                expires_at: 1_060,
                server_nonce: [0x77; 32],
            });
        let authority = OwnerAuthoritySnapshot {
            owner_p_id: PersonId("p_owner-alpha".to_string()),
            head_sequence: 9,
            head_hash: [0x88; 32],
            credential_set_digest: [0x99; 32],
        };
        let context = OwnerApprovalContextV2::mobile_claw_vpn_dev_e2e_execute(
            MobileClawVpnDevE2eApprovalContextInput {
                owner_p_id: authority.owner_p_id.clone(),
                execution: &tuple,
                replay_nonce: [0xaa; 32],
            },
        )
        .unwrap();
        PendingBinding::from_trusted_state(member_id, &selection, &tuple, &context, &authority)
            .unwrap()
    }

    fn pending(
        store: &CapabilityStore,
        binding: &PendingBinding,
        challenge_byte: u8,
        now: Instant,
    ) -> (ReservationHandle, ChallengeHandle) {
        let reservation = store
            .reserve(binding.member_scope.clone(), now, Duration::from_secs(60))
            .unwrap();
        let challenge = ChallengeHandle::from_server_random([challenge_byte; 32]).unwrap();
        store
            .commit_pending(&reservation, &challenge, binding.clone(), now)
            .unwrap();
        (reservation, challenge)
    }

    fn issued(
        store: &CapabilityStore,
        binding: &PendingBinding,
        challenge_byte: u8,
        now: Instant,
    ) -> ProofToken {
        let (_, challenge) = pending(store, binding, challenge_byte, now);
        store
            .claim_finishing(&challenge, binding, now)
            .unwrap()
            .issue_proof(now, Duration::from_secs(20))
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

        assert!(
            PendingBinding::from_trusted_state(
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
            PendingBinding::from_trusted_state(
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
            PendingBinding::from_trusted_state(
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

        let store = CapabilityStore::new(limits(8, 4));
        let binding = binding("member-alpha", ClawSelector::ClawM, 0x10);
        let now = Instant::now();
        let reservation = store
            .reserve(binding.member_scope.clone(), now, Duration::from_secs(60))
            .unwrap();
        assert_eq!(store.status().unwrap().reserved, 1);
        store.release_reserved(&reservation).unwrap();
        assert_eq!(store.status().unwrap().total, 0);

        let (reservation, challenge) = pending(&store, &binding, 0x11, now);
        assert_eq!(store.status().unwrap().pending, 1);
        assert_eq!(
            store.release_reserved(&reservation),
            Err(FoundationError::Rejected)
        );
        let claim = store.claim_finishing(&challenge, &binding, now).unwrap();
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
            store.claim_finishing(&challenge, &binding, now),
            Err(FoundationError::Rejected)
        ));
    }

    #[test]
    fn finishing_drop_explicit_error_and_unwind_burn_synchronously() {
        for mode in ["drop", "explicit", "panic"] {
            let store = CapabilityStore::new(limits(4, 2));
            let binding = binding("member-alpha", ClawSelector::ClawM, 0x20);
            let now = Instant::now();
            let (_, challenge) = pending(&store, &binding, 0x21, now);
            match mode {
                "drop" => drop(store.claim_finishing(&challenge, &binding, now).unwrap()),
                "explicit" => store
                    .claim_finishing(&challenge, &binding, now)
                    .unwrap()
                    .burn(),
                "panic" => {
                    let unwind = catch_unwind(AssertUnwindSafe(|| {
                        let _claim = store.claim_finishing(&challenge, &binding, now).unwrap();
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
    fn panic_while_store_lock_is_held_still_burns_before_unwind_returns() {
        let store = CapabilityStore::new(limits(4, 2));
        let binding = binding("member-alpha", ClawSelector::ClawM, 0x22);
        let now = Instant::now();
        let (_, challenge) = pending(&store, &binding, 0x23, now);
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let mut claim = store.claim_finishing(&challenge, &binding, now).unwrap();
            let mut rng = PanicRng;
            let _ = claim.issue_proof_with_rng(now, Duration::from_secs(20), &mut rng);
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
    fn wrong_member_or_static_binding_never_transitions() {
        let store = CapabilityStore::new(limits(8, 4));
        let expected = binding("member-alpha", ClawSelector::ClawM, 0x30);
        let wrong_member = binding("member-beta", ClawSelector::ClawM, 0x30);
        let mut wrong_head = expected.clone();
        wrong_head.authority_digest[0] ^= 1;
        let now = Instant::now();
        let (_, challenge) = pending(&store, &expected, 0x31, now);

        for wrong in [&wrong_member, &wrong_head] {
            assert!(matches!(
                store.claim_finishing(&challenge, wrong, now),
                Err(FoundationError::Rejected)
            ));
            assert_eq!(store.status().unwrap().pending, 1);
        }

        let token = store
            .claim_finishing(&challenge, &expected, now)
            .unwrap()
            .issue_proof(now, Duration::from_secs(20))
            .unwrap();
        let duplicate = ProofToken(*token.as_bytes());
        assert!(store.consume_proof(duplicate, &wrong_member, now).is_err());
        assert_eq!(store.status().unwrap().proof_issued, 1);
        let consumed = store.consume_proof(token, &expected, now).unwrap();
        assert!(consumed.binding.matches(&expected));
        assert_eq!(store.status().unwrap().burned, 1);
    }

    #[test]
    fn proof_is_hash_only_single_use_and_response_loss_cannot_reissue() {
        let store = CapabilityStore::new(limits(8, 4));
        let binding = binding("member-alpha", ClawSelector::ClawM, 0x40);
        let now = Instant::now();
        let (_, challenge) = pending(&store, &binding, 0x41, now);
        let token = store
            .claim_finishing(&challenge, &binding, now)
            .unwrap()
            .issue_proof(now, Duration::from_secs(20))
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
            store.claim_finishing(&challenge, &binding, now),
            Err(FoundationError::Rejected)
        ));
        assert_eq!(store.status().unwrap().proof_issued, 1);
    }

    #[test]
    fn same_token_concurrency_has_exactly_one_atomic_consumer() {
        let store = CapabilityStore::new(limits(8, 4));
        let binding = binding("member-alpha", ClawSelector::ClawM, 0x50);
        let now = Instant::now();
        let token = issued(&store, &binding, 0x51, now);
        let raw = *token.as_bytes();
        drop(token);

        let left_store = store.clone();
        let left_binding = binding.clone();
        let left =
            thread::spawn(move || left_store.consume_proof(ProofToken(raw), &left_binding, now));
        let right_store = store.clone();
        let right_binding = binding.clone();
        let right =
            thread::spawn(move || right_store.consume_proof(ProofToken(raw), &right_binding, now));
        let successes =
            usize::from(left.join().unwrap().is_ok()) + usize::from(right.join().unwrap().is_ok());
        assert_eq!(successes, 1);
        assert_eq!(store.status().unwrap().burned, 1);
    }

    #[test]
    fn duplicate_challenge_is_rejected_before_and_after_first_claim() {
        let store = CapabilityStore::new(limits(8, 4));
        let first = binding("member-alpha", ClawSelector::ClawM, 0x60);
        let second = binding("member-beta", ClawSelector::ClawL, 0x61);
        let now = Instant::now();
        let (_, challenge) = pending(&store, &first, 0x62, now);
        let reservation = store
            .reserve(second.member_scope.clone(), now, Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            store.commit_pending(&reservation, &challenge, second, now),
            Err(FoundationError::Rejected)
        );
        let status = store.status().unwrap();
        assert_eq!(status.pending, 1);
        assert_eq!(status.reserved, 1);
        store.release_reserved(&reservation).unwrap();

        drop(store.claim_finishing(&challenge, &first, now).unwrap());
        let reservation = store
            .reserve(
                binding("member-beta", ClawSelector::ClawL, 0x63).member_scope,
                now,
                Duration::from_secs(60),
            )
            .unwrap();
        let replacement = binding("member-beta", ClawSelector::ClawL, 0x63);
        assert_eq!(
            store.commit_pending(&reservation, &challenge, replacement, now),
            Err(FoundationError::Rejected)
        );
        assert_eq!(store.status().unwrap().burned, 1);
        assert_eq!(store.status().unwrap().reserved, 1);
    }

    #[test]
    fn quotas_deadlines_expiry_and_restart_are_fail_closed() {
        let store = CapabilityStore::new(limits(2, 1));
        let alpha = binding("member-alpha", ClawSelector::ClawM, 0x70);
        let beta = binding("member-beta", ClawSelector::ClawL, 0x71);
        let now = Instant::now();
        let alpha_reservation = store
            .reserve(alpha.member_scope.clone(), now, Duration::from_secs(10))
            .unwrap();
        assert!(matches!(
            store.reserve(alpha.member_scope.clone(), now, Duration::from_secs(10)),
            Err(FoundationError::MemberFull)
        ));
        let beta_reservation = store
            .reserve(beta.member_scope.clone(), now, Duration::from_secs(10))
            .unwrap();
        assert!(matches!(
            store.reserve(
                MemberScope::from_server_derived("member-gamma").unwrap(),
                now,
                Duration::from_secs(10)
            ),
            Err(FoundationError::StoreFull)
        ));
        assert_eq!(store.status().unwrap().total, 2);
        assert!(matches!(
            store.reserve(alpha.member_scope.clone(), now, Duration::MAX),
            Err(FoundationError::InvalidDeadline)
        ));

        store
            .prune_expired(now.checked_add(Duration::from_secs(10)).unwrap())
            .unwrap();
        assert_eq!(store.status().unwrap().total, 0);

        let restarted = CapabilityStore::new(limits(2, 1));
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
        let store = CapabilityStore::new(limits(4, 2));
        let binding = binding("member-alpha", ClawSelector::ClawM, 0x80);
        let now = Instant::now();
        let reservation = store
            .reserve(binding.member_scope.clone(), now, Duration::from_secs(1))
            .unwrap();
        let challenge = ChallengeHandle::from_server_random([0x81; 32]).unwrap();
        store
            .commit_pending(&reservation, &challenge, binding.clone(), now)
            .unwrap();
        let claim = store.claim_finishing(&challenge, &binding, now).unwrap();
        let expired = now.checked_add(Duration::from_secs(1)).unwrap();
        store.prune_expired(expired).unwrap();
        assert_eq!(store.status().unwrap().burned, 1);
        drop(claim);
        assert_eq!(store.status().unwrap().burned, 1);
        store.prune_expired(expired).unwrap();
        assert_eq!(store.status().unwrap().total, 0);
    }

    #[test]
    fn constant_time_lookup_visits_every_bounded_entry() {
        let store = CapabilityStore::new(limits(8, 8));
        let now = Instant::now();
        let bindings = [
            binding("member-alpha", ClawSelector::ClawM, 0x90),
            binding("member-beta", ClawSelector::ClawL, 0x91),
            binding("member-gamma", ClawSelector::ClawM, 0x92),
        ];
        let mut hashes = Vec::new();
        for (binding, challenge_byte) in bindings.iter().zip([0xa0, 0xa1, 0xa2]) {
            let token = issued(&store, binding, challenge_byte, now);
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
        let store = CapabilityStore::new(limits(4, 2));
        let binding = binding("member-alpha", ClawSelector::ClawM, 0xb0);
        let now = Instant::now();
        let token = issued(&store, &binding, 0xb1, now);
        let token_hash = domain_hash(PROOF_TOKEN_HASH_DOMAIN, token.as_bytes());
        store.consume_proof(token, &binding, now).unwrap();
        let inner = store.lock_operation().unwrap();
        let lookup = inner.lookup_hash_ct(LookupKind::AnyProofToken, &token_hash);
        assert!(lookup.index.is_some());
        assert_eq!(lookup.comparisons, inner.entries.len());
    }
}
