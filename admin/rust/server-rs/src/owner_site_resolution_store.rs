//! Durable, fail-closed resolution store for owner-site promotion (DP2 Fatia-2).
//!
//! Like the promotion boundary, this store is compiled into production but is
//! reachable only through the linearizer, which production never drives (no
//! `Pending` source), so several methods and variants are inert here.
//!
//! This module persists a strictly-smaller PROJECTION of promotion state —
//! resolution keys, captured generations, consumed claim ids, and
//! authority/revoke watermarks. It NEVER serializes the sealed carriers
//! (`PendingFinished`, `OwnerSitePromotionWitness`, `VerifiedMeshPeer`,
//! `DialPermit`): those types have no serde and are owned by the linearizer.
//! The projection is sufficient to (§5):
//!   - prevent reopening a resolved channel,
//!   - prevent reuse of a claim,
//!   - preserve fences/tombstones,
//!   - detect key/claim/generation collisions,
//!   - close on recovery without reconstructing authority or a carrier.
//!
//! Durability reuses `household_rs::storage::atomic_write_cbor` (0600 tmp →
//! fsync → rename → parent fsync). In-memory state becomes observable only
//! after the corresponding durable write succeeds (§6.1); any write/encode
//! failure returns a rejection and mutates nothing (§6.2).

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use household_rs::StorageError;
use household_rs::storage;
use serde::{Deserialize, Serialize};

/// Compile-time budgets. There is deliberately no env/config path to raise or
/// disable them (§5). Reaching a limit rejects BEFORE registering or promoting;
/// there is no eviction that would convert saturation into authorization.
pub(crate) const MAX_OWNER_SITE_PROMOTION_RECORDS: usize = 16_384;
pub(crate) const MAX_OWNER_SITE_CONSUMED_CLAIMS: usize = 16_384;
pub(crate) const MAX_OWNER_SITE_PROMOTION_STORE_BYTES: u64 = 16 * 1024 * 1024;

const OWNER_SITE_PROMOTION_STATE_VERSION: u8 = 1;
const OWNER_SITE_PROMOTION_STATE_KIND: &str = "owner-site-promotion-state";
const OWNER_SITE_PROMOTION_STATE_FILE: &str = "owner_site_promotion_state_v1.cbor";

/// The persisted identity of one exact owner-site channel (§5). Derived by the
/// linearizer from `PendingFinished`'s private fields; never accepted from wire.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerSiteResolutionKeyV1 {
    pub(crate) household: String,
    pub(crate) ws_instance: [u8; 32],
    pub(crate) channel_id: [u8; 32],
    pub(crate) channel_epoch: u64,
    pub(crate) channel_binding: [u8; 32],
}

/// Persisted lifecycle state. Only these four are durable; `Promoted`/`Revoking`
/// carriers live in memory and are never serialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum OwnerSiteResolutionState {
    Pending,
    Promoted,
    Revoking,
    Closed,
}

/// One persisted resolution record — the projection, not a carrier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerSiteResolutionRecord {
    key: OwnerSiteResolutionKeyV1,
    claim_id: [u8; 32],
    authz_epoch: u64,
    roster_digest: [u8; 32],
    provider_generation: u64,
    cancellation_generation: u64,
    state: OwnerSiteResolutionState,
}

impl OwnerSiteResolutionRecord {
    #[must_use]
    pub(crate) fn state(&self) -> OwnerSiteResolutionState {
        self.state
    }

    #[must_use]
    pub(crate) fn claim_id(&self) -> &[u8; 32] {
        &self.claim_id
    }
}

/// Watermark identity: household + the authority coordinate `(authz_epoch,
/// roster_digest)`. Equal epoch with a distinct digest is a terminal conflict,
/// never a tie (§5).
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerSiteWatermarkKey {
    household: String,
    authz_epoch: u64,
    roster_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerSiteWatermark {
    max_provider_generation: u64,
    max_cancellation_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerSiteWatermarkEntry {
    key: OwnerSiteWatermarkKey,
    value: OwnerSiteWatermark,
}

/// The canonical CBOR envelope (§5). The three sets are kept strictly sorted
/// and duplicate-free so the serialization is deterministic; on load a set that
/// is out of order or has duplicates makes the store unavailable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerSitePromotionStateEnvelope {
    v: u8,
    kind: String,
    records: Vec<OwnerSiteResolutionRecord>,
    consumed_claims: Vec<[u8; 32]>,
    watermarks: Vec<OwnerSiteWatermarkEntry>,
}

impl OwnerSitePromotionStateEnvelope {
    fn empty() -> Self {
        Self {
            v: OWNER_SITE_PROMOTION_STATE_VERSION,
            kind: OWNER_SITE_PROMOTION_STATE_KIND.to_string(),
            records: Vec::new(),
            consumed_claims: Vec::new(),
            watermarks: Vec::new(),
        }
    }

    /// Reject any envelope that is not exactly our canonical shape: version,
    /// kind, strictly-sorted-and-unique sets, budgets, and no epoch/digest
    /// conflict (§5/§6).
    fn validate(&self) -> Result<(), OwnerSiteResolutionStoreError> {
        if self.v != OWNER_SITE_PROMOTION_STATE_VERSION
            || self.kind != OWNER_SITE_PROMOTION_STATE_KIND
        {
            return Err(OwnerSiteResolutionStoreError::Unavailable);
        }
        if self.records.len() > MAX_OWNER_SITE_PROMOTION_RECORDS
            || self.consumed_claims.len() > MAX_OWNER_SITE_CONSUMED_CLAIMS
        {
            return Err(OwnerSiteResolutionStoreError::Unavailable);
        }
        // Records strictly ascending by key (⇒ sorted and unique).
        if self
            .records
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
        {
            return Err(OwnerSiteResolutionStoreError::Unavailable);
        }
        // Consumed claims strictly ascending (⇒ sorted and unique).
        if self
            .consumed_claims
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(OwnerSiteResolutionStoreError::Unavailable);
        }
        // Watermarks strictly ascending by key.
        if self
            .watermarks
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
        {
            return Err(OwnerSiteResolutionStoreError::Unavailable);
        }
        // Equal (household, authz_epoch) with a different roster_digest is a
        // terminal conflict.
        for (i, a) in self.watermarks.iter().enumerate() {
            for b in &self.watermarks[i + 1..] {
                if a.key.household == b.key.household
                    && a.key.authz_epoch == b.key.authz_epoch
                    && a.key.roster_digest != b.key.roster_digest
                {
                    return Err(OwnerSiteResolutionStoreError::Unavailable);
                }
            }
        }
        Ok(())
    }
}

/// Rejection reasons. Every variant fails closed: it produces no witness, peer,
/// or permit and leaves persisted state unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerSiteResolutionStoreError {
    /// The on-disk store could not be loaded/validated, or is oversized. The
    /// promotion path must close.
    Unavailable,
    /// A budget was reached; nothing is evicted to make room.
    Saturated,
    /// The key already exists (resolved channels cannot be reopened).
    DuplicateKey,
    /// The claim id already exists as a record or in the consumed set.
    DuplicateClaim,
    /// The requested lifecycle transition is not allowed from the current state.
    InvalidTransition,
    /// A generation would move backwards.
    GenerationRollback,
    /// Equal authority epoch with a distinct roster digest.
    DigestConflict,
    /// The durable write itself failed (encode/ENOSPC/write/flush/fsync/rename).
    Persist,
}

impl From<StorageError> for OwnerSiteResolutionStoreError {
    fn from(_: StorageError) -> Self {
        // Any storage-layer failure is a persistence failure that must fail
        // closed; the caller emits zero witness/peer/permit.
        OwnerSiteResolutionStoreError::Persist
    }
}

/// The durable resolution store owned by the linearizer. It holds the validated
/// in-memory envelope plus the file path; all mutations persist first and only
/// then become observable in memory.
#[derive(Debug)]
pub(crate) struct OwnerSiteResolutionStore {
    path: PathBuf,
    envelope: OwnerSitePromotionStateEnvelope,
}

impl OwnerSiteResolutionStore {
    #[must_use]
    fn state_path(state_dir: &Path) -> PathBuf {
        storage::household_dir(state_dir).join(OWNER_SITE_PROMOTION_STATE_FILE)
    }

    /// Open the store, applying fail-closed recovery (§6):
    ///   - absent file → start with no external records;
    ///   - oversized/malformed/non-canonical/duplicate/conflict → unavailable;
    ///   - any persisted `Pending`/`Promoted`/`Revoking` is terminalized to
    ///     `Closed` before it can serve a promotion (never reconstructed as
    ///     live authority).
    pub(crate) fn open(state_dir: &Path) -> Result<Self, OwnerSiteResolutionStoreError> {
        let path = Self::state_path(state_dir);

        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() > MAX_OWNER_SITE_PROMOTION_STORE_BYTES {
                return Err(OwnerSiteResolutionStoreError::Unavailable);
            }
        }

        let loaded: Option<OwnerSitePromotionStateEnvelope> = storage::read_optional_cbor(&path)
            .map_err(|_| OwnerSiteResolutionStoreError::Unavailable)?;

        let mut envelope = match loaded {
            None => OwnerSitePromotionStateEnvelope::empty(),
            Some(envelope) => {
                envelope.validate()?;
                envelope
            }
        };

        // Terminalize every recovered live-ish record to Closed. A crash can
        // never yield an open/promotable record after restart; consumed claims
        // and watermarks are retained to bar reuse and detect conflicts.
        for record in &mut envelope.records {
            if matches!(
                record.state,
                OwnerSiteResolutionState::Pending
                    | OwnerSiteResolutionState::Promoted
                    | OwnerSiteResolutionState::Revoking
            ) {
                record.state = OwnerSiteResolutionState::Closed;
            }
        }

        Ok(Self { path, envelope })
    }

    /// Persist a candidate envelope durably, then adopt it in memory. On any
    /// failure the in-memory state is left untouched (§6.1/§6.2).
    fn commit(
        &mut self,
        candidate: OwnerSitePromotionStateEnvelope,
    ) -> Result<(), OwnerSiteResolutionStoreError> {
        storage::atomic_write_cbor(&self.path, &candidate)?;
        self.envelope = candidate;
        Ok(())
    }

    /// Test-only sibling of [`Self::commit`] that drives the durable write
    /// through the injectable tmp-write failure seam. It proves the
    /// write-first-then-adopt order fails closed: the in-memory envelope is
    /// replaced only after the durable write succeeds, so an injected failure
    /// leaves memory and disk untouched (§6.1/§6.2, §12 store faults).
    #[cfg(test)]
    fn commit_with_injected_write_error(
        &mut self,
        candidate: OwnerSitePromotionStateEnvelope,
        error: std::io::Error,
    ) -> Result<(), OwnerSiteResolutionStoreError> {
        storage::atomic_write_cbor_with_tmp_write_error(&self.path, &candidate, error)?;
        self.envelope = candidate;
        Ok(())
    }

    #[must_use]
    fn record_index(&self, key: &OwnerSiteResolutionKeyV1) -> Option<usize> {
        self.envelope
            .records
            .binary_search_by(|record| record.key.cmp(key))
            .ok()
    }

    /// The single live record for `key`, if any (`Closed` records are resolved,
    /// never live).
    #[must_use]
    pub(crate) fn live_record(
        &self,
        key: &OwnerSiteResolutionKeyV1,
    ) -> Option<&OwnerSiteResolutionRecord> {
        self.record_index(key)
            .map(|index| &self.envelope.records[index])
            .filter(|record| record.state != OwnerSiteResolutionState::Closed)
    }

    #[must_use]
    pub(crate) fn is_claim_present(&self, claim_id: &[u8; 32]) -> bool {
        self.envelope
            .consumed_claims
            .binary_search(claim_id)
            .is_ok()
            || self
                .envelope
                .records
                .iter()
                .any(|record| &record.claim_id == claim_id)
    }

    /// Register a fresh `Pending` record (§7.1). Rejects if the key already
    /// exists (no reopening), if the claim collides, or if a budget is reached.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_pending(
        &mut self,
        key: OwnerSiteResolutionKeyV1,
        claim_id: [u8; 32],
        authz_epoch: u64,
        roster_digest: [u8; 32],
        provider_generation: u64,
        cancellation_generation: u64,
    ) -> Result<(), OwnerSiteResolutionStoreError> {
        if self.record_index(&key).is_some() {
            return Err(OwnerSiteResolutionStoreError::DuplicateKey);
        }
        if self.is_claim_present(&claim_id) {
            return Err(OwnerSiteResolutionStoreError::DuplicateClaim);
        }
        if self.envelope.records.len() >= MAX_OWNER_SITE_PROMOTION_RECORDS {
            return Err(OwnerSiteResolutionStoreError::Saturated);
        }

        let mut candidate = self.envelope.clone();
        let record = OwnerSiteResolutionRecord {
            key,
            claim_id,
            authz_epoch,
            roster_digest,
            provider_generation,
            cancellation_generation,
            state: OwnerSiteResolutionState::Pending,
        };
        let insert_at = candidate
            .records
            .binary_search_by(|existing| existing.key.cmp(&record.key))
            .expect_err("duplicate key was already rejected");
        candidate.records.insert(insert_at, record);
        self.commit(candidate)
    }

    /// CAS `Pending -> Promoted` and mark the claim consumed in one atomic
    /// image (§7.6–7.8). The claim must belong to the key and be unconsumed.
    pub(crate) fn promote(
        &mut self,
        key: &OwnerSiteResolutionKeyV1,
        claim_id: &[u8; 32],
    ) -> Result<(), OwnerSiteResolutionStoreError> {
        let index = self
            .record_index(key)
            .ok_or(OwnerSiteResolutionStoreError::InvalidTransition)?;
        if self.envelope.records[index].state != OwnerSiteResolutionState::Pending {
            return Err(OwnerSiteResolutionStoreError::InvalidTransition);
        }
        if &self.envelope.records[index].claim_id != claim_id {
            return Err(OwnerSiteResolutionStoreError::DuplicateClaim);
        }
        if self.envelope.consumed_claims.binary_search(claim_id).is_ok() {
            return Err(OwnerSiteResolutionStoreError::DuplicateClaim);
        }
        if self.envelope.consumed_claims.len() >= MAX_OWNER_SITE_CONSUMED_CLAIMS {
            return Err(OwnerSiteResolutionStoreError::Saturated);
        }

        let mut candidate = self.envelope.clone();
        candidate.records[index].state = OwnerSiteResolutionState::Promoted;
        let insert_at = candidate
            .consumed_claims
            .binary_search(claim_id)
            .expect_err("unconsumed claim was already checked");
        candidate.consumed_claims.insert(insert_at, *claim_id);
        self.commit(candidate)
    }

    /// Advance the revoke fence and mark `Revoking` (§9.1–9.2). Generations may
    /// only move forward.
    pub(crate) fn begin_revoke(
        &mut self,
        key: &OwnerSiteResolutionKeyV1,
        cancellation_generation: u64,
    ) -> Result<(), OwnerSiteResolutionStoreError> {
        let index = self
            .record_index(key)
            .ok_or(OwnerSiteResolutionStoreError::InvalidTransition)?;
        let current = &self.envelope.records[index];
        if !matches!(
            current.state,
            OwnerSiteResolutionState::Promoted | OwnerSiteResolutionState::Revoking
        ) {
            return Err(OwnerSiteResolutionStoreError::InvalidTransition);
        }
        if cancellation_generation < current.cancellation_generation {
            return Err(OwnerSiteResolutionStoreError::GenerationRollback);
        }

        let mut candidate = self.envelope.clone();
        candidate.records[index].cancellation_generation = cancellation_generation;
        candidate.records[index].state = OwnerSiteResolutionState::Revoking;
        self.commit(candidate)
    }

    /// Retain the highest provider/cancellation generations observed for one
    /// authority coordinate `(household, authz_epoch, roster_digest)` (§5). Equal
    /// epoch with a distinct digest is a terminal conflict; a generation that
    /// moves backwards is a rollback. Neither is a tie or an eviction.
    pub(crate) fn observe_authority(
        &mut self,
        household: &str,
        authz_epoch: u64,
        roster_digest: [u8; 32],
        provider_generation: u64,
        cancellation_generation: u64,
    ) -> Result<(), OwnerSiteResolutionStoreError> {
        if self.envelope.watermarks.iter().any(|entry| {
            entry.key.household == household
                && entry.key.authz_epoch == authz_epoch
                && entry.key.roster_digest != roster_digest
        }) {
            return Err(OwnerSiteResolutionStoreError::DigestConflict);
        }
        let watermark_key = OwnerSiteWatermarkKey {
            household: household.to_string(),
            authz_epoch,
            roster_digest,
        };
        let mut candidate = self.envelope.clone();
        match candidate
            .watermarks
            .binary_search_by(|entry| entry.key.cmp(&watermark_key))
        {
            Ok(index) => {
                let value = &mut candidate.watermarks[index].value;
                if provider_generation < value.max_provider_generation
                    || cancellation_generation < value.max_cancellation_generation
                {
                    return Err(OwnerSiteResolutionStoreError::GenerationRollback);
                }
                value.max_provider_generation = provider_generation;
                value.max_cancellation_generation = cancellation_generation;
            }
            Err(insert_at) => {
                if candidate.watermarks.len() >= MAX_OWNER_SITE_PROMOTION_RECORDS {
                    return Err(OwnerSiteResolutionStoreError::Saturated);
                }
                candidate.watermarks.insert(
                    insert_at,
                    OwnerSiteWatermarkEntry {
                        key: watermark_key,
                        value: OwnerSiteWatermark {
                            max_provider_generation: provider_generation,
                            max_cancellation_generation: cancellation_generation,
                        },
                    },
                );
            }
        }
        self.commit(candidate)
    }

    /// The retained `(max_provider_generation, max_cancellation_generation)` for
    /// an authority coordinate, if observed.
    #[must_use]
    pub(crate) fn watermark(
        &self,
        household: &str,
        authz_epoch: u64,
        roster_digest: [u8; 32],
    ) -> Option<(u64, u64)> {
        let watermark_key = OwnerSiteWatermarkKey {
            household: household.to_string(),
            authz_epoch,
            roster_digest,
        };
        self.envelope
            .watermarks
            .binary_search_by(|entry| entry.key.cmp(&watermark_key))
            .ok()
            .map(|index| {
                let value = self.envelope.watermarks[index].value;
                (
                    value.max_provider_generation,
                    value.max_cancellation_generation,
                )
            })
    }

    /// Confirm the terminal `Closed` state after draining (§9.5). Idempotent:
    /// closing a `Closed` record is a no-op that persists nothing new.
    pub(crate) fn confirm_closed(
        &mut self,
        key: &OwnerSiteResolutionKeyV1,
    ) -> Result<(), OwnerSiteResolutionStoreError> {
        let index = self
            .record_index(key)
            .ok_or(OwnerSiteResolutionStoreError::InvalidTransition)?;
        if self.envelope.records[index].state == OwnerSiteResolutionState::Closed {
            return Ok(());
        }
        let mut candidate = self.envelope.clone();
        candidate.records[index].state = OwnerSiteResolutionState::Closed;
        self.commit(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fill: u8) -> OwnerSiteResolutionKeyV1 {
        OwnerSiteResolutionKeyV1 {
            household: format!("household-{fill}"),
            ws_instance: [fill; 32],
            channel_id: [fill ^ 0x11; 32],
            channel_epoch: u64::from(fill),
            channel_binding: [fill ^ 0x22; 32],
        }
    }

    fn store(dir: &std::path::Path) -> OwnerSiteResolutionStore {
        OwnerSiteResolutionStore::open(dir).expect("open store")
    }

    #[test]
    fn empty_store_opens_and_round_trips_a_pending_record() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = store(tmp.path());
        assert!(s.live_record(&key(1)).is_none());
        s.register_pending(key(1), [9; 32], 1, [2; 32], 3, 4).unwrap();
        assert_eq!(
            s.live_record(&key(1)).map(OwnerSiteResolutionRecord::state),
            Some(OwnerSiteResolutionState::Pending)
        );
        // Reload from disk: the durable projection survives.
        let reloaded = store(tmp.path());
        assert!(reloaded.is_claim_present(&[9; 32]));
    }

    #[test]
    fn duplicate_key_and_claim_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = store(tmp.path());
        s.register_pending(key(1), [9; 32], 1, [2; 32], 3, 4).unwrap();
        assert_eq!(
            s.register_pending(key(1), [8; 32], 1, [2; 32], 3, 4),
            Err(OwnerSiteResolutionStoreError::DuplicateKey)
        );
        assert_eq!(
            s.register_pending(key(2), [9; 32], 1, [2; 32], 3, 4),
            Err(OwnerSiteResolutionStoreError::DuplicateClaim)
        );
    }

    #[test]
    fn promote_consumes_claim_and_is_one_shot() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = store(tmp.path());
        s.register_pending(key(1), [9; 32], 1, [2; 32], 3, 4).unwrap();
        s.promote(&key(1), &[9; 32]).unwrap();
        assert_eq!(
            s.live_record(&key(1)).map(OwnerSiteResolutionRecord::state),
            Some(OwnerSiteResolutionState::Promoted)
        );
        // A second promote cannot re-run: not Pending anymore.
        assert_eq!(
            s.promote(&key(1), &[9; 32]),
            Err(OwnerSiteResolutionStoreError::InvalidTransition)
        );
    }

    #[test]
    fn restart_terminalizes_live_records_to_closed_and_bars_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let mut s = store(tmp.path());
            s.register_pending(key(1), [9; 32], 1, [2; 32], 3, 4).unwrap();
            s.promote(&key(1), &[9; 32]).unwrap();
        }
        // Restart: Promoted must recover as Closed, never live.
        let mut s = store(tmp.path());
        assert!(s.live_record(&key(1)).is_none());
        // The resolved key cannot be reopened, and its claim stays consumed.
        assert_eq!(
            s.register_pending(key(1), [7; 32], 1, [2; 32], 3, 4),
            Err(OwnerSiteResolutionStoreError::DuplicateKey)
        );
        assert!(s.is_claim_present(&[9; 32]));
    }

    #[test]
    fn revoke_then_close_is_ordered_and_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = store(tmp.path());
        s.register_pending(key(1), [9; 32], 1, [2; 32], 3, 4).unwrap();
        s.promote(&key(1), &[9; 32]).unwrap();
        s.begin_revoke(&key(1), 5).unwrap();
        assert_eq!(
            s.live_record(&key(1)).map(OwnerSiteResolutionRecord::state),
            Some(OwnerSiteResolutionState::Revoking)
        );
        // Cancellation generation cannot move backwards.
        assert_eq!(
            s.begin_revoke(&key(1), 4),
            Err(OwnerSiteResolutionStoreError::GenerationRollback)
        );
        s.confirm_closed(&key(1)).unwrap();
        assert!(s.live_record(&key(1)).is_none());
        // Duplicate close is a no-op.
        s.confirm_closed(&key(1)).unwrap();
    }

    #[test]
    fn non_canonical_envelope_is_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        // Build an envelope with unsorted duplicate claims and persist it raw.
        let mut env = OwnerSitePromotionStateEnvelope::empty();
        env.consumed_claims = vec![[2; 32], [1; 32]]; // descending → non-canonical
        let path = OwnerSiteResolutionStore::state_path(tmp.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        storage::atomic_write_cbor(&path, &env).unwrap();
        assert_eq!(
            OwnerSiteResolutionStore::open(tmp.path()).map(|_| ()),
            Err(OwnerSiteResolutionStoreError::Unavailable)
        );
    }

    #[test]
    fn persisted_state_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let mut s = store(tmp.path());
        s.register_pending(key(1), [9; 32], 1, [2; 32], 3, 4).unwrap();
        let path = OwnerSiteResolutionStore::state_path(tmp.path());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the durable promotion-state file must be 0600");
    }

    #[test]
    fn resolution_key_changes_with_each_component() {
        // Every key component must independently distinguish the record.
        let base = key(1);
        let mut ws = base.clone();
        ws.ws_instance = [0xaa; 32];
        let mut cid = base.clone();
        cid.channel_id = [0xbb; 32];
        let mut ep = base.clone();
        ep.channel_epoch = base.channel_epoch + 1;
        let mut cb = base.clone();
        cb.channel_binding = [0xcc; 32];
        let mut hh = base.clone();
        hh.household = "other-household".to_string();
        for other in [ws, cid, ep, cb, hh] {
            assert_ne!(base, other, "each key component must change the key identity");
        }
    }

    #[test]
    fn commit_write_failure_fails_closed_and_leaves_state_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = store(tmp.path());
        s.register_pending(key(1), [9; 32], 1, [2; 32], 3, 4).unwrap();

        let before_len = s.envelope.records.len();
        let path = OwnerSiteResolutionStore::state_path(tmp.path());
        let disk_before = std::fs::read(&path).unwrap();

        // Inject a failure at the tmp-write stage. The durable write never
        // completes, so the (deliberately empty) candidate must NOT be adopted
        // and no partial file may survive.
        let injected = std::io::Error::new(std::io::ErrorKind::Other, "injected tmp write failure");
        let res =
            s.commit_with_injected_write_error(OwnerSitePromotionStateEnvelope::empty(), injected);

        assert_eq!(
            res,
            Err(OwnerSiteResolutionStoreError::Persist),
            "a durable-write failure must fail closed as Persist"
        );
        assert_eq!(
            s.envelope.records.len(),
            before_len,
            "in-memory state must be untouched after a failed write"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            disk_before,
            "on-disk state must be untouched — no partial write survives"
        );
    }
}
