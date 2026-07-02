//! Local owner-write-only store for Product A `relay_stream` offers.
//!
//! This store is not a trust anchor. It persists owner-minted offers and
//! re-verifies them against the expected owner on read. Guest/relay paths do not
//! write raw contracts here; normal writes go through `mint_relay_stream_offer`.
//! Owner-key CRL/revocation remains a consumer boundary outside this module.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use household_rs::claw_share::SlotId;
use household_rs::keys::IdentityKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::claw_share_relay_stream_contract::{
    RelayStreamContractError, RelayStreamOfferContract, RelayStreamOfferMintInput,
    RelayStreamResource, mint_relay_stream_offer,
};
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;

const RELAY_STREAM_OFFER_STORE_VERSION: u8 = 1;
const RELAY_STREAM_OFFER_STORE_KIND: &str = "claw-share/relay-stream-offer-store";
const RELAY_STREAM_OFFER_STORE_FILE: &str = "claw_share_relay_stream_offers.cbor";

/// Fail-closed caps on the offer store — the backstop behind the per-source rate
/// limit on the relay-offer request endpoints. A flood of Public/Group offer
/// requests cannot grow the store without bound: at a cap a NEW offer is rejected
/// (`StoreFull`) rather than evicting a valid one. Re-minting an existing
/// `(slot_id, resource)` key replaces in place and is never capped.
const MAX_RELAY_STREAM_OFFERS: usize = 4096;
const MAX_RELAY_STREAM_OFFERS_PER_CLAW: usize = 64;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayStreamOfferStoreKey {
    pub slot_id: SlotId,
    pub resource: RelayStreamResource,
}

impl RelayStreamOfferStoreKey {
    #[must_use]
    pub fn new(slot_id: SlotId, resource: RelayStreamResource) -> Self {
        Self { slot_id, resource }
    }
}

impl fmt::Debug for RelayStreamOfferStoreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamOfferStoreKey")
            .field("slot_id", &self.slot_id)
            .field("resource", &self.resource)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRelayStreamOfferStore {
    v: u8,
    kind: String,
    offers: Vec<PersistedRelayStreamOfferEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRelayStreamOfferEntry {
    key: RelayStreamOfferStoreKey,
    offer: RelayStreamOfferContract,
}

pub struct RelayStreamOfferStore {
    path: PathBuf,
    offers: BTreeMap<RelayStreamOfferStoreKey, RelayStreamOfferContract>,
}

impl fmt::Debug for RelayStreamOfferStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamOfferStore")
            .field("path", &self.path)
            .field("offer_count", &self.offers.len())
            .finish()
    }
}

impl RelayStreamOfferStore {
    pub fn load(
        state_dir: impl AsRef<Path>,
        trust: &RelayStreamIssuerTrust,
        now_unix: u64,
    ) -> Result<Self, RelayStreamOfferStoreError> {
        let path = relay_stream_offer_store_path(state_dir.as_ref());
        let persisted =
            household_rs::storage::read_optional_cbor::<PersistedRelayStreamOfferStore>(&path)
                .map_err(RelayStreamOfferStoreError::Storage)?;

        let mut store = Self {
            path,
            offers: BTreeMap::new(),
        };
        let Some(persisted) = persisted else {
            return Ok(store);
        };
        if persisted.v != RELAY_STREAM_OFFER_STORE_VERSION {
            return Err(RelayStreamOfferStoreError::VersionUnsupported(persisted.v));
        }
        if persisted.kind != RELAY_STREAM_OFFER_STORE_KIND {
            return Err(RelayStreamOfferStoreError::KindMismatch(persisted.kind));
        }

        let mut pruned = false;
        for entry in persisted.offers {
            let computed_key = Self::key_for_offer(&entry.offer);
            if entry.key != computed_key {
                pruned = true;
                continue;
            }
            if trust.verify_offer(&entry.offer, now_unix).is_err() {
                pruned = true;
                continue;
            }
            store.offers.insert(entry.key, entry.offer);
        }
        if pruned {
            store.persist()?;
        }
        Ok(store)
    }

    pub fn put_minted(
        &mut self,
        input: RelayStreamOfferMintInput<'_>,
        owner_key: &dyn IdentityKey,
        trust: &RelayStreamIssuerTrust,
    ) -> Result<RelayStreamOfferContract, RelayStreamOfferStoreError> {
        let now_unix = input.now_unix;
        let offer = mint_relay_stream_offer(input, owner_key)?;
        trust.verify_offer(&offer, now_unix)?;
        let key = Self::key_for_offer(&offer);
        self.offers.insert(key, offer.clone());
        self.persist()?;
        Ok(offer)
    }

    /// Fase E2/E3: store an ALREADY-SIGNED offer. Group/Public offers are minted
    /// without a `GuestCredential`, so they can't go through [`put_minted`]; the
    /// caller mints them (with a UNIQUE `slot_id`) and stores them here. Verified
    /// under `trust` before insert; keyed by `(slot_id, resource)` like every
    /// offer (hence the caller's unique-slot-id requirement to avoid collisions).
    pub fn put_signed(
        &mut self,
        offer: RelayStreamOfferContract,
        trust: &RelayStreamIssuerTrust,
        now_unix: u64,
    ) -> Result<RelayStreamOfferContract, RelayStreamOfferStoreError> {
        trust.verify_offer(&offer, now_unix)?;
        let key = Self::key_for_offer(&offer);
        // Fail-closed caps apply only to a NEW key — re-minting the same
        // (slot_id, resource) replaces in place and is bounded already. Prune
        // expired/untrusted entries first so the caps count only live offers,
        // then REJECT on overflow; never evict a valid offer to admit a new one.
        if !self.offers.contains_key(&key) {
            self.prune_inactive(trust, now_unix);
            if self.offers.len() >= MAX_RELAY_STREAM_OFFERS {
                return Err(RelayStreamOfferStoreError::StoreFull {
                    scope: "global",
                    max: MAX_RELAY_STREAM_OFFERS,
                    current: self.offers.len(),
                });
            }
            let claw_id = &offer.payload.claw_id;
            let per_claw = self
                .offers
                .values()
                .filter(|existing| existing.payload.claw_id == *claw_id)
                .count();
            if per_claw >= MAX_RELAY_STREAM_OFFERS_PER_CLAW {
                return Err(RelayStreamOfferStoreError::StoreFull {
                    scope: "per-claw",
                    max: MAX_RELAY_STREAM_OFFERS_PER_CLAW,
                    current: per_claw,
                });
            }
        }
        self.offers.insert(key, offer.clone());
        self.persist()?;
        Ok(offer)
    }

    /// Drop in-memory entries that no longer derive from their key or fail the
    /// trust seam (expired / revoked / bad signature). No persist — callers that
    /// mutate persist afterwards. Mirrors `list_active`'s prune without cloning.
    fn prune_inactive(&mut self, trust: &RelayStreamIssuerTrust, now_unix: u64) {
        let mut drop_keys = Vec::new();
        for (key, offer) in &self.offers {
            if *key != Self::key_for_offer(offer) || trust.verify_offer(offer, now_unix).is_err() {
                drop_keys.push(key.clone());
            }
        }
        for key in drop_keys {
            self.offers.remove(&key);
        }
    }

    pub fn get_active(
        &mut self,
        slot_id: &SlotId,
        resource: RelayStreamResource,
        trust: &RelayStreamIssuerTrust,
        now_unix: u64,
    ) -> Result<Option<RelayStreamOfferContract>, RelayStreamOfferStoreError> {
        let key = RelayStreamOfferStoreKey::new(slot_id.clone(), resource);
        let Some(offer) = self.offers.get(&key).cloned() else {
            return Ok(None);
        };
        if trust.verify_offer(&offer, now_unix).is_ok() {
            return Ok(Some(offer));
        }
        self.offers.remove(&key);
        self.persist()?;
        Ok(None)
    }

    /// Return every stored offer that is still active and issuer-trusted, in
    /// deterministic store-key order, pruning any that fail.
    ///
    /// This is the read a future pool uses to learn the set of offers to park.
    /// Like `load`/`get_active`, the store is a cache, not an authority: each
    /// survivor is re-checked against the caller-supplied trust seam
    /// (`verify_offer` = issuer trust + signature + `not_after`/path), and the
    /// persisted key is defensively recomputed and compared. Anything that
    /// mismatches its key, fails verification, has expired, or whose issuer was
    /// revoked is dropped from memory; a single `persist` at the end records the
    /// prune if anything was removed. The trust seam comes from the caller; no
    /// authority is embedded here.
    pub fn list_active(
        &mut self,
        trust: &RelayStreamIssuerTrust,
        now_unix: u64,
    ) -> Result<Vec<RelayStreamOfferContract>, RelayStreamOfferStoreError> {
        let mut active = Vec::new();
        let mut prune_keys = Vec::new();
        for (key, offer) in &self.offers {
            // Defensive: a persisted key that no longer derives from the offer
            // (corruption/tamper) is pruned, exactly as on load.
            if *key != Self::key_for_offer(offer) {
                prune_keys.push(key.clone());
                continue;
            }
            if trust.verify_offer(offer, now_unix).is_ok() {
                active.push(offer.clone());
            } else {
                prune_keys.push(key.clone());
            }
        }
        if !prune_keys.is_empty() {
            for key in &prune_keys {
                self.offers.remove(key);
            }
            self.persist()?;
        }
        Ok(active)
    }

    pub fn remove(
        &mut self,
        slot_id: &SlotId,
        resource: RelayStreamResource,
    ) -> Result<bool, RelayStreamOfferStoreError> {
        let key = RelayStreamOfferStoreKey::new(slot_id.clone(), resource);
        let removed = self.offers.remove(&key).is_some();
        if removed {
            self.persist()?;
        }
        Ok(removed)
    }

    pub fn remove_slot(&mut self, slot_id: &SlotId) -> Result<usize, RelayStreamOfferStoreError> {
        let before = self.offers.len();
        self.offers.retain(|key, _| &key.slot_id != slot_id);
        let removed = before - self.offers.len();
        if removed > 0 {
            self.persist()?;
        }
        Ok(removed)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.offers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.offers.is_empty()
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&self) -> Result<(), RelayStreamOfferStoreError> {
        let offers = self
            .offers
            .iter()
            .map(|(key, offer)| PersistedRelayStreamOfferEntry {
                key: key.clone(),
                offer: offer.clone(),
            })
            .collect();
        let persisted = PersistedRelayStreamOfferStore {
            v: RELAY_STREAM_OFFER_STORE_VERSION,
            kind: RELAY_STREAM_OFFER_STORE_KIND.to_string(),
            offers,
        };
        ensure_parent_owner_only(&self.path)?;
        household_rs::storage::atomic_write_cbor(&self.path, &persisted)
            .map_err(RelayStreamOfferStoreError::Storage)
    }

    fn key_for_offer(offer: &RelayStreamOfferContract) -> RelayStreamOfferStoreKey {
        RelayStreamOfferStoreKey::new(offer.payload.slot_id.clone(), offer.payload.resource)
    }
}

#[must_use]
pub fn relay_stream_offer_store_path(state_dir: &Path) -> PathBuf {
    household_rs::storage::household_dir(state_dir).join(RELAY_STREAM_OFFER_STORE_FILE)
}

fn ensure_parent_owner_only(path: &Path) -> Result<(), RelayStreamOfferStoreError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|error| RelayStreamOfferStoreError::Io {
        path: parent.to_path_buf(),
        operation: "create-store-dir",
        message: error.to_string(),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|error| {
            RelayStreamOfferStoreError::Io {
                path: parent.to_path_buf(),
                operation: "chmod-store-dir",
                message: error.to_string(),
            }
        })?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum RelayStreamOfferStoreError {
    #[error("unsupported relay stream offer store version: {0}")]
    VersionUnsupported(u8),

    #[error("relay stream offer store kind mismatch: {0}")]
    KindMismatch(String),

    #[error("relay stream offer store contract error: {0}")]
    Contract(#[from] RelayStreamContractError),

    #[error("relay stream offer store storage error: {0}")]
    Storage(#[source] household_rs::StorageError),

    #[error("relay stream offer store full ({scope}): {current}/{max}")]
    StoreFull {
        scope: &'static str,
        max: usize,
        current: usize,
    },

    #[error("relay stream offer store {operation} failed at {path}: {message}")]
    Io {
        path: PathBuf,
        operation: &'static str,
        message: String,
    },
}

#[cfg(test)]
pub(crate) fn write_raw_offers_for_test(
    state_dir: &Path,
    entries: Vec<(RelayStreamOfferStoreKey, RelayStreamOfferContract)>,
) -> Result<(), RelayStreamOfferStoreError> {
    let persisted = PersistedRelayStreamOfferStore {
        v: RELAY_STREAM_OFFER_STORE_VERSION,
        kind: RELAY_STREAM_OFFER_STORE_KIND.to_string(),
        offers: entries
            .into_iter()
            .map(|(key, offer)| PersistedRelayStreamOfferEntry { key, offer })
            .collect(),
    };
    household_rs::storage::atomic_write_cbor(&relay_stream_offer_store_path(state_dir), &persisted)
        .map_err(RelayStreamOfferStoreError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::claw_share::GuestCredential;
    use household_rs::claw_share::SlotId;
    use household_rs::household_mesh_log::{
        DirectoryDeviceStatus, ProjectedDirectoryDevice, ProjectedState,
    };
    use household_rs::household_record::HouseholdRecord;
    use household_rs::ids::{derive_household_id, derive_machine_id};
    use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
    use household_rs::machine_cert::{MachineCert, Platform, SignOptions};
    use household_rs::person_cert::derive_person_id;

    use crate::claw_share_relay_stream_contract::{
        RelayStreamClawStaticPublicKey, RelayStreamExpectedPath,
    };
    use crate::claw_share_relay_stream_issuer_trust::{
        RelayStreamIssuerTrust, RelayStreamTrustContext,
    };
    use crate::claw_share_rendezvous_stream_relay::RendezvousToken;

    const NOW: u64 = 1_800_000_000;
    const NOT_AFTER: u64 = NOW + 60;
    const SLOT: SlotId = SlotId([0x22; 16]);
    const SLOT_B: SlotId = SlotId([0x23; 16]);
    const SLOT_C: SlotId = SlotId([0x24; 16]);
    const SLOT_D: SlotId = SlotId([0x25; 16]);
    const SLOT_E: SlotId = SlotId([0x26; 16]);
    const SLOT_F: SlotId = SlotId([0x27; 16]);

    fn owner() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
    }

    fn owner_pub() -> P256PublicKey {
        owner().public()
    }

    fn guest() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap()
    }

    fn other_guest_pub() -> P256PublicKey {
        P256Keypair::from_secret_scalar(&[0x44; 32])
            .unwrap()
            .public()
    }

    fn attacker() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap()
    }

    fn hh() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0xAA; 32]).unwrap()
    }

    fn other_machine() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0xBB; 32]).unwrap()
    }

    fn machine_cert_for(machine_pub: &P256PublicKey) -> MachineCert {
        MachineCert::sign(
            &hh(),
            machine_pub,
            &SignOptions {
                hh_id: derive_household_id(&hh().public()),
                hostname: "engine-mac".into(),
                platform: Platform::Macos,
                joined_at: NOW - 1_000,
            },
        )
        .unwrap()
    }

    fn record_for(machine_pub: &P256PublicKey) -> HouseholdRecord {
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: derive_household_id(&hh().public()),
            hh_pub: hh().public(),
            name: "home".into(),
            created_at: 0,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![derive_machine_id(machine_pub)],
            is_follower: false,
        }
    }

    fn trust_for(machine: P256Keypair) -> RelayStreamIssuerTrust {
        let machine_pub = machine.public();
        RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
            record: record_for(&machine_pub),
            cert: machine_cert_for(&machine_pub),
            projection: ProjectedState::default(),
        })
    }

    // Authorizes the offer signer `owner()` (the engine machine key m_priv).
    fn trust() -> RelayStreamIssuerTrust {
        trust_for(owner())
    }

    // Authorizes a DIFFERENT machine, so offers signed by `owner()` fail the
    // issuer check and are pruned: the trust-resolver analogue of "wrong owner".
    fn untrusted() -> RelayStreamIssuerTrust {
        trust_for(other_machine())
    }

    fn trust_revoked() -> RelayStreamIssuerTrust {
        RelayStreamIssuerTrust::new(|| {
            let mut projection = ProjectedState::default();
            projection.directory_devices.insert(
                owner_pub().as_bytes().to_vec(),
                ProjectedDirectoryDevice {
                    label: "engine-mac".to_string(),
                    status: DirectoryDeviceStatus::Removed,
                },
            );
            RelayStreamTrustContext {
                record: record_for(&owner_pub()),
                cert: machine_cert_for(&owner_pub()),
                projection,
            }
        })
    }

    fn credential_for(slot_id: SlotId) -> GuestCredential {
        GuestCredential::sign(
            derive_household_id(&owner_pub()),
            derive_person_id(&owner_pub()),
            owner_pub(),
            "claw_alpha".to_string(),
            guest().public(),
            slot_id,
            NOW - 60,
            NOW + 600,
            &owner(),
        )
        .unwrap()
    }

    fn credential() -> GuestCredential {
        credential_for(SLOT)
    }

    fn token(label: u8) -> RendezvousToken {
        RendezvousToken::try_new(vec![label; 16]).unwrap()
    }

    fn static_pub(label: u8) -> RelayStreamClawStaticPublicKey {
        RelayStreamClawStaticPublicKey::try_new([label; 32]).unwrap()
    }

    fn mint_input_for(
        credential: &GuestCredential,
        resource: RelayStreamResource,
        token_label: u8,
    ) -> RelayStreamOfferMintInput<'_> {
        RelayStreamOfferMintInput {
            rendezvous_token: token(token_label),
            credential,
            resource,
            expected_path: RelayStreamExpectedPath::RelayStream,
            relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
            claw_static_pub: static_pub(0x77),
            not_after: NOT_AFTER,
            now_unix: NOW,
        }
    }

    fn temp_state_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn put_signed_enforces_per_claw_cap_fail_closed() {
        use crate::claw_share_relay_stream_contract::mint_relay_stream_group_offer;

        let dir = temp_state_dir();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();

        let mint = |i: usize, claw: &str| {
            let mut slot = [0u8; 16];
            slot[0] = (i & 0xff) as u8;
            slot[1] = ((i >> 8) & 0xff) as u8;
            mint_relay_stream_group_offer(
                token((i & 0xff) as u8),
                SlotId(slot),
                "g".to_string(),
                "g_a".to_string(),
                guest().public(),
                claw.to_string(),
                RelayStreamResource::Pty,
                "relay-stream://127.0.0.1:49152".to_string(),
                static_pub(0x33),
                NOT_AFTER,
                NOW,
                &owner(),
            )
            .unwrap()
        };

        // Fill exactly to the per-claw cap with unique slot_ids for one claw.
        for i in 0..MAX_RELAY_STREAM_OFFERS_PER_CLAW {
            store
                .put_signed(mint(i, "claw_cap"), &trust(), NOW)
                .unwrap();
        }
        // A new offer for the SAME claw is rejected fail-closed, not stored.
        let err = store
            .put_signed(mint(9_999, "claw_cap"), &trust(), NOW)
            .unwrap_err();
        assert!(matches!(
            err,
            RelayStreamOfferStoreError::StoreFull {
                scope: "per-claw",
                ..
            }
        ));
        // A different claw still admits — the cap is per-claw, not a global lock.
        store
            .put_signed(mint(10_000, "claw_other"), &trust(), NOW)
            .unwrap();
    }

    #[test]
    fn relay_stream_offer_store_empty_load_when_file_missing() {
        let dir = temp_state_dir();

        let store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();

        assert!(store.is_empty());
        assert_eq!(
            store.path(),
            relay_stream_offer_store_path(dir.path()).as_path()
        );
        assert!(!store.path().exists());
    }

    #[test]
    fn relay_stream_offer_store_put_minted_persists_and_reloads_active_offer() {
        let dir = temp_state_dir();
        let credential = credential();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();

        let offer = store
            .put_minted(
                mint_input_for(&credential, RelayStreamResource::Pty, 0x42),
                &owner(),
                &trust(),
            )
            .unwrap();

        assert_eq!(offer.payload.guest_device_pub, credential.guest_device_pub);
        assert_eq!(offer.payload.slot_id, credential.slot_id);
        assert_eq!(offer.payload.claw_id, credential.claw_id);
        trust().verify_offer(&offer, NOW).unwrap();
        offer
            .verify_for_audience(&owner_pub(), &credential.guest_device_pub, NOW)
            .unwrap();

        let mut reloaded = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        let active = reloaded
            .get_active(&SLOT, RelayStreamResource::Pty, &trust(), NOW)
            .unwrap()
            .unwrap();
        assert_eq!(active, offer);
    }

    #[test]
    fn relay_stream_offer_store_ignores_tampered_or_attacker_signed_disk_offers() {
        let dir = temp_state_dir();
        let credential = credential();
        let mut owner_store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        let mut tampered = owner_store
            .put_minted(
                mint_input_for(&credential, RelayStreamResource::Pty, 0x42),
                &owner(),
                &trust(),
            )
            .unwrap();
        tampered.payload.guest_device_pub = other_guest_pub();
        let attacker_offer = mint_relay_stream_offer(
            mint_input_for(&credential, RelayStreamResource::ClawSite, 0x43),
            &owner(),
        )
        .unwrap();
        let attacker_offer =
            RelayStreamOfferContract::sign(attacker_offer.payload.clone(), &attacker()).unwrap();
        write_raw_offers_for_test(
            dir.path(),
            vec![
                (
                    RelayStreamOfferStoreKey::new(SLOT, RelayStreamResource::Pty),
                    tampered,
                ),
                (
                    RelayStreamOfferStoreKey::new(SLOT, RelayStreamResource::ClawSite),
                    attacker_offer,
                ),
            ],
        )
        .unwrap();

        let mut loaded = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();

        assert!(loaded.is_empty());
        assert!(
            loaded
                .get_active(&SLOT, RelayStreamResource::Pty, &trust(), NOW)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn relay_stream_offer_store_expired_offer_is_pruned_on_load_and_get() {
        let dir = temp_state_dir();
        let credential = credential();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        let offer = store
            .put_minted(
                mint_input_for(&credential, RelayStreamResource::Pty, 0x42),
                &owner(),
                &trust(),
            )
            .unwrap();
        assert_eq!(offer.payload.not_after, NOT_AFTER);

        let mut loaded_after_expiry =
            RelayStreamOfferStore::load(dir.path(), &trust(), NOT_AFTER).unwrap();
        assert!(loaded_after_expiry.is_empty());
        assert!(
            loaded_after_expiry
                .get_active(&SLOT, RelayStreamResource::Pty, &trust(), NOT_AFTER)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn relay_stream_offer_store_unauthorized_issuer_prunes_stored_offer() {
        let dir = temp_state_dir();
        let credential = credential();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        store
            .put_minted(
                mint_input_for(&credential, RelayStreamResource::Pty, 0x42),
                &owner(),
                &trust(),
            )
            .unwrap();

        let mut loaded = RelayStreamOfferStore::load(dir.path(), &untrusted(), NOW).unwrap();

        assert!(loaded.is_empty());
        assert!(
            loaded
                .get_active(&SLOT, RelayStreamResource::Pty, &untrusted(), NOW)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn relay_stream_offer_store_list_active_empty_store_returns_empty_vec() {
        let dir = temp_state_dir();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();

        let active = store.list_active(&trust(), NOW).unwrap();

        assert!(active.is_empty());
        assert!(store.is_empty());
        assert!(!store.path().exists());
    }

    #[test]
    fn relay_stream_offer_store_list_active_returns_valid_offers_in_key_order() {
        let dir = temp_state_dir();
        let credential = credential();
        let credential_b = credential_for(SLOT_B);
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        let pty = store
            .put_minted(
                RelayStreamOfferMintInput {
                    not_after: NOW + 300,
                    ..mint_input_for(&credential, RelayStreamResource::Pty, 0x42)
                },
                &owner(),
                &trust(),
            )
            .unwrap();
        let clawsite = store
            .put_minted(
                RelayStreamOfferMintInput {
                    not_after: NOW + 300,
                    ..mint_input_for(&credential_b, RelayStreamResource::ClawSite, 0x43)
                },
                &owner(),
                &trust(),
            )
            .unwrap();

        let active = store.list_active(&trust(), NOW).unwrap();

        assert_eq!(active, vec![pty, clawsite]);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn relay_stream_offer_store_list_active_prunes_invalid_entries_and_persists_once() {
        let dir = temp_state_dir();
        let credential = credential();
        let credential_b = credential_for(SLOT_B);
        let credential_c = credential_for(SLOT_C);
        let credential_d = credential_for(SLOT_D);
        let credential_e = credential_for(SLOT_E);
        let credential_f = credential_for(SLOT_F);
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        let valid_pty = mint_relay_stream_offer(
            RelayStreamOfferMintInput {
                not_after: NOW + 300,
                ..mint_input_for(&credential, RelayStreamResource::Pty, 0x41)
            },
            &owner(),
        )
        .unwrap();
        let valid_clawsite = mint_relay_stream_offer(
            RelayStreamOfferMintInput {
                not_after: NOW + 300,
                ..mint_input_for(&credential_b, RelayStreamResource::ClawSite, 0x42)
            },
            &owner(),
        )
        .unwrap();
        let expired = mint_relay_stream_offer(
            mint_input_for(&credential_c, RelayStreamResource::Pty, 0x43),
            &owner(),
        )
        .unwrap();
        let mut tampered = mint_relay_stream_offer(
            RelayStreamOfferMintInput {
                not_after: NOW + 300,
                ..mint_input_for(&credential_d, RelayStreamResource::ClawSite, 0x44)
            },
            &owner(),
        )
        .unwrap();
        tampered.payload.guest_device_pub = other_guest_pub();
        let attacker_payload = mint_relay_stream_offer(
            RelayStreamOfferMintInput {
                not_after: NOW + 300,
                ..mint_input_for(&credential_e, RelayStreamResource::Pty, 0x45)
            },
            &owner(),
        )
        .unwrap()
        .payload;
        let attacker_offer = RelayStreamOfferContract::sign(attacker_payload, &attacker()).unwrap();
        let wrong_key_offer = mint_relay_stream_offer(
            RelayStreamOfferMintInput {
                not_after: NOW + 300,
                ..mint_input_for(&credential_f, RelayStreamResource::Pty, 0x46)
            },
            &owner(),
        )
        .unwrap();

        for offer in [
            valid_pty.clone(),
            valid_clawsite.clone(),
            expired,
            tampered,
            attacker_offer,
        ] {
            store
                .offers
                .insert(RelayStreamOfferStore::key_for_offer(&offer), offer);
        }
        store.offers.insert(
            RelayStreamOfferStoreKey::new(SLOT_F, RelayStreamResource::ClawSite),
            wrong_key_offer,
        );

        let active = store.list_active(&trust(), NOT_AFTER).unwrap();

        assert_eq!(active, vec![valid_pty.clone(), valid_clawsite.clone()]);
        assert_eq!(store.len(), 2);
        let mut reloaded = RelayStreamOfferStore::load(dir.path(), &trust(), NOT_AFTER).unwrap();
        assert_eq!(
            reloaded.list_active(&trust(), NOT_AFTER).unwrap(),
            vec![valid_pty, valid_clawsite]
        );
    }

    #[test]
    fn relay_stream_offer_store_list_active_prunes_revoked_issuer() {
        let dir = temp_state_dir();
        let credential = credential();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        store
            .put_minted(
                RelayStreamOfferMintInput {
                    not_after: NOW + 300,
                    ..mint_input_for(&credential, RelayStreamResource::Pty, 0x42)
                },
                &owner(),
                &trust(),
            )
            .unwrap();

        let active = store.list_active(&trust_revoked(), NOW).unwrap();

        assert!(active.is_empty());
        assert!(store.is_empty());
        let reloaded = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        assert!(reloaded.is_empty());
    }

    #[test]
    fn relay_stream_offer_store_upsert_replaces_same_key_and_keeps_different_resource() {
        let dir = temp_state_dir();
        let credential = credential();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        let first = store
            .put_minted(
                mint_input_for(&credential, RelayStreamResource::Pty, 0x42),
                &owner(),
                &trust(),
            )
            .unwrap();
        let second = store
            .put_minted(
                mint_input_for(&credential, RelayStreamResource::Pty, 0x43),
                &owner(),
                &trust(),
            )
            .unwrap();
        let clawsite = store
            .put_minted(
                mint_input_for(&credential, RelayStreamResource::ClawSite, 0x44),
                &owner(),
                &trust(),
            )
            .unwrap();
        let ip_tunnel = store
            .put_minted(
                mint_input_for(&credential, RelayStreamResource::IpTunnel, 0x45),
                &owner(),
                &trust(),
            )
            .unwrap();

        assert_ne!(
            first.payload.rendezvous_token,
            second.payload.rendezvous_token
        );
        assert_eq!(store.len(), 3);
        let mut reloaded = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        let pty = reloaded
            .get_active(&SLOT, RelayStreamResource::Pty, &trust(), NOW)
            .unwrap()
            .unwrap();
        let site = reloaded
            .get_active(&SLOT, RelayStreamResource::ClawSite, &trust(), NOW)
            .unwrap()
            .unwrap();
        let vpn = reloaded
            .get_active(&SLOT, RelayStreamResource::IpTunnel, &trust(), NOW)
            .unwrap()
            .unwrap();
        assert_eq!(pty, second);
        assert_eq!(site, clawsite);
        assert_eq!(vpn, ip_tunnel);
    }

    #[test]
    fn relay_stream_offer_store_remove_key_and_slot_persist() {
        let dir = temp_state_dir();
        let credential = credential();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        store
            .put_minted(
                mint_input_for(&credential, RelayStreamResource::Pty, 0x42),
                &owner(),
                &trust(),
            )
            .unwrap();
        store
            .put_minted(
                mint_input_for(&credential, RelayStreamResource::ClawSite, 0x43),
                &owner(),
                &trust(),
            )
            .unwrap();

        assert!(store.remove(&SLOT, RelayStreamResource::Pty).unwrap());
        assert!(!store.remove(&SLOT, RelayStreamResource::Pty).unwrap());
        let mut reloaded = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        assert!(
            reloaded
                .get_active(&SLOT, RelayStreamResource::Pty, &trust(), NOW)
                .unwrap()
                .is_none()
        );
        assert!(
            reloaded
                .get_active(&SLOT, RelayStreamResource::ClawSite, &trust(), NOW)
                .unwrap()
                .is_some()
        );

        assert_eq!(reloaded.remove_slot(&SLOT).unwrap(), 1);
        let reloaded_again = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        assert!(reloaded_again.is_empty());
    }

    #[test]
    fn relay_stream_offer_store_debug_does_not_leak_token() {
        let dir = temp_state_dir();
        let credential = credential();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        store
            .put_minted(
                RelayStreamOfferMintInput {
                    rendezvous_token: RendezvousToken::try_new(b"0123456789abcdef").unwrap(),
                    ..mint_input_for(&credential, RelayStreamResource::Pty, 0x42)
                },
                &owner(),
                &trust(),
            )
            .unwrap();

        let debug = format!("{store:?}");

        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("30313233343536373839616263646566"));
        assert!(debug.contains("offer_count"));
    }

    #[cfg(unix)]
    #[test]
    fn relay_stream_offer_store_file_permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_state_dir();
        let credential = credential();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust(), NOW).unwrap();
        store
            .put_minted(
                mint_input_for(&credential, RelayStreamResource::Pty, 0x42),
                &owner(),
                &trust(),
            )
            .unwrap();

        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(store.path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }
}
