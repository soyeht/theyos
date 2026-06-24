//! Live, sync-readable trust-context cache for the Product A `relay_stream` seam.
//!
//! C4a building block. It produces a [`RelayStreamIssuerTrust`] whose required
//! sync, infallible source reads a cached [`RelayStreamTrustContext`] (household
//! record + machine cert + projected mesh log) that is refreshed live via the
//! async [`RelayStreamTrustContextCache::refresh`]. This closes two C3.3 carries
//! as a testable API:
//!   * A: the seam's source closure is sync + infallible, so it is fed by a
//!     sync-readable cache (`RwLock`), never by `block_on` or a dead snapshot.
//!   * C: `load`/`refresh` fail closed with
//!     [`RelayStreamTrustContextCacheError::HouseholdUnavailable`] when no
//!     household is loaded; they never substitute a permissive/fake context.
//!
//! This module does NOT spawn a pool/listener, wire bootstrap/app state, drive
//! an invalidation loop, or emit `DirectoryDeviceRemoved`. A consumer (C4) owns
//! deciding when to call `refresh` (e.g. after a mesh-log append) and mounting
//! the resulting seam into the responder/pool.

use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use household_rs::household_mesh_log::MeshLogStore;

use crate::claw_share_relay_stream_issuer_trust::{
    RelayStreamIssuerTrust, RelayStreamTrustContext,
};
use crate::household_state::HouseholdState;

/// Sync-readable, live-refreshable cache of the `relay_stream` trust context.
///
/// Clone-cheap (`Arc` inside): clones share the same underlying cache, so a
/// [`RelayStreamIssuerTrust`] handed out earlier observes later refreshes.
#[derive(Clone)]
pub struct RelayStreamTrustContextCache {
    context: Arc<RwLock<RelayStreamTrustContext>>,
}

impl RelayStreamTrustContextCache {
    /// Build the cache from the current household identity and a fresh mesh-log
    /// projection. Fails closed if no household is loaded.
    pub async fn load(
        household: &HouseholdState,
        mesh_log: &MeshLogStore,
    ) -> Result<Self, RelayStreamTrustContextCacheError> {
        let context = build_context(household, mesh_log).await?;
        Ok(Self {
            context: Arc::new(RwLock::new(context)),
        })
    }

    /// Re-read the household identity and mesh-log projection and atomically
    /// replace the cached context. Fails closed if no household is loaded and
    /// leaves the previous context untouched (never substitutes a permissive
    /// one).
    pub async fn refresh(
        &self,
        household: &HouseholdState,
        mesh_log: &MeshLogStore,
    ) -> Result<(), RelayStreamTrustContextCacheError> {
        let context = build_context(household, mesh_log).await?;
        let mut guard = self.context.write().unwrap_or_else(PoisonError::into_inner);
        *guard = context;
        Ok(())
    }

    /// Produce a [`RelayStreamIssuerTrust`] whose source reads the *current*
    /// cached context on every verification; sync, infallible, no `Option`, no
    /// `block_on`, no snapshot. Verifications after a [`Self::refresh`] observe
    /// the new context, including a `DirectoryDeviceRemoved` kill switch or a
    /// member removal.
    #[must_use]
    pub fn issuer_trust(&self) -> RelayStreamIssuerTrust {
        let context = Arc::clone(&self.context);
        RelayStreamIssuerTrust::new(move || {
            context
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        })
    }
}

async fn build_context(
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
) -> Result<RelayStreamTrustContext, RelayStreamTrustContextCacheError> {
    let identity = household
        .current()
        .await
        .ok_or(RelayStreamTrustContextCacheError::HouseholdUnavailable)?;
    Ok(RelayStreamTrustContext {
        record: identity.record.clone(),
        cert: identity.cert.clone(),
        projection: mesh_log.project(),
    })
}

impl fmt::Debug for RelayStreamTrustContextCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamTrustContextCache")
            .field("context", &"redacted")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamTrustContextCacheError {
    #[error("household identity is unavailable")]
    HouseholdUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    use household_rs::LoadedIdentity;
    use household_rs::claw_share::SlotId;
    use household_rs::household_mesh_log::{LogEntry, MeshEvent};
    use household_rs::household_record::HouseholdRecord;
    use household_rs::ids::{MachineId, derive_household_id, derive_machine_id};
    use household_rs::issuer_trust::MachineIssuerError;
    use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
    use household_rs::machine_cert::{MachineCert, Platform, SignOptions};

    use crate::claw_share_relay_stream_contract::{
        RelayStreamClawStaticPublicKey, RelayStreamContractError, RelayStreamExpectedPath,
        RelayStreamOfferContract, RelayStreamOfferPayload, RelayStreamResource,
    };
    use crate::claw_share_rendezvous_stream_relay::RendezvousToken;

    const NOW: u64 = 1_800_000_000;

    fn hh() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0xAA; 32]).unwrap()
    }

    fn machine() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
    }

    fn other_machine() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0xCC; 32]).unwrap()
    }

    fn guest_pub() -> P256PublicKey {
        P256Keypair::from_secret_scalar(&[0x33; 32])
            .unwrap()
            .public()
    }

    fn machine_cert() -> MachineCert {
        MachineCert::sign(
            &hh(),
            &machine().public(),
            &SignOptions {
                hh_id: derive_household_id(&hh().public()),
                hostname: "engine-mac".to_string(),
                platform: Platform::Macos,
                joined_at: NOW - 1_000,
            },
        )
        .unwrap()
    }

    fn record_with(members: Vec<MachineId>) -> HouseholdRecord {
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: derive_household_id(&hh().public()),
            hh_pub: hh().public(),
            name: "home".to_string(),
            created_at: 0,
            shamir_k: 1,
            shamir_n: 1,
            members,
            is_follower: false,
        }
    }

    fn member_record() -> HouseholdRecord {
        record_with(vec![derive_machine_id(&machine().public())])
    }

    // A loaded identity whose household root (hh) is DISTINCT from the machine
    // signing key, so trust acceptance must go through the cert/membership path,
    // never the `signer_pub == hh_pub` root fallback.
    fn identity_with(record: HouseholdRecord) -> Arc<LoadedIdentity> {
        Arc::new(LoadedIdentity {
            record,
            cert: machine_cert(),
            hh_priv: None,
            m_priv: Box::new(machine()),
            backing: "software",
        })
    }

    fn household_with(record: HouseholdRecord) -> HouseholdState {
        HouseholdState::loaded(identity_with(record))
    }

    fn offer() -> RelayStreamOfferContract {
        let payload = RelayStreamOfferPayload::new(
            RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
            "claw_alpha".to_string(),
            SlotId([0x22; 16]),
            guest_pub(),
            RelayStreamResource::Pty,
            RelayStreamExpectedPath::RelayStream,
            "relay-stream://127.0.0.1:49152".to_string(),
            RelayStreamClawStaticPublicKey::try_new([0x77; 32]).unwrap(),
            NOW + 60,
        );
        RelayStreamOfferContract::sign(payload, &machine()).unwrap()
    }

    fn mesh_log_removing(device: &P256PublicKey) -> MeshLogStore {
        let mesh_log = MeshLogStore::new();
        let entry = LogEntry::sign(
            NOW,
            hh().public(),
            MeshEvent::DirectoryDeviceRemoved {
                device_pub: device.clone(),
            },
            &hh(),
        )
        .unwrap();
        mesh_log.append(entry).unwrap();
        mesh_log
    }

    #[tokio::test]
    async fn load_with_empty_household_fails_closed() {
        let result =
            RelayStreamTrustContextCache::load(&HouseholdState::empty(), &MeshLogStore::new())
                .await;

        assert!(matches!(
            result,
            Err(RelayStreamTrustContextCacheError::HouseholdUnavailable)
        ));
    }

    #[tokio::test]
    async fn load_with_member_household_accepts_machine_signed_offer() {
        let household = household_with(member_record());
        let cache = RelayStreamTrustContextCache::load(&household, &MeshLogStore::new())
            .await
            .unwrap();

        // Root ([0xAA]) is distinct from the offer signer machine ([0x11]):
        // acceptance is via cert + membership, not the root fallback.
        cache.issuer_trust().verify_offer(&offer(), NOW).unwrap();
    }

    #[tokio::test]
    async fn refresh_after_member_removed_rejects_via_live_record() {
        let household = household_with(member_record());
        let mesh_log = MeshLogStore::new();
        let cache = RelayStreamTrustContextCache::load(&household, &mesh_log)
            .await
            .unwrap();
        cache.issuer_trust().verify_offer(&offer(), NOW).unwrap();

        // Swap in a household whose members no longer include the machine, then
        // refresh: the same offer must now be rejected (record is read live).
        household
            .set_loaded(identity_with(record_with(vec![derive_machine_id(
                &other_machine().public(),
            )])))
            .await;
        cache.refresh(&household, &mesh_log).await.unwrap();

        assert!(matches!(
            cache.issuer_trust().verify_offer(&offer(), NOW),
            Err(RelayStreamContractError::IssuerUnauthorized(
                MachineIssuerError::NonMember
            ))
        ));
    }

    #[tokio::test]
    async fn refresh_after_directory_device_removed_rejects_via_live_projection() {
        let household = household_with(member_record());
        let cache = RelayStreamTrustContextCache::load(&household, &MeshLogStore::new())
            .await
            .unwrap();
        cache.issuer_trust().verify_offer(&offer(), NOW).unwrap();

        // Project a DirectoryDeviceRemoved for the issuing machine and refresh:
        // the same offer must now be rejected (projection is read live).
        cache
            .refresh(&household, &mesh_log_removing(&machine().public()))
            .await
            .unwrap();

        assert!(matches!(
            cache.issuer_trust().verify_offer(&offer(), NOW),
            Err(RelayStreamContractError::IssuerUnauthorized(
                MachineIssuerError::DeviceRemoved
            ))
        ));
    }

    #[tokio::test]
    async fn issuer_trust_reads_latest_context_after_refresh() {
        let household = household_with(member_record());
        let cache = RelayStreamTrustContextCache::load(&household, &MeshLogStore::new())
            .await
            .unwrap();

        // Take the seam BEFORE the refresh; it must observe the later context.
        let trust = cache.issuer_trust();
        trust.verify_offer(&offer(), NOW).unwrap();

        cache
            .refresh(&household, &mesh_log_removing(&machine().public()))
            .await
            .unwrap();

        // The pre-refresh `trust` now rejects: it reads the live cache, not a
        // captured snapshot.
        assert!(trust.verify_offer(&offer(), NOW).is_err());
    }

    #[tokio::test]
    async fn debug_and_error_do_not_leak_secret() {
        let household = household_with(member_record());
        let cache = RelayStreamTrustContextCache::load(&household, &MeshLogStore::new())
            .await
            .unwrap();

        let debug = format!("{cache:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("secret"));

        let error_debug = format!(
            "{:?}",
            RelayStreamTrustContextCacheError::HouseholdUnavailable
        );
        assert!(!error_debug.contains("private"));
        assert!(!error_debug.contains("secret"));
    }
}
