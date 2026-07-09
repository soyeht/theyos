//! Persisted Product A mobile Mesh-C model operations.
//!
//! This module is storage/API-adjacent only. It does not verify owner auth,
//! expose a network endpoint, open relay sessions, or mutate host networking.
//! Owner-sensitive methods are named `owner_approved_*` to make the future
//! caller boundary explicit: the caller must complete owner authorization
//! before invoking them.

use std::fmt;
use std::path::PathBuf;

use crate::claw_vpn_mobile_state::{
    ClawVpnMobileAclGrant, ClawVpnMobileClawId, ClawVpnMobileDeviceId, ClawVpnMobileMesh,
    ClawVpnMobileMeshError, ClawVpnMobileMeshRevocation, ClawVpnMobileOfferToken,
    ClawVpnMobileSessionId,
};
use crate::storage;
use rand::RngCore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClawVpnMobileMeshStoreErrorKind {
    Storage,
    Model,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnMobileMeshStoreError {
    kind: ClawVpnMobileMeshStoreErrorKind,
    operation: &'static str,
    storage_kind: Option<&'static str>,
    model_error: Option<ClawVpnMobileMeshError>,
}

impl fmt::Debug for ClawVpnMobileMeshStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnMobileMeshStoreError")
            .field("kind", &self.kind)
            .field("operation", &self.operation)
            .field("storage_kind", &self.storage_kind)
            .field("model_error", &self.model_error)
            .finish()
    }
}

impl fmt::Display for ClawVpnMobileMeshStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Product A mobile VPN mesh store operation failed")
    }
}

impl std::error::Error for ClawVpnMobileMeshStoreError {}

impl ClawVpnMobileMeshStoreError {
    fn storage(operation: &'static str, source: &crate::StorageError) -> Self {
        Self {
            kind: ClawVpnMobileMeshStoreErrorKind::Storage,
            operation,
            storage_kind: Some(source.kind()),
            model_error: None,
        }
    }

    fn model(operation: &'static str, source: ClawVpnMobileMeshError) -> Self {
        Self {
            kind: ClawVpnMobileMeshStoreErrorKind::Model,
            operation,
            storage_kind: None,
            model_error: Some(source),
        }
    }

    #[must_use]
    pub fn kind(&self) -> ClawVpnMobileMeshStoreErrorKind {
        self.kind
    }

    #[must_use]
    pub fn operation(&self) -> &'static str {
        self.operation
    }

    #[must_use]
    pub fn storage_kind(&self) -> Option<&'static str> {
        self.storage_kind
    }

    #[must_use]
    pub fn model_error(&self) -> Option<ClawVpnMobileMeshError> {
        self.model_error
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnMobileMeshStoreStatus {
    snapshot_present: bool,
    enrolled_device_count: usize,
    available_claw_count: usize,
    grant_count: usize,
    offer_count: usize,
    session_count: usize,
}

impl fmt::Debug for ClawVpnMobileMeshStoreStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnMobileMeshStoreStatus")
            .field("snapshot_present", &self.snapshot_present)
            .field("enrolled_device_count", &self.enrolled_device_count)
            .field("available_claw_count", &self.available_claw_count)
            .field("grant_count", &self.grant_count)
            .field("offer_count", &self.offer_count)
            .field("session_count", &self.session_count)
            .finish()
    }
}

impl ClawVpnMobileMeshStoreStatus {
    #[must_use]
    pub fn snapshot_present(&self) -> bool {
        self.snapshot_present
    }

    #[must_use]
    pub fn enrolled_device_count(&self) -> usize {
        self.enrolled_device_count
    }

    #[must_use]
    pub fn available_claw_count(&self) -> usize {
        self.available_claw_count
    }

    #[must_use]
    pub fn grant_count(&self) -> usize {
        self.grant_count
    }

    #[must_use]
    pub fn offer_count(&self) -> usize {
        self.offer_count
    }

    #[must_use]
    pub fn session_count(&self) -> usize {
        self.session_count
    }
}

#[derive(Clone)]
pub struct ClawVpnMobileMeshStore {
    state_dir: PathBuf,
    offer_ttl_secs: u64,
}

impl fmt::Debug for ClawVpnMobileMeshStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnMobileMeshStore")
            .field("state_dir", &"<redacted>")
            .field("offer_ttl_secs", &self.offer_ttl_secs)
            .finish()
    }
}

impl ClawVpnMobileMeshStore {
    pub fn new(
        state_dir: impl Into<PathBuf>,
        offer_ttl_secs: u64,
    ) -> Result<Self, ClawVpnMobileMeshStoreError> {
        ClawVpnMobileMesh::new(offer_ttl_secs)
            .map_err(|source| ClawVpnMobileMeshStoreError::model("new", source))?;
        Ok(Self {
            state_dir: state_dir.into(),
            offer_ttl_secs,
        })
    }

    pub fn load(&self) -> Result<ClawVpnMobileMesh, ClawVpnMobileMeshStoreError> {
        match storage::read_claw_vpn_mobile_mesh_snapshot(&self.state_dir)
            .map_err(|source| ClawVpnMobileMeshStoreError::storage("load", &source))?
        {
            Some(snapshot) => ClawVpnMobileMesh::from_snapshot(snapshot)
                .map_err(|source| ClawVpnMobileMeshStoreError::model("load", source)),
            None => ClawVpnMobileMesh::new(self.offer_ttl_secs)
                .map_err(|source| ClawVpnMobileMeshStoreError::model("load", source)),
        }
    }

    fn save(&self, mesh: &ClawVpnMobileMesh) -> Result<(), ClawVpnMobileMeshStoreError> {
        storage::write_claw_vpn_mobile_mesh_snapshot(&self.state_dir, &mesh.snapshot())
            .map_err(|source| ClawVpnMobileMeshStoreError::storage("save", &source))
    }

    pub fn owner_approved_delete_snapshot(&self) -> Result<(), ClawVpnMobileMeshStoreError> {
        storage::delete_claw_vpn_mobile_mesh_snapshot(&self.state_dir).map_err(|source| {
            ClawVpnMobileMeshStoreError::storage("owner_approved_delete_snapshot", &source)
        })
    }

    pub fn status(&self) -> Result<ClawVpnMobileMeshStoreStatus, ClawVpnMobileMeshStoreError> {
        let snapshot = storage::read_claw_vpn_mobile_mesh_snapshot(&self.state_dir)
            .map_err(|source| ClawVpnMobileMeshStoreError::storage("status", &source))?;
        let Some(snapshot) = snapshot else {
            return Ok(ClawVpnMobileMeshStoreStatus {
                snapshot_present: false,
                enrolled_device_count: 0,
                available_claw_count: 0,
                grant_count: 0,
                offer_count: 0,
                session_count: 0,
            });
        };
        let mesh = ClawVpnMobileMesh::from_snapshot(snapshot)
            .map_err(|source| ClawVpnMobileMeshStoreError::model("status", source))?;
        Ok(status_from_mesh(true, &mesh))
    }

    pub fn owner_approved_enroll_device(
        &self,
        device: ClawVpnMobileDeviceId,
    ) -> Result<bool, ClawVpnMobileMeshStoreError> {
        self.update("owner_approved_enroll_device", |mesh| {
            Ok(mesh.enroll_device(device))
        })
    }

    pub fn set_claw_available(
        &self,
        claw: ClawVpnMobileClawId,
    ) -> Result<bool, ClawVpnMobileMeshStoreError> {
        self.update("set_claw_available", |mesh| {
            Ok(mesh.set_claw_available(claw))
        })
    }

    pub fn set_claw_unavailable(
        &self,
        claw: &ClawVpnMobileClawId,
    ) -> Result<bool, ClawVpnMobileMeshStoreError> {
        self.update("set_claw_unavailable", |mesh| {
            Ok(mesh.set_claw_unavailable(claw))
        })
    }

    pub fn owner_approved_grant(
        &self,
        grant: ClawVpnMobileAclGrant,
    ) -> Result<bool, ClawVpnMobileMeshStoreError> {
        self.update("owner_approved_grant", |mesh| Ok(mesh.grant(grant)))
    }

    pub fn owner_approved_revoke(
        &self,
        grant: &ClawVpnMobileAclGrant,
    ) -> Result<ClawVpnMobileMeshRevocation, ClawVpnMobileMeshStoreError> {
        self.update("owner_approved_revoke", |mesh| Ok(mesh.revoke(grant)))
    }

    pub fn mint_offer_token(
        &self,
        grant: &ClawVpnMobileAclGrant,
        now_unix: u64,
    ) -> Result<ClawVpnMobileOfferToken, ClawVpnMobileMeshStoreError> {
        let token = generate_offer_token()
            .map_err(|source| ClawVpnMobileMeshStoreError::model("mint_offer_token", source))?;
        self.update("mint_offer_token", |mesh| {
            mesh.mint_offer_with_token(grant, now_unix, token.clone())?;
            Ok(token)
        })
    }

    pub fn consume_offer_token(
        &self,
        token: &ClawVpnMobileOfferToken,
        grant: &ClawVpnMobileAclGrant,
        now_unix: u64,
    ) -> Result<ClawVpnMobileSessionId, ClawVpnMobileMeshStoreError> {
        self.update("consume_offer_token", |mesh| {
            mesh.consume_offer_token(token, grant, now_unix)
        })
    }

    pub fn close_session(
        &self,
        session_id: ClawVpnMobileSessionId,
    ) -> Result<(), ClawVpnMobileMeshStoreError> {
        self.update("close_session", |mesh| mesh.close_session(session_id))
    }

    fn update<T>(
        &self,
        operation: &'static str,
        apply: impl FnOnce(&mut ClawVpnMobileMesh) -> Result<T, ClawVpnMobileMeshError>,
    ) -> Result<T, ClawVpnMobileMeshStoreError> {
        let mut mesh = self.load()?;
        let result = apply(&mut mesh)
            .map_err(|source| ClawVpnMobileMeshStoreError::model(operation, source))?;
        self.save(&mesh)?;
        Ok(result)
    }
}

fn generate_offer_token() -> Result<ClawVpnMobileOfferToken, ClawVpnMobileMeshError> {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    ClawVpnMobileOfferToken::try_new(hex::encode(bytes))
}

fn status_from_mesh(
    snapshot_present: bool,
    mesh: &ClawVpnMobileMesh,
) -> ClawVpnMobileMeshStoreStatus {
    let snapshot = mesh.snapshot();
    ClawVpnMobileMeshStoreStatus {
        snapshot_present,
        enrolled_device_count: snapshot.enrolled_device_count(),
        available_claw_count: snapshot.available_claw_count(),
        grant_count: snapshot.grant_count(),
        offer_count: snapshot.offer_count(),
        session_count: snapshot.session_count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member() -> crate::claw_vpn_mobile_state::ClawVpnMobileMemberId {
        crate::claw_vpn_mobile_state::ClawVpnMobileMemberId::try_new("member-alpha").unwrap()
    }

    fn device() -> ClawVpnMobileDeviceId {
        ClawVpnMobileDeviceId::try_new("device-alpha").unwrap()
    }

    fn claw() -> ClawVpnMobileClawId {
        ClawVpnMobileClawId::try_new("claw-alpha").unwrap()
    }

    fn grant() -> ClawVpnMobileAclGrant {
        ClawVpnMobileAclGrant::new(member(), device(), claw())
    }

    #[test]
    fn store_persists_offer_lifecycle_without_reopening_consumed_offer() {
        let td = tempfile::tempdir().unwrap();
        let store = ClawVpnMobileMeshStore::new(td.path(), 60).unwrap();
        let grant = grant();

        assert!(!store.status().unwrap().snapshot_present());
        assert!(store.owner_approved_enroll_device(device()).unwrap());
        assert!(store.set_claw_available(claw()).unwrap());
        assert!(store.owner_approved_grant(grant.clone()).unwrap());
        let offer_token = store.mint_offer_token(&grant, 10).unwrap();
        let session = store.consume_offer_token(&offer_token, &grant, 20).unwrap();

        let status = store.status().unwrap();
        assert!(status.snapshot_present());
        assert_eq!(status.enrolled_device_count(), 1);
        assert_eq!(status.available_claw_count(), 1);
        assert_eq!(status.grant_count(), 1);
        assert_eq!(status.offer_count(), 1);
        assert_eq!(status.session_count(), 1);
        assert!(store.load().unwrap().has_active_session(session));
        assert_eq!(
            store
                .consume_offer_token(&offer_token, &grant, 21)
                .unwrap_err()
                .model_error(),
            Some(ClawVpnMobileMeshError::OfferAlreadyConsumed)
        );
    }

    #[test]
    fn store_denies_mint_until_owner_approved_grant_is_persisted() {
        let td = tempfile::tempdir().unwrap();
        let store = ClawVpnMobileMeshStore::new(td.path(), 60).unwrap();
        let grant = grant();

        assert!(store.owner_approved_enroll_device(device()).unwrap());
        assert!(store.set_claw_available(claw()).unwrap());
        let err = store.mint_offer_token(&grant, 10).unwrap_err();
        assert_eq!(err.kind(), ClawVpnMobileMeshStoreErrorKind::Model);
        assert_eq!(err.operation(), "mint_offer_token");
        assert_eq!(
            err.model_error(),
            Some(ClawVpnMobileMeshError::Unauthorized)
        );
        assert_eq!(store.status().unwrap().offer_count(), 0);

        assert!(store.owner_approved_grant(grant.clone()).unwrap());
        let offer_token = store.mint_offer_token(&grant, 20).unwrap();
        let session = store.consume_offer_token(&offer_token, &grant, 21).unwrap();
        assert!(store.load().unwrap().has_active_session(session));
        assert_eq!(
            store
                .consume_offer_token(&offer_token, &grant, 22)
                .unwrap_err()
                .model_error(),
            Some(ClawVpnMobileMeshError::OfferAlreadyConsumed)
        );
    }

    #[test]
    fn store_update_error_after_in_memory_mutation_does_not_persist() {
        let td = tempfile::tempdir().unwrap();
        let store = ClawVpnMobileMeshStore::new(td.path(), 60).unwrap();

        let err = store
            .update::<()>("test_mutating_error", |mesh| {
                assert!(mesh.enroll_device(device()));
                Err(ClawVpnMobileMeshError::Unauthorized)
            })
            .unwrap_err();

        assert_eq!(err.kind(), ClawVpnMobileMeshStoreErrorKind::Model);
        assert_eq!(err.operation(), "test_mutating_error");
        assert_eq!(
            err.model_error(),
            Some(ClawVpnMobileMeshError::Unauthorized)
        );
        assert!(!store.status().unwrap().snapshot_present());
    }

    #[test]
    fn store_revoke_closes_matching_session_and_persists_counts() {
        let td = tempfile::tempdir().unwrap();
        let store = ClawVpnMobileMeshStore::new(td.path(), 60).unwrap();
        let grant = grant();
        assert!(store.owner_approved_enroll_device(device()).unwrap());
        assert!(store.set_claw_available(claw()).unwrap());
        assert!(store.owner_approved_grant(grant.clone()).unwrap());
        let offer_token = store.mint_offer_token(&grant, 10).unwrap();
        let session = store.consume_offer_token(&offer_token, &grant, 20).unwrap();
        assert!(store.load().unwrap().has_active_session(session));

        let revocation = store.owner_approved_revoke(&grant).unwrap();
        assert!(revocation.grant_removed());
        assert_eq!(revocation.closed_session_count(), 1);
        assert!(!store.load().unwrap().has_active_session(session));
        let status = store.status().unwrap();
        assert_eq!(status.grant_count(), 0);
        assert_eq!(status.session_count(), 0);
    }

    #[test]
    fn store_debug_and_error_display_are_redacted() {
        let td = tempfile::tempdir().unwrap();
        let store = ClawVpnMobileMeshStore::new(td.path(), 60).unwrap();
        let grant = grant();
        let debug = format!("{store:?} {grant:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("device-alpha"));
        assert!(!debug.contains("claw-alpha"));
        assert!(!debug.contains(td.path().to_string_lossy().as_ref()));

        let err = store.mint_offer_token(&grant, 10).unwrap_err();
        let display = err.to_string();
        let debug = format!("{err:?}");
        assert_eq!(display, "Product A mobile VPN mesh store operation failed");
        assert!(!debug.contains("device-alpha"));
        assert!(!debug.contains("claw-alpha"));
        assert!(!debug.contains(td.path().to_string_lossy().as_ref()));
    }
}
