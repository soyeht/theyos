//! Shared household identity state for axum handlers.

use std::sync::Arc;

use household_rs::LoadedIdentity;
use tokio::sync::RwLock;

/// Wrapper around a fully-loaded household identity. The handler layer only
/// reads from this. The daemon can start cold and hot-load the identity after
/// `theyos install` writes it, so the slot is updated behind an async lock.
pub type SharedHouseholdIdentity = Arc<LoadedIdentity>;

pub type SharedOwnerAuthState = Arc<household_rs::HouseholdAuthState>;

/// Both identity fields in a single lock so `clear()` can zero them atomically.
/// Eliminates the race window where a concurrent reader could see identity=None
/// but `owner_auth=Some` between two separate write-lock acquisitions.
struct Inner {
    identity: Option<SharedHouseholdIdentity>,
    owner_auth: Option<SharedOwnerAuthState>,
}

/// State the household handlers see — `None` only during the narrow window
/// between HTTP listener startup and bootstrap completion.
#[derive(Clone)]
pub struct HouseholdState {
    inner: Arc<RwLock<Inner>>,
}

impl HouseholdState {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                identity: None,
                owner_auth: None,
            })),
        }
    }

    #[must_use]
    pub fn loaded(id: SharedHouseholdIdentity) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                identity: Some(id),
                owner_auth: None,
            })),
        }
    }

    #[must_use]
    pub fn loaded_with_owner_auth(
        id: SharedHouseholdIdentity,
        owner_auth: Option<SharedOwnerAuthState>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                identity: Some(id),
                owner_auth,
            })),
        }
    }

    pub async fn current(&self) -> Option<SharedHouseholdIdentity> {
        self.inner.read().await.identity.clone()
    }

    pub async fn set_loaded(&self, id: SharedHouseholdIdentity) {
        self.inner.write().await.identity = Some(id);
    }

    /// Set identity and owner auth atomically. Eliminates the race window in the
    /// hot-load watcher where `identity=Some` but `owner_auth=None` was briefly visible.
    pub async fn set_loaded_with_owner_auth(
        &self,
        id: SharedHouseholdIdentity,
        owner_auth: Option<SharedOwnerAuthState>,
    ) {
        let mut guard = self.inner.write().await;
        guard.identity = Some(id);
        guard.owner_auth = owner_auth;
    }

    pub async fn current_owner_auth(&self) -> Option<SharedOwnerAuthState> {
        self.inner.read().await.owner_auth.clone()
    }

    pub async fn set_owner_auth(&self, auth: SharedOwnerAuthState) {
        self.inner.write().await.owner_auth = Some(auth);
    }

    /// Zero out all in-memory household state atomically (called during teardown
    /// so no stale cert material remains reachable until the process restarts).
    /// Single lock acquisition ensures no reader can observe a partial clear.
    pub async fn clear(&self) {
        let mut guard = self.inner.write().await;
        guard.identity = None;
        guard.owner_auth = None;
    }
}
