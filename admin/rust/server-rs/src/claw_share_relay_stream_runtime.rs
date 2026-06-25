//! Default-off live wiring skeleton for Product A `relay_stream`.
//!
//! C6 building block. This module composes the dormant `relay_stream` pieces from
//! caller-injected live app-state handles, but does not mount itself into
//! bootstrap, advertise any capability, wire claim-ack, or touch the guest/iOS
//! path. The default config is disabled; when disabled, assembly returns before
//! loading household state, reading the offer store, creating a Noise key,
//! spawning tasks, or dialing a relay.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use household_rs::claw_share::ClawShareSlotStore;
use household_rs::claw_share_data_tunnel::{ClawTargetRouter, ReplayGuard};
use household_rs::household_mesh_log::MeshLogStore;
use household_rs::ids::HouseholdId;
use keystore_rs::KeystoreBackend;
use tokio::sync::Notify;

use crate::claw_share_relay_stream_admission::RelayStreamAdmission;
use crate::claw_share_relay_stream_contract::{RelayStreamContractError, RelayStreamOfferContract};
use crate::claw_share_relay_stream_offer_store::RelayStreamOfferStoreError;
use crate::claw_share_relay_stream_responder_config::{
    DEFAULT_RELAY_STREAM_RESPONDER_AUTH_DEADLINE, DEFAULT_RELAY_STREAM_RESPONDER_IDLE_TIMEOUT,
    RelayStreamResponderConfig,
};
use crate::claw_share_relay_stream_responder_params::{
    RelayStreamResponderParamsError, assemble_relay_stream_responder_params,
};
use crate::claw_share_relay_stream_responder_reverse_connect::{
    RelayStreamResponderReverseConnectConfig, RelayStreamResponderReverseConnectError,
};
use crate::claw_share_relay_stream_reverse_connect_binding::bind_relay_stream_reverse_connect;
use crate::claw_share_relay_stream_reverse_connect_pool::{
    RelayStreamOfferResyncDriverHandle, RelayStreamReverseConnectBindingBuildError,
    RelayStreamReverseConnectBindingFactory, RelayStreamReverseConnectPoolConfig,
    RelayStreamReverseConnectPoolError, spawn_relay_stream_offer_resync_driver,
};
use crate::claw_share_relay_stream_trust_context_cache::RelayStreamTrustContextCacheError;
use crate::claw_share_relay_stream_trust_context_health::{
    RelayStreamTrustContextRefreshPolicy, RelayStreamTrustContextRuntime,
};
use crate::claw_share_relay_stream_trust_refresh_driver::{
    RelayStreamTrustRefreshConfig, RelayStreamTrustRefreshConfigError,
    RelayStreamTrustRefreshDriverHandle, spawn_relay_stream_trust_refresh_driver,
};
use crate::household_state::HouseholdState;

/// Default-off composition config for the live `relay_stream` skeleton.
#[derive(Debug, Clone)]
pub struct RelayStreamLiveConfig {
    pub enabled: bool,
    pub responder: RelayStreamResponderConfig,
    pub reverse_connect: RelayStreamResponderReverseConnectConfig,
    pub trust_policy: RelayStreamTrustContextRefreshPolicy,
    pub trust_refresh: RelayStreamTrustRefreshConfig,
    pub pool: RelayStreamReverseConnectPoolConfig,
    /// How often the offer re-sync driver re-reads the store and reconciles
    /// workers so claim-provisioned offers are served without a restart.
    pub resync_tick: Duration,
}

impl Default for RelayStreamLiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            responder: RelayStreamResponderConfig::new(
                "127.0.0.1:49152",
                Some(
                    crate::claw_share_relay_stream_noise_keystore::DEFAULT_RELAY_STREAM_NOISE_KEY_ID,
                ),
                DEFAULT_RELAY_STREAM_RESPONDER_AUTH_DEADLINE,
                DEFAULT_RELAY_STREAM_RESPONDER_IDLE_TIMEOUT,
            )
            .unwrap(),
            reverse_connect: RelayStreamResponderReverseConnectConfig::default(),
            trust_policy: RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(60), 3)
                .unwrap(),
            trust_refresh: RelayStreamTrustRefreshConfig::new(Duration::from_secs(10)),
            pool: RelayStreamReverseConnectPoolConfig::default(),
            resync_tick: Duration::from_secs(30),
        }
    }
}

/// Caller-supplied live handles and factories.
///
/// The state handles are cloned into the driver/pool closures; callers remain
/// responsible for passing the same live app-state instances the rest of the
/// engine uses. Router factories are injected so this skeleton has no opinion
/// about real PTY/ClawSite backends yet.
pub struct RelayStreamLiveInputs<'a, P, S> {
    pub state_dir: PathBuf,
    pub household: HouseholdState,
    pub mesh_log: Arc<MeshLogStore>,
    pub keystore_backend: &'a dyn KeystoreBackend,
    pub household_id: HouseholdId,
    pub slots: Arc<ClawShareSlotStore>,
    pub replay: Arc<ReplayGuard>,
    pub pty_router_factory: Arc<dyn Fn() -> P + Send + Sync>,
    pub clawsite_router_factory: Arc<dyn Fn() -> S + Send + Sync>,
    pub refresh_trigger: Arc<Notify>,
    pub now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// Abortable handles for the pieces this skeleton spawns.
pub struct RelayStreamLiveHandles {
    trust_runtime: Arc<RelayStreamTrustContextRuntime>,
    refresh_driver: RelayStreamTrustRefreshDriverHandle,
    resync_driver: RelayStreamOfferResyncDriverHandle,
}

impl RelayStreamLiveHandles {
    pub fn shutdown(&self) {
        self.refresh_driver.shutdown();
        self.resync_driver.shutdown();
    }

    #[must_use]
    pub fn offer_count(&self) -> usize {
        self.resync_driver.offer_count()
    }

    #[must_use]
    pub fn pool_task_count(&self) -> usize {
        self.resync_driver.task_count()
    }

    #[must_use]
    pub fn trust_runtime(&self) -> &Arc<RelayStreamTrustContextRuntime> {
        &self.trust_runtime
    }
}

impl Drop for RelayStreamLiveHandles {
    fn drop(&mut self) {
        self.refresh_driver.abort();
        self.resync_driver.shutdown();
    }
}

impl fmt::Debug for RelayStreamLiveHandles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamLiveHandles")
            .field("trust_runtime", &self.trust_runtime)
            .field("refresh_driver", &"redacted")
            .field("resync_driver", &self.resync_driver)
            .finish()
    }
}

/// Assemble the `relay_stream` live skeleton.
///
/// `Ok(None)` is the default-off path and intentionally returns before any
/// state read, keystore operation, task spawn, or network dial. `Ok(Some(_))`
/// builds the trust runtime once, shares that same `Arc` between the admission
/// factory and the refresh driver, snapshots active offers from the local store,
/// and starts the reverse-connect pool over that static offer set.
pub async fn assemble_relay_stream_live<P, S>(
    inputs: RelayStreamLiveInputs<'_, P, S>,
    config: RelayStreamLiveConfig,
) -> Result<Option<RelayStreamLiveHandles>, RelayStreamLiveError>
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
{
    if !config.enabled {
        return Ok(None);
    }

    let reverse_connect = config.reverse_connect.validate()?;
    let pool_config = config.pool.validate()?;
    let now = (inputs.now_unix)();
    let trust_runtime = Arc::new(
        RelayStreamTrustContextRuntime::load(
            &inputs.household,
            inputs.mesh_log.as_ref(),
            now,
            config.trust_policy,
        )
        .await?,
    );
    let admission = RelayStreamAdmission::new(Arc::clone(&trust_runtime));
    let trust = admission.admit(now)?;

    let params = Arc::new(
        assemble_relay_stream_responder_params(
            &config.responder,
            inputs.keystore_backend,
            admission.clone(),
        )
        .await?,
    );

    let binding_factory = build_binding_factory(
        admission,
        inputs.household_id,
        Arc::clone(&inputs.slots),
        Arc::clone(&inputs.replay),
        Arc::clone(&inputs.pty_router_factory),
        Arc::clone(&inputs.clawsite_router_factory),
        Arc::clone(&inputs.now_unix),
    );

    let refresh_driver = spawn_relay_stream_trust_refresh_driver(
        Arc::clone(&trust_runtime),
        inputs.household,
        Arc::clone(&inputs.mesh_log),
        config.trust_refresh,
        Arc::clone(&inputs.refresh_trigger),
        Arc::clone(&inputs.now_unix),
    )?;

    // The re-sync driver subsumes the static pool: an initial synchronous resync
    // seeds workers for the offers on disk now, and each tick re-reads the store
    // so claim-provisioned offers are served without a restart.
    let resync_driver = spawn_relay_stream_offer_resync_driver(
        inputs.state_dir,
        trust,
        config.resync_tick,
        pool_config,
        reverse_connect,
        params,
        binding_factory,
        inputs.now_unix,
    )?;

    Ok(Some(RelayStreamLiveHandles {
        trust_runtime,
        refresh_driver,
        resync_driver,
    }))
}

#[allow(clippy::too_many_arguments)]
fn build_binding_factory<P, S>(
    admission: RelayStreamAdmission,
    household_id: HouseholdId,
    slots: Arc<ClawShareSlotStore>,
    replay: Arc<ReplayGuard>,
    pty_router_factory: Arc<dyn Fn() -> P + Send + Sync>,
    clawsite_router_factory: Arc<dyn Fn() -> S + Send + Sync>,
    now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> Arc<RelayStreamReverseConnectBindingFactory<P, S>>
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
{
    Arc::new(move |offer: Arc<RelayStreamOfferContract>, now| {
        if offer.payload.not_after <= now {
            return Err(RelayStreamReverseConnectBindingBuildError::Expired);
        }
        let trust = admission.admit(now).map_err(|error| {
            RelayStreamReverseConnectBindingBuildError::Unhealthy(error.to_string())
        })?;
        let router_clock = Arc::clone(&now_unix);
        Ok(bind_relay_stream_reverse_connect(
            offer,
            trust,
            household_id.clone(),
            Arc::clone(&slots),
            Arc::clone(&replay),
            pty_router_factory(),
            clawsite_router_factory(),
            move || router_clock(),
        ))
    })
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamLiveError {
    #[error("relay stream trust context unavailable: {0}")]
    TrustContext(#[from] RelayStreamTrustContextCacheError),

    #[error("relay stream admission failed: {0}")]
    Admission(#[from] crate::claw_share_relay_stream_admission::RelayStreamAdmissionError),

    #[error("relay stream offer store failed: {0}")]
    OfferStore(#[from] RelayStreamOfferStoreError),

    #[error("relay stream responder params failed: {0}")]
    ResponderParams(#[from] RelayStreamResponderParamsError),

    #[error("relay stream trust refresh driver failed: {0}")]
    TrustRefresh(#[from] RelayStreamTrustRefreshConfigError),

    #[error("relay stream reverse-connect failed: {0}")]
    ReverseConnect(#[from] RelayStreamResponderReverseConnectError),

    #[error("relay stream reverse-connect pool failed: {0}")]
    Pool(#[from] RelayStreamReverseConnectPoolError),

    #[error("relay stream contract failed: {0}")]
    Contract(#[from] RelayStreamContractError),
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use household_rs::claw_share_data_tunnel::TcpStreamRouter;
    use household_rs::ids::derive_household_id;
    use keystore_rs::FileKeystore;
    use tokio::net::TcpListener;
    use tokio::time::{sleep, timeout};

    use crate::claw_share_relay_stream_contract::{
        RelayStreamExpectedPath, RelayStreamOfferMintInput, RelayStreamResource,
    };
    use crate::claw_share_relay_stream_noise_keystore::{
        DEFAULT_RELAY_STREAM_NOISE_KEY_ID, RelayStreamNoiseKeyStore,
    };
    use crate::claw_share_relay_stream_offer_store::RelayStreamOfferStore;
    use crate::claw_share_relay_stream_responder_config::RelayStreamResponderConfig;
    use crate::claw_share_relay_stream_test_support::{
        data_tunnel_credential, data_tunnel_store, now_unix, owner_pub, owner_signer,
        relay_stream_household_state, relay_stream_issuer_trust, rendezvous_token,
    };

    fn backend(dir: &tempfile::TempDir) -> FileKeystore {
        FileKeystore::new(dir.path(), "com.soyeht.theyos.test")
    }

    fn enabled_config(relay_addr: std::net::SocketAddr) -> RelayStreamLiveConfig {
        RelayStreamLiveConfig {
            enabled: true,
            responder: RelayStreamResponderConfig::new(
                "127.0.0.1:49152",
                Some(DEFAULT_RELAY_STREAM_NOISE_KEY_ID),
                Duration::from_millis(200),
                Duration::from_secs(60),
            )
            .unwrap(),
            reverse_connect: RelayStreamResponderReverseConnectConfig {
                relay_addr,
                connect_timeout: Duration::from_millis(50),
                hello_timeout: Duration::from_millis(50),
                allow_non_loopback_relay_addr: false,
            },
            trust_policy: RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(2), 2)
                .unwrap(),
            trust_refresh: RelayStreamTrustRefreshConfig::new(Duration::from_millis(100)),
            pool: RelayStreamReverseConnectPoolConfig {
                per_offer_parked: 1,
                max_total_connections: 1,
                backoff: crate::claw_share_relay_stream_reverse_connect_pool::RelayStreamReverseConnectBackoffPolicy::new(
                    Duration::from_millis(25),
                    Duration::from_millis(50),
                )
                .unwrap(),
            },
            resync_tick: Duration::from_secs(30),
        }
    }

    fn inputs<'a>(
        state_dir: impl AsRef<Path>,
        backend: &'a dyn KeystoreBackend,
    ) -> RelayStreamLiveInputs<'a, TcpStreamRouter, TcpStreamRouter> {
        inputs_with(
            state_dir,
            backend,
            relay_stream_household_state(),
            Arc::new(MeshLogStore::new()),
            Arc::new(Notify::new()),
        )
    }

    fn inputs_with<'a>(
        state_dir: impl AsRef<Path>,
        backend: &'a dyn KeystoreBackend,
        household: HouseholdState,
        mesh_log: Arc<MeshLogStore>,
        refresh_trigger: Arc<Notify>,
    ) -> RelayStreamLiveInputs<'a, TcpStreamRouter, TcpStreamRouter> {
        RelayStreamLiveInputs {
            state_dir: state_dir.as_ref().to_path_buf(),
            household,
            mesh_log,
            keystore_backend: backend,
            household_id: derive_household_id(&owner_pub()),
            slots: data_tunnel_store(),
            replay: Arc::new(ReplayGuard::new()),
            pty_router_factory: Arc::new(|| TcpStreamRouter::new("127.0.0.1:1")),
            clawsite_router_factory: Arc::new(|| TcpStreamRouter::new("127.0.0.1:1")),
            refresh_trigger,
            now_unix: Arc::new(now_unix),
        }
    }

    async fn unused_loopback_addr() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    fn seed_offer(
        state_dir: &Path,
        backend: &dyn KeystoreBackend,
        resource: RelayStreamResource,
        token_label: u8,
    ) {
        let keypair = RelayStreamNoiseKeyStore::new(backend)
            .get_or_create(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
            .unwrap();
        let credential = data_tunnel_credential();
        let mut store =
            RelayStreamOfferStore::load(state_dir, &relay_stream_issuer_trust(), now_unix())
                .unwrap();
        store
            .put_minted(
                RelayStreamOfferMintInput {
                    rendezvous_token: rendezvous_token(token_label),
                    credential: &credential,
                    resource,
                    expected_path: RelayStreamExpectedPath::RelayStream,
                    relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
                    claw_static_pub: keypair.public_key().clone(),
                    not_after: now_unix() + 600,
                    now_unix: now_unix(),
                },
                &owner_signer(),
                &relay_stream_issuer_trust(),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn live_wiring_default_off_has_no_side_effects() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir);
        let config = RelayStreamLiveConfig::default();

        let result = assemble_relay_stream_live(inputs(dir.path(), &backend), config)
            .await
            .unwrap();

        assert!(result.is_none());
        assert!(
            !crate::claw_share_relay_stream_offer_store::relay_stream_offer_store_path(dir.path())
                .exists()
        );
        assert!(
            !backend
                .path_for(
                    &RelayStreamNoiseKeyStore::account_for_key_id(
                        DEFAULT_RELAY_STREAM_NOISE_KEY_ID
                    )
                    .unwrap()
                )
                .exists()
        );
    }

    #[tokio::test]
    async fn live_wiring_enabled_empty_store_spawns_zero_offer_pool() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir);
        let config = enabled_config(unused_loopback_addr().await);

        let handles = assemble_relay_stream_live(inputs(dir.path(), &backend), config)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(handles.offer_count(), 0);
        assert_eq!(handles.pool_task_count(), 0);
        handles.trust_runtime().ensure_healthy(now_unix()).unwrap();
        handles.shutdown();
    }

    #[tokio::test]
    async fn live_wiring_top_level_enabled_uses_default_responder_params() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir);
        let mut config = RelayStreamLiveConfig {
            enabled: true,
            ..RelayStreamLiveConfig::default()
        };
        config.reverse_connect.relay_addr = unused_loopback_addr().await;

        let handles = assemble_relay_stream_live(inputs(dir.path(), &backend), config)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(handles.offer_count(), 0);
        assert_eq!(handles.pool_task_count(), 0);
        handles.shutdown();
    }

    #[tokio::test]
    async fn live_wiring_lists_active_offers_for_pool_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir);
        seed_offer(dir.path(), &backend, RelayStreamResource::Pty, 0x42);
        seed_offer(dir.path(), &backend, RelayStreamResource::ClawSite, 0x43);
        let config = enabled_config(unused_loopback_addr().await);

        let handles = assemble_relay_stream_live(inputs(dir.path(), &backend), config)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(handles.offer_count(), 2);
        assert_eq!(handles.pool_task_count(), 2);
        handles.shutdown();
    }

    #[tokio::test]
    async fn live_wiring_driver_refreshes_same_runtime_from_live_household() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir);
        let household = relay_stream_household_state();
        let mesh_log = Arc::new(MeshLogStore::new());
        let trigger = Arc::new(Notify::new());
        let mut config = enabled_config(unused_loopback_addr().await);
        config.trust_policy =
            RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(60), 1).unwrap();
        config.trust_refresh = RelayStreamTrustRefreshConfig::new(Duration::from_secs(10));

        let handles = assemble_relay_stream_live(
            inputs_with(
                dir.path(),
                &backend,
                household.clone(),
                Arc::clone(&mesh_log),
                Arc::clone(&trigger),
            ),
            config,
        )
        .await
        .unwrap()
        .unwrap();
        handles.trust_runtime().ensure_healthy(now_unix()).unwrap();

        household.clear().await;
        trigger.notify_one();
        let error = timeout(Duration::from_secs(1), async {
            loop {
                if let Err(error) = handles.trust_runtime().ensure_healthy(now_unix()) {
                    break error;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        assert!(matches!(
            error,
            crate::claw_share_relay_stream_trust_context_health::RelayStreamTrustContextHealthError::RefreshFailing { .. }
        ));
        handles.shutdown();
    }

    #[tokio::test]
    async fn live_wiring_rejects_bad_refresh_cadence_before_spawning_pool() {
        let dir = tempfile::tempdir().unwrap();
        let backend = backend(&dir);
        let mut config = enabled_config(unused_loopback_addr().await);
        config.trust_policy =
            RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(1), 2).unwrap();
        config.trust_refresh = RelayStreamTrustRefreshConfig::new(Duration::from_secs(1));

        let error = assemble_relay_stream_live(inputs(dir.path(), &backend), config)
            .await
            .unwrap_err();

        assert!(matches!(error, RelayStreamLiveError::TrustRefresh(_)));
    }
}
