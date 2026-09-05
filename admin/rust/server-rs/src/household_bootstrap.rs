//! Household identity bring-up at server startup (Phase 1 cryptographic
//! skeleton).
//!
//! Wires together:
//!
//! - `try_load_existing` — load persisted `HouseholdRecord` + `MachineCert`
//!   (or stay cold until `theyos install` runs).
//! - [`PairDeviceWindow`](household_rs::pair_device::PairDeviceWindow) — single-use
//!   pair-receiving state machine, persisted as `pair_device_window.cbor`.
//! - Listener interface enumeration (loopback + LAN + Tailscale), narrowed by
//!   `HouseholdExposurePolicy`, and the 60s refresh loop (FR-008).
//! - Bonjour publisher (FR-017) — only announces once identity is loaded.

use crate::bonjour_trust::BrowserConfig;
use crate::claw_share_relay_offer_challenge::{GroupClaimNonceTable, RelayOfferChallengeTable};
use crate::claw_share_relay_stream_abuse::RelayAbuseState;
use crate::handlers_bootstrap::{BootstrapHandlerState, BootstrapStateArc};
use crate::handlers_claw_share;
use crate::handlers_device_pairing;
use crate::handlers_household;
use crate::handlers_household_claws;
use crate::handlers_household_guest_image;
use crate::handlers_household_roster;
use crate::handlers_owner_events;
use crate::handlers_pair_device;
use crate::handlers_pair_machine;
use crate::household_listener;
use crate::household_listener::InterfaceClass;
use crate::household_state::HouseholdState;
use crate::state::SharedState;
use crate::time_util;
use crate::{bonjour_browser, bonjour_publisher, setup_beacon, startup_wiring};
use household_rs::KeyBackingPolicy;
use household_rs::bootstrap::{
    recover_interrupted_household_teardown_under_lifecycle, try_load_existing_under_lifecycle,
};
use household_rs::bootstrap_state::{self, BootstrapState};
use household_rs::claw_share::ClawShareSlotStore;
use household_rs::claw_share_data_tunnel::ReplayGuard;
use household_rs::household_lifecycle::{
    HouseholdLifecycleLock, HouseholdLifecycleLockError, LifecycleWriteGuard,
};
use household_rs::household_mesh_log::MeshLogStore;
use household_rs::owner_events::{OwnerEventLog, OwnerEventsBroadcaster, log_path};
use household_rs::pair_machine::PairMachineWindow;
use nostr_relay_rs::nostr::Keys;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tower::ServiceExt;
use tracing::info;

const TERMINAL_REPLAY_REBIND_INTERVAL: Duration = Duration::from_millis(100);

/// Global bootstrap state — shared by all handlers that need to read or
/// transition the onboarding state machine. Set once at engine startup.
static BOOTSTRAP_STATE: OnceLock<BootstrapStateArc> = OnceLock::new();

const HOUSEHOLD_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(30);
const PHASE3_TASK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct Phase3RuntimeController {
    inner: Arc<RwLock<Option<Phase3RuntimeBundle>>>,
    router: Phase3RouterSlot,
    state_dir: PathBuf,
    household: HouseholdState,
    pair_machine_window: Arc<PairMachineWindow>,
    key_policy: KeyBackingPolicy,
    shared_state: Option<SharedState>,
}

#[derive(Clone)]
struct Phase3RouterSlot {
    state_dir: Arc<PathBuf>,
    router: Arc<RwLock<Option<Phase3RouterEntry>>>,
}

#[derive(Clone)]
struct Phase3RouterEntry {
    generation: household_rs::household_lifecycle::HouseholdLifecycleGenerationV1,
    router: axum::Router,
    cancel: tokio::sync::watch::Sender<bool>,
    active: Arc<Phase3ActiveLeases>,
}

#[derive(Default)]
struct Phase3ActiveLeases {
    count: std::sync::atomic::AtomicUsize,
    idle: tokio::sync::Notify,
}

struct Phase3ActiveLease(Arc<Phase3ActiveLeases>);

impl Drop for Phase3ActiveLease {
    fn drop(&mut self) {
        if self
            .0
            .count
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.0.idle.notify_waiters();
        }
    }
}

impl Phase3RouterSlot {
    fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir: Arc::new(state_dir),
            router: Arc::new(RwLock::new(None)),
        }
    }

    async fn publish(
        &self,
        generation: household_rs::household_lifecycle::HouseholdLifecycleGenerationV1,
        router: axum::Router,
    ) {
        let (cancel, _) = tokio::sync::watch::channel(false);
        *self.router.write().await = Some(Phase3RouterEntry {
            generation,
            router,
            cancel,
            active: Arc::new(Phase3ActiveLeases::default()),
        });
    }

    async fn retire(&self) {
        let entry = self.router.write().await.take();
        let Some(entry) = entry else {
            return;
        };
        let _ = entry.cancel.send(true);
        loop {
            // Register the waiter before observing the counter so the final
            // lease cannot drop between the load and `notified()` creation.
            let idle = entry.active.idle.notified();
            if entry
                .active
                .count
                .load(std::sync::atomic::Ordering::Acquire)
                == 0
            {
                break;
            }
            idle.await;
        }
    }

    async fn route_or_reject(&self, request: axum::extract::Request) -> axum::response::Response {
        let (entry, _lease) = {
            let slot = self.router.read().await;
            let Some(entry) = slot.as_ref() else {
                return handlers_pair_machine::pre_household_reject().await;
            };
            entry
                .active
                .count
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            (entry.clone(), Phase3ActiveLease(Arc::clone(&entry.active)))
        };
        let state_dir = Arc::clone(&self.state_dir);
        let lifecycle_guard = tokio::task::spawn_blocking(move || {
            let lifecycle = HouseholdLifecycleLock::open_verified(state_dir.as_ref())?;
            let deadline = Instant::now()
                .checked_add(HOUSEHOLD_LIFECYCLE_TIMEOUT)
                .ok_or(HouseholdLifecycleLockError::Io)?;
            lifecycle.lock_shared_until(deadline)
        })
        .await;
        let Ok(Ok(lifecycle_guard)) = lifecycle_guard else {
            return handlers_pair_machine::pre_household_reject().await;
        };
        if lifecycle_guard.lifecycle_generation().ok().flatten() != Some(entry.generation) {
            return handlers_pair_machine::pre_household_reject().await;
        }
        let mut cancel = entry.cancel.subscribe();
        let response = tokio::select! {
            response = entry.router.oneshot(request) => {
                response.unwrap_or_else(|error| match error {})
            }
            changed = cancel.changed() => {
                let _ = changed;
                handlers_pair_machine::pre_household_reject().await
            }
        };
        drop(lifecycle_guard);
        response
    }
}

struct Phase3RuntimeBundle {
    generation: household_rs::household_lifecycle::HouseholdLifecycleGenerationV1,
    router: axum::Router,
    _event_log: Arc<OwnerEventLog>,
    _event_broadcaster: OwnerEventsBroadcaster,
    watchdog_cancel: tokio::sync::watch::Sender<bool>,
    watchdog_task: tokio::task::JoinHandle<()>,
    bonjour_task: Option<tokio::task::JoinHandle<()>>,
    #[cfg(target_os = "macos")]
    macos_local_listener:
        Option<crate::macos_local_registration_listener::MacosLocalRegistrationListener>,
}

impl Phase3RuntimeBundle {
    async fn shutdown(mut self) -> Result<(), String> {
        let _ = self.watchdog_cancel.send(true);
        match tokio::time::timeout(PHASE3_TASK_SHUTDOWN_TIMEOUT, &mut self.watchdog_task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(
                    stage = "phase3_runtime.watchdog_join_failed",
                    error = %error,
                );
            }
            Err(_) => {
                self.watchdog_task.abort();
                let _ = self.watchdog_task.await;
                tracing::warn!(stage = "phase3_runtime.watchdog_shutdown_forced");
            }
        }
        if let Some(task) = self.bonjour_task.take() {
            task.abort();
            let _ = task.await;
        }
        #[cfg(target_os = "macos")]
        if let Some(listener) = self.macos_local_listener.take()
            && let Err(error) = listener.shutdown().await
        {
            return Err(format!(
                "shut down macOS local registration listener: {error}"
            ));
        }
        Ok(())
    }
}

impl Phase3RuntimeController {
    fn new(
        state_dir: PathBuf,
        household: HouseholdState,
        pair_machine_window: Arc<PairMachineWindow>,
        key_policy: KeyBackingPolicy,
        shared_state: Option<SharedState>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
            router: Phase3RouterSlot::new(state_dir.clone()),
            state_dir,
            household,
            pair_machine_window,
            key_policy,
            shared_state,
        }
    }

    pub(crate) async fn install_under_lifecycle(
        &self,
        lifecycle: &LifecycleWriteGuard,
        loaded: Arc<household_rs::LoadedIdentity>,
    ) -> Result<(), String> {
        let broadcaster = OwnerEventsBroadcaster::new();
        let event_log = OwnerEventLog::open_with_broadcaster_under_lifecycle(
            lifecycle,
            self.state_dir.clone(),
            loaded.record.hh_id.as_str(),
            broadcaster.clone(),
        )
        .map_err(|error| format!("open owner event log: {error}"))?;
        self.install_with_resources_under_lifecycle(lifecycle, loaded, event_log, broadcaster)
            .await
    }

    async fn install_with_resources_under_lifecycle(
        &self,
        lifecycle: &LifecycleWriteGuard,
        loaded: Arc<household_rs::LoadedIdentity>,
        event_log: Arc<OwnerEventLog>,
        event_broadcaster: OwnerEventsBroadcaster,
    ) -> Result<(), String> {
        let generation = lifecycle
            .lifecycle_generation()
            .map_err(|error| format!("read lifecycle generation: {error}"))?
            .ok_or_else(|| "installed household has no lifecycle generation".to_string())?;
        let published = self
            .household
            .current()
            .await
            .ok_or_else(|| "installed household is not published in memory".to_string())?;
        if published.record.hh_id != loaded.record.hh_id || published.cert.m_id != loaded.cert.m_id
        {
            return Err("installed household differs from published in-memory identity".into());
        }

        // Retire the old generation before binding any replacement-owned
        // resources (notably the fixed macOS UDS path). The router slot is
        // cleared first, so no request can enter G0 while its tasks are being
        // joined or while G1 is still incomplete.
        self.router.retire().await;
        let previous = self.inner.write().await.take();
        if let Some(previous) = previous {
            previous.shutdown().await?;
        }

        let pair_machine_state = handlers_pair_machine::PairMachineRouterState {
            window: Arc::clone(&self.pair_machine_window),
            household: self.household.clone(),
            event_log: Arc::clone(&event_log),
            event_broadcaster: event_broadcaster.clone(),
            state_dir: self.state_dir.clone(),
        };
        let owner_approval_policy = handlers_owner_events::owner_approval_policy_from_env();
        let mut owner_events_state = handlers_owner_events::OwnerEventsRouterState::new(
            self.household.clone(),
            Arc::clone(&self.pair_machine_window),
            Arc::clone(&event_log),
            event_broadcaster.clone(),
            self.state_dir.clone(),
            self.key_policy,
        )
        .with_owner_approval_policy(owner_approval_policy.clone());
        if owner_approval_policy.secure_upgrade_strong_minting_enabled() {
            match handlers_owner_events::secure_upgrade_runtime_config_from_env() {
                Ok(config) => {
                    owner_events_state = owner_events_state.with_secure_upgrade_runtime(config);
                }
                Err(error) => {
                    tracing::warn!(
                        stage = "secure_upgrade.runtime_unavailable",
                        reason = %error,
                        "Secure/Upgrade rollout is enabled but runtime config is unavailable"
                    );
                }
            }
        }
        if let Some(state) = self.shared_state.as_ref() {
            owner_events_state = owner_events_state
                .with_recovery_consume_rate_limiter(Arc::clone(&state.rate_limiter));
        }
        // One RP/anchor per generation, shared by both routers. The macOS UDS
        // router always needs it; the TCP router only gets it when the operator
        // opened THEYOS_OWNER_WEBAUTHN_NETWORK, which is what keeps the
        // phone-reachable enrollment surface closed by default.
        let owner_webauthn_network = owner_webauthn_network_enabled();
        let owner_webauthn_runtime = if cfg!(target_os = "macos") || owner_webauthn_network {
            Some(
                OwnerWebauthnRuntime::build(&self.state_dir)
                    .map_err(|error| format!("build owner passkey registration state: {error}"))?,
            )
        } else {
            None
        };
        if owner_webauthn_network {
            let runtime = owner_webauthn_runtime
                .as_ref()
                .ok_or_else(|| "owner passkey runtime missing for network router".to_string())?;
            owner_events_state = runtime.apply(owner_events_state);
            tracing::info!(
                stage = "owner_webauthn.network_surface_open",
                env = OWNER_WEBAUTHN_NETWORK_ENV,
                "owner passkey enrollment is reachable over the network router"
            );
        }
        let router = phase3_router(
            pair_machine_state.clone(),
            owner_events_state.clone(),
            self.household.clone(),
            Arc::clone(&event_log),
            self.state_dir.clone(),
        );
        #[cfg(target_os = "macos")]
        let macos_local_listener = {
            let state_dir = self.state_dir.clone();
            let verifier: Arc<dyn crate::macos_local_caller_auth::MacosLocalCallerAuth> = Arc::new(
                crate::macos_local_caller_auth::DesignatedRequirementMacosLocalCallerAuth::new(
                    macos_local_app_profile_for_state_dir(&state_dir),
                ),
            );
            let runtime = owner_webauthn_runtime.as_ref().ok_or_else(|| {
                "owner passkey runtime missing for macOS local listener".to_string()
            })?;
            let state = macos_local_owner_webauthn_registration_state(
                owner_events_state.clone(),
                runtime,
                verifier,
            );
            let router =
                handlers_owner_events::owner_webauthn_macos_local_registration_router(state);
            Some(
                crate::macos_local_registration_listener::spawn_macos_local_registration_listener(
                    &state_dir, router,
                )
                .map_err(|error| format!("start macOS local registration listener: {error}"))?,
            )
        };

        // Spawn tasks only after every fallible resource in the bundle has
        // been constructed. An install error therefore leaves no detached
        // watchdog/browser behind.
        let (watchdog_cancel, watchdog_rx) = tokio::sync::watch::channel(false);
        let watchdog_task = handlers_owner_events::spawn_owner_timeout_watchdog(
            owner_events_state.clone(),
            watchdog_rx,
        );
        let bonjour_task = (loaded.record.shamir_n == 1)
            .then(|| bonjour_browser::spawn_bonjour_browser(pair_machine_state));

        let replacement = Phase3RuntimeBundle {
            generation,
            router,
            _event_log: event_log,
            _event_broadcaster: event_broadcaster,
            watchdog_cancel,
            watchdog_task,
            bonjour_task,
            #[cfg(target_os = "macos")]
            macos_local_listener,
        };
        self.router
            .publish(replacement.generation, replacement.router.clone())
            .await;
        *self.inner.write().await = Some(replacement);
        tracing::info!(
            stage = "phase3_runtime.installed",
            hh_id = %loaded.record.hh_id,
            m_id = %loaded.cert.m_id,
        );
        // A household that became live in this process (fresh install →
        // initialize → pair) never went through the boot-time adoption
        // above, and its "Mac Host" would stay invisible until a restart.
        if let Some(state) = self.shared_state.as_ref() {
            adopt_seeded_mac_host(
                state,
                loaded.record.hh_id.as_str(),
                loaded.cert.m_id.as_str(),
            );
        }
        Ok(())
    }

    pub(crate) async fn deactivate(&self) -> Result<(), String> {
        self.router.retire().await;
        let bundle = self.inner.write().await.take();
        if let Some(bundle) = bundle {
            bundle.shutdown().await?;
        }
        Ok(())
    }

    async fn route_or_reject(&self, request: axum::extract::Request) -> axum::response::Response {
        self.router.route_or_reject(request).await
    }
}

fn phase3_router(
    pair_machine_state: handlers_pair_machine::PairMachineRouterState,
    owner_events_state: handlers_owner_events::OwnerEventsRouterState,
    household: HouseholdState,
    event_log: Arc<OwnerEventLog>,
    state_dir: PathBuf,
) -> axum::Router {
    let sign_machine_cert_router = crate::handlers_sign_machine_cert::sign_machine_cert_router(
        crate::handlers_sign_machine_cert::SignMachineCertRouterState {
            household,
            event_log,
            state_dir,
        },
    );
    let router = axum::Router::new()
        .route(
            "/api/v1/household/join-request",
            axum::routing::post(handlers_pair_machine::founder_join_request_handler),
        )
        .with_state(pair_machine_state)
        .merge(
            axum::Router::new()
                .route(
                    "/api/v1/household/owner-events",
                    axum::routing::get(handlers_owner_events::owner_events_long_poll),
                )
                .route(
                    "/api/v1/household/owner-device/push-token",
                    axum::routing::post(handlers_owner_events::push_token_register_handler),
                )
                .route(
                    "/api/v1/household/owner-webauthn/registration/start",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_registration_start_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-webauthn/registration/finish",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_registration_finish_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-webauthn/registration/status",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_registration_status_handler,
                    ),
                )
                .route(
                    handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_START_PATH,
                    axum::routing::post(
                        handlers_owner_events::secure_upgrade_app_attest_start_handler,
                    ),
                )
                .route(
                    handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_FINISH_PATH,
                    axum::routing::post(
                        handlers_owner_events::secure_upgrade_app_attest_finish_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-webauthn/revoke/start",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_revoke_credential_start_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-webauthn/revoke/finish",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_revoke_credential_finish_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-webauthn/add-credential/start",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_add_credential_start_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-webauthn/add-credential/finish",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_add_credential_finish_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-webauthn/recovery/status",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_recovery_status_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-webauthn/recovery/start",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_recovery_start_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-webauthn/recovery/finish",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_recovery_finish_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-webauthn/recovery/consume/start",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_recovery_consume_start_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-webauthn/recovery/consume/finish",
                    axum::routing::post(
                        handlers_owner_events::owner_webauthn_recovery_consume_finish_handler,
                    ),
                )
                .route(
                    "/api/v1/household/owner-events/{cursor}/approve",
                    axum::routing::post(handlers_owner_events::owner_approve_handler),
                )
                .route(
                    "/api/v1/household/owner-events/{cursor}/approval-v2/start",
                    axum::routing::post(handlers_owner_events::owner_approval_v2_start_handler),
                )
                .route(
                    "/api/v1/household/owner-events/{cursor}/decline",
                    axum::routing::post(handlers_owner_events::owner_decline_handler),
                )
                .route(
                    "/api/v1/household/device-pairing/request",
                    axum::routing::post(handlers_device_pairing::device_pairing_request_handler),
                )
                .route(
                    "/api/v1/household/device-pairing/approve",
                    axum::routing::post(handlers_device_pairing::device_pairing_approve_handler),
                )
                .route(
                    "/api/v1/household/device-pairing/requests",
                    axum::routing::get(handlers_device_pairing::device_pairing_requests_handler),
                )
                .route(
                    "/api/v1/household/device-pairing/reject",
                    axum::routing::post(handlers_device_pairing::device_pairing_reject_handler),
                )
                .route(
                    "/api/v1/household/device-pairing/{request_id}",
                    axum::routing::get(handlers_device_pairing::device_pairing_poll_handler),
                )
                .with_state(owner_events_state),
        )
        .merge(sign_machine_cert_router);
    #[cfg(test)]
    let router = router.layer(axum::middleware::from_fn(
        |request: axum::extract::Request, next: axum::middleware::Next| async move {
            PHASE3_TEST_DISPATCH_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            next.run(request).await
        },
    ));
    router.fallback(handlers_pair_machine::pre_household_reject)
}

#[cfg(test)]
static PHASE3_TEST_DISPATCH_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[derive(Debug, thiserror::Error)]
enum LifecycleIdentityLoadError {
    #[error("household lifecycle lock failed: {0}")]
    Lifecycle(#[from] HouseholdLifecycleLockError),
    #[error("household teardown recovery failed: {0}")]
    Recovery(#[from] household_rs::StorageError),
    #[error("household identity load failed: {0}")]
    Bootstrap(#[from] household_rs::BootstrapError),
    #[error("household lifecycle deadline overflowed")]
    DeadlineOverflow,
}

/// A disk identity observation that remains serialized against teardown until
/// its matching in-memory authority has been published.
///
/// Keeping the write guard in the transaction makes it impossible for either
/// startup call site to accidentally return a naked `LoadedIdentity` and drop
/// lifecycle protection before publication.
struct LifecycleIdentityLoad {
    guard: LifecycleWriteGuard,
    loaded: Option<Arc<household_rs::LoadedIdentity>>,
    owner_auth: Option<Arc<household_rs::HouseholdAuthState>>,
}

impl LifecycleIdentityLoad {
    fn lifecycle_guard(&self) -> &LifecycleWriteGuard {
        &self.guard
    }

    async fn publish_into(&self, household: &HouseholdState) {
        let Some(loaded) = self.loaded.as_ref() else {
            return;
        };
        household
            .set_loaded_with_owner_auth(Arc::clone(loaded), self.owner_auth.clone())
            .await;
    }
}

/// Best-effort description of the owner-event log file, for the failure line.
///
/// The open error reads "bound to a different household or lifecycle
/// generation" for a permission mismatch too, so the line has to name what was
/// actually on disk or it explains nothing.
fn describe_owner_event_log_file(path: &Path) -> String {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    match std::fs::symlink_metadata(path) {
        Ok(meta) => format!(
            "mode={:o} uid={} nlink={} len={}",
            meta.permissions().mode() & 0o7777,
            meta.uid(),
            meta.nlink(),
            meta.len(),
        ),
        Err(error) => format!("unavailable ({error})"),
    }
}

/// Latch the generic fail-stop state for a terminal Phase-3 failure.
///
/// Mirrors the three sibling terminal Phase-3 outbox branches: persist
/// `Recovering` and push it through the state root, so a boot that refuses
/// every listener never leaves `ready` on disk for the next process to believe.
fn persist_phase3_fail_stop(state_dir: &Path, lifecycle: &LifecycleWriteGuard) {
    if let Err(state_error) = bootstrap_state::persist(state_dir, BootstrapState::Recovering) {
        tracing::error!(
            stage = "bootstrap.phase3_outbox_fail_stop_persist_failed",
            error = %state_error,
        );
    } else if let Err(sync_error) = lifecycle.sync_state_root() {
        tracing::error!(
            stage = "bootstrap.phase3_outbox_fail_stop_sync_failed",
            error = %sync_error,
        );
    }
}

/// Give the seeded `mac-host` row the household scope it was born without.
///
/// `seed_mac_host_instance` runs in `main` before any household exists, so
/// the row is inserted with a null `household_id` and `list_for_household`
/// keeps it invisible. Stamping must therefore happen every time a household
/// becomes live in this process — at boot for an installed one, and again
/// when a fresh install is initialized and paired without a restart. Until
/// 2026-09-01 only the boot path did it, so a first-time user finished
/// pairing and saw no "Mac Host" (and no way to open a new session) until
/// the engine was restarted. Idempotent: only a fully unscoped row changes.
fn adopt_seeded_mac_host(state: &SharedState, hh_id: &str, m_id: &str) {
    match state.instance_db.stamp_mac_host_household(hh_id, m_id) {
        Ok(true) => info!(
            stage = "bootstrap.mac_host.scoped",
            hh_id = %hh_id,
            "seeded mac-host instance adopted into the household"
        ),
        Ok(false) => {}
        Err(e) => tracing::warn!(
            stage = "bootstrap.mac_host.scope_failed",
            error = %e,
            "could not scope the seeded mac-host instance to the household"
        ),
    }
}

fn acquire_recovered_household_lifecycle(
    state_dir: &Path,
) -> Result<LifecycleWriteGuard, LifecycleIdentityLoadError> {
    let lifecycle = HouseholdLifecycleLock::open_verified(state_dir)?;
    let deadline = Instant::now()
        .checked_add(HOUSEHOLD_LIFECYCLE_TIMEOUT)
        .ok_or(LifecycleIdentityLoadError::DeadlineOverflow)?;
    let guard = lifecycle.lock_exclusive_until(deadline)?;
    recover_interrupted_household_teardown_under_lifecycle(&guard, state_dir)?;
    Ok(guard)
}

fn load_identity_under_lifecycle(
    guard: LifecycleWriteGuard,
    state_dir: &Path,
    key_policy: KeyBackingPolicy,
) -> Result<LifecycleIdentityLoad, LifecycleIdentityLoadError> {
    let loaded = try_load_existing_under_lifecycle(&guard, state_dir, key_policy)?.map(Arc::new);
    let owner_auth = loaded
        .as_deref()
        .and_then(|identity| load_owner_auth_for_identity(state_dir, identity));
    Ok(LifecycleIdentityLoad {
        guard,
        loaded,
        owner_auth,
    })
}

fn active_terminal_replay_addr(
    lifecycle: &LifecycleWriteGuard,
    state_dir: &Path,
    loaded: Option<&household_rs::LoadedIdentity>,
) -> Result<Option<(SocketAddr, household_rs::pair_machine::JoinTransport)>, String> {
    let terminal = household_rs::household_install_transaction::load_active_finalize_terminal_result_under_lifecycle(lifecycle)
        .map_err(|error| format!("load active pair-machine terminal result: {error}"))?;
    let Some(terminal) = terminal else {
        return Ok(None);
    };
    let loaded = loaded.ok_or_else(|| {
        "active pair-machine terminal result exists without installed identity".to_string()
    })?;
    if loaded.record.hh_id != *terminal.hh_id() || loaded.cert.m_id != *terminal.m_id() {
        return Err("active pair-machine terminal result differs from local identity".into());
    }
    lifecycle
        .verify_state_root(state_dir)
        .map_err(|error| format!("verify terminal state root: {error}"))?;
    let bootstrap = bootstrap_state::load(state_dir)
        .map_err(|error| format!("load terminal bootstrap state: {error}"))?;
    let delivery =
        household_rs::household_install_transaction::load_finalize_ack_delivery_under_lifecycle(
            lifecycle,
        )
        .map_err(|error| format!("load pair-machine delivery boundary: {error}"))?;
    match (&bootstrap, &delivery) {
        (
            BootstrapState::PairMachineInstallRestartRequired,
            household_rs::household_install_transaction::FinalizeAckDeliveryRecoveryOutcome::Absent,
        ) => {}
        (
            BootstrapState::PairMachineInstallRestartRequired | BootstrapState::Ready,
            household_rs::household_install_transaction::FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(delivered),
        ) if delivered.as_ref() == &terminal => {}
        _ => {
            return Err(
                "terminal bootstrap state and full delivery authority diverged".to_string(),
            );
        }
    }
    let (addr, transport) = handlers_pair_machine::exact_terminal_replay_endpoint(&terminal)
        .map_err(|error| format!("resolve exact pair-machine terminal address: {error}"))?;
    addr.parse::<SocketAddr>()
        .map(|addr| Some((addr, transport)))
        .map_err(|error| format!("parse exact pair-machine terminal address: {error}"))
}

pub(crate) async fn bind_terminal_replay_listener(
    addr: SocketAddr,
    state: handlers_pair_machine::PreHouseholdRouterState,
) -> std::io::Result<(tokio::net::TcpListener, axum::Router)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    Ok((
        listener,
        handlers_pair_machine::terminal_replay_router(state),
    ))
}

fn terminal_replay_endpoint_is_still_active(
    state_dir: &Path,
    expected: SocketAddr,
    expected_transport: household_rs::pair_machine::JoinTransport,
) -> bool {
    let Ok(lifecycle) = HouseholdLifecycleLock::open_verified(state_dir) else {
        return false;
    };
    let Some(deadline) = Instant::now().checked_add(Duration::from_secs(1)) else {
        return false;
    };
    let guard = match lifecycle.lock_exclusive_until(deadline) {
        Ok(guard) => guard,
        Err(error) if terminal_replay_lock_failure_is_contention(error) => {
            // Contention is not evidence that replay authority disappeared.
            // Keep the terminal listener and retry the check rather than
            // creating a transient lost-Ack outage.
            return true;
        }
        Err(error) => {
            // Unsafe path/filesystem, required recovery, and I/O failure are
            // persistent authority failures, not contention. Stop serving so
            // a degraded listener cannot monopolize the retained LAN address.
            tracing::warn!(
                stage = "pair_machine.terminal_replay_lifecycle_invalid",
                error = %error,
                "terminal replay listener is shutting down fail-closed"
            );
            return false;
        }
    };
    let Ok(Some(terminal)) = household_rs::household_install_transaction::load_active_finalize_terminal_result_under_lifecycle(&guard)
    else {
        return false;
    };
    let Ok((addr, transport)) = handlers_pair_machine::exact_terminal_replay_endpoint(&terminal)
    else {
        return false;
    };
    transport == expected_transport && addr.parse::<SocketAddr>() == Ok(expected)
}

const fn terminal_replay_lock_failure_is_contention(error: HouseholdLifecycleLockError) -> bool {
    matches!(error, HouseholdLifecycleLockError::LockTimeout)
}

pub(crate) async fn wait_until_terminal_replay_is_inactive(
    state_dir: PathBuf,
    expected: SocketAddr,
    expected_transport: household_rs::pair_machine::JoinTransport,
    bootstrap: BootstrapStateArc,
) {
    loop {
        tokio::time::sleep(TERMINAL_REPLAY_REBIND_INTERVAL).await;
        if !matches!(
            *bootstrap.read().await,
            BootstrapState::PairMachineInstallRestartRequired | BootstrapState::Ready
        ) {
            return;
        }
        let check_dir = state_dir.clone();
        let active = tokio::task::spawn_blocking(move || {
            terminal_replay_endpoint_is_still_active(&check_dir, expected, expected_transport)
        })
        .await
        .unwrap_or(false);
        if !active {
            return;
        }
    }
}

fn spawn_supervised_terminal_replay_listener(
    addr: SocketAddr,
    transport: household_rs::pair_machine::JoinTransport,
    state: handlers_pair_machine::PreHouseholdRouterState,
    initial: Option<(tokio::net::TcpListener, axum::Router)>,
) {
    tokio::spawn(async move {
        let state_dir = state.state_dir.clone();
        let Some(bootstrap) = state.bootstrap.clone() else {
            return;
        };
        let mut initial = initial;
        loop {
            if !matches!(
                *bootstrap.read().await,
                BootstrapState::PairMachineInstallRestartRequired | BootstrapState::Ready
            ) {
                return;
            }
            let check_dir = state_dir.clone();
            let active = tokio::task::spawn_blocking(move || {
                terminal_replay_endpoint_is_still_active(&check_dir, addr, transport)
            })
            .await
            .unwrap_or(false);
            if !active {
                return;
            }
            let bound = match initial.take() {
                Some(bound) => Ok(bound),
                None => bind_terminal_replay_listener(addr, state.clone()).await,
            };
            match bound {
                Ok((listener, router)) => {
                    tracing::info!(
                        stage = "pair_machine.terminal_replay_listener_live",
                        address = %addr,
                    );
                    if let Err(error) =
                        core_rs::phase0_axum_serve!(listener, router, connect_info = SocketAddr)
                            .with_graceful_shutdown(wait_until_terminal_replay_is_inactive(
                                state_dir.clone(),
                                addr,
                                transport,
                                Arc::clone(&bootstrap),
                            ))
                            .await
                    {
                        tracing::warn!(
                            stage = "pair_machine.terminal_replay_listener_exited",
                            address = %addr,
                            error = %error,
                        );
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        stage = "pair_machine.terminal_replay_bind_retry",
                        address = %addr,
                        error = %error,
                    );
                }
            }
            tokio::time::sleep(TERMINAL_REPLAY_REBIND_INTERVAL).await;
        }
    });
}

fn acquire_and_load_identity_under_lifecycle(
    state_dir: &Path,
    key_policy: KeyBackingPolicy,
) -> Result<LifecycleIdentityLoad, LifecycleIdentityLoadError> {
    let guard = acquire_recovered_household_lifecycle(state_dir)?;
    load_identity_under_lifecycle(guard, state_dir, key_policy)
}

/// Access the global bootstrap state.
///
/// Returns `None` only before `bootstrap_household` has run (should never
/// happen in production — the household router is up before any handler fires).
#[must_use]
pub fn global_bootstrap_state() -> Option<BootstrapStateArc> {
    BOOTSTRAP_STATE.get().map(Arc::clone)
}

#[derive(Clone)]
struct ClawShareRuntimeHandles {
    slot_store: Arc<ClawShareSlotStore>,
    mesh_log: Arc<MeshLogStore>,
    replayguard: Arc<ReplayGuard>,
    relay_offer_challenges: Arc<RelayOfferChallengeTable>,
    group_claim_nonces: Arc<GroupClaimNonceTable>,
    relay_offer_abuse: Arc<Mutex<RelayAbuseState>>,
}

struct EngineRelayIdentity {
    keys: Keys,
    npub_hex: String,
}

struct ClawShareBootstrapState {
    runtime: ClawShareRuntimeHandles,
    engine_relay_identity: Option<EngineRelayIdentity>,
    relay_urls: Vec<String>,
}

/// Resolve the on-disk household state directory.
///
/// Order of precedence:
/// 1. `THEYOS_HOUSEHOLD_STATE_DIR` (explicit override)
/// 2. `THEYOS_STATE_DIR` (operator-facing compatibility alias)
/// 3. `<THEYOS_DIR>/household-state` (when `THEYOS_DIR` is set)
/// 4. Platform default:
///    - macOS: `~/Library/Application Support/Soyeht`
///    - Linux: `$XDG_DATA_HOME/Soyeht` (falling back to `~/.local/share/Soyeht`)
/// 5. `./.run/household-state` (last-resort fallback for CI / dev environments
///    where the home directory is unavailable)
///
/// Tests for both platforms: see `tests::resolve_*` below.
#[must_use]
pub fn resolve_household_state_dir() -> PathBuf {
    if let Ok(v) = std::env::var("THEYOS_HOUSEHOLD_STATE_DIR") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    if let Ok(v) = std::env::var("THEYOS_STATE_DIR") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    // Explicit THEYOS_DIR override (e.g. dev, Docker, NixOS module).
    if let Ok(v) = std::env::var("THEYOS_DIR") {
        if !v.is_empty() {
            return PathBuf::from(v).join("household-state");
        }
    }
    // Platform-specific defaults (T012).
    if let Some(home) = home_dir() {
        #[cfg(target_os = "macos")]
        {
            return home
                .join("Library")
                .join("Application Support")
                .join("Soyeht");
        }
        #[cfg(not(target_os = "macos"))]
        {
            let xdg = std::env::var("XDG_DATA_HOME")
                .ok()
                .filter(|s| !s.is_empty())
                .map_or_else(|| home.join(".local").join("share"), PathBuf::from);
            return xdg.join("Soyeht");
        }
    }
    // Last-resort fallback.
    PathBuf::from("./.run/household-state")
}

/// Resolve the current user's home directory.
///
/// Uses `HOME` env var on Linux/macOS; does not depend on `dirs` crate.
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Default port the household / bootstrap engine listens on when
/// `THEYOS_HOUSEHOLD_PORT` is unset. This is the single source for the
/// iOS-facing engine port: it is documented in `PORTS.md` and pinned by the
/// `ports_registry` test (and, on the client side, by the iOS
/// `SoyehtInstallProfile` port test). Do not hardcode `8091` elsewhere — call
/// [`household_port_from_env`] or reference this constant.
pub const DEFAULT_HOUSEHOLD_PORT: u16 = 8091;

#[must_use]
pub fn household_port_from_env() -> u16 {
    std::env::var("THEYOS_HOUSEHOLD_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_HOUSEHOLD_PORT)
}

#[cfg(any(target_os = "macos", test))]
fn macos_local_app_profile_for_state_dir(
    state_dir: &Path,
) -> crate::macos_local_caller_auth::MacosLocalAppProfile {
    // The Dev engine runs in the exact `SoyehtDev` namespace. Keep this tied to
    // state isolation, not to a caller-supplied header or permissive env flag.
    let namespace = if state_dir
        .file_name()
        .is_some_and(|name| name == "household-state")
    {
        state_dir.parent().and_then(Path::file_name)
    } else {
        state_dir.file_name()
    };
    let is_dev_state = namespace.is_some_and(|name| name == "SoyehtDev");
    if is_dev_state {
        crate::macos_local_caller_auth::MacosLocalAppProfile::Development
    } else {
        crate::macos_local_caller_auth::MacosLocalAppProfile::Production
    }
}

type LocalOwnerWebauthnRp = household_rs::owner_webauthn::OwnerWebauthnRp;

/// Relying-party ID for owner passkey enrollment. Unset keeps the placeholder,
/// so an engine that is not configured behaves exactly as before this switch
/// existed.
pub const OWNER_WEBAUTHN_RP_ID_ENV: &str = "THEYOS_OWNER_WEBAUTHN_RP_ID";
/// Relying-party origin that must accompany [`OWNER_WEBAUTHN_RP_ID_ENV`].
pub const OWNER_WEBAUTHN_RP_ORIGIN_ENV: &str = "THEYOS_OWNER_WEBAUTHN_RP_ORIGIN";
/// Opens owner passkey enrollment on the TCP router. Only the literal `1`
/// opens it; anything else (including an unparseable value) stays closed.
pub const OWNER_WEBAUTHN_NETWORK_ENV: &str = "THEYOS_OWNER_WEBAUTHN_NETWORK";

/// `household-rs` requires the RP ID to be a domain the tenant controls, not a
/// domain shared across households (`owner_webauthn.rs`, `OwnerWebauthnConfig::new`):
/// every credential minted under an RP ID is usable by whoever serves that
/// domain's `webauthn` association file, so one shared domain would make one
/// operator the relying party for the whole fleet. These placeholders resolve
/// to nothing, which is why the passkey surface stays unreachable until a
/// deployment names its own domain.
pub const DEFAULT_OWNER_WEBAUTHN_RP_ID: &str = "household.example.test";
const DEFAULT_OWNER_WEBAUTHN_RP_ORIGIN: &str = "https://household.example.test";
const OWNER_WEBAUTHN_RP_NAME: &str = "Soyeht";

/// The RP built once per household generation, plus the keystore the anchor
/// verifier reads.
///
/// One instance, shared: `OwnerWebauthnRp` owns the in-memory challenge store,
/// so a second instance would give the TCP router and the macOS UDS router a
/// challenge store each, and a registration started on one would fail on the
/// other as an unknown challenge. Cloning the `Arc` is what keeps the two
/// routers on the same store.
#[derive(Clone)]
struct OwnerWebauthnRuntime {
    rp: Arc<tokio::sync::Mutex<LocalOwnerWebauthnRp>>,
    anchor: Arc<dyn keystore_rs::KeystoreBackend>,
}

impl OwnerWebauthnRuntime {
    fn build(state_dir: &Path) -> Result<Self, String> {
        Ok(Self {
            rp: Arc::new(tokio::sync::Mutex::new(owner_webauthn_rp_from_env()?)),
            anchor: owner_webauthn_registration_anchor_store(state_dir),
        })
    }

    fn apply(
        &self,
        state: handlers_owner_events::OwnerEventsRouterState,
    ) -> handlers_owner_events::OwnerEventsRouterState {
        state
            .with_owner_webauthn_rp_shared(Arc::clone(&self.rp))
            .with_owner_webauthn_anchor(Arc::clone(&self.anchor))
    }
}

fn owner_webauthn_rp_from_env() -> Result<LocalOwnerWebauthnRp, String> {
    owner_webauthn_rp_from_values(
        non_empty_env(OWNER_WEBAUTHN_RP_ID_ENV).as_deref(),
        non_empty_env(OWNER_WEBAUTHN_RP_ORIGIN_ENV).as_deref(),
    )
}

fn owner_webauthn_rp_from_values(
    rp_id: Option<&str>,
    rp_origin: Option<&str>,
) -> Result<LocalOwnerWebauthnRp, String> {
    let rp_id = rp_id.unwrap_or(DEFAULT_OWNER_WEBAUTHN_RP_ID);
    let rp_origin = rp_origin.unwrap_or(DEFAULT_OWNER_WEBAUTHN_RP_ORIGIN);
    let origin = webauthn_rs::prelude::Url::parse(rp_origin).map_err(|e| e.to_string())?;
    let config = household_rs::owner_webauthn::OwnerWebauthnConfig::new(
        rp_id,
        origin,
        OWNER_WEBAUTHN_RP_NAME,
    )
    .map_err(|e| e.to_string())?;
    household_rs::owner_webauthn::OwnerWebauthnRp::new(config).map_err(|e| e.to_string())
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Whether the TCP (phone-reachable) router gets the passkey RP and anchor.
///
/// Closed unless the value is exactly `1`: the surface mints owner authority,
/// so an operator typo must leave it shut rather than half-open.
#[must_use]
fn owner_webauthn_network_enabled() -> bool {
    owner_webauthn_network_enabled_from_value(
        std::env::var(OWNER_WEBAUTHN_NETWORK_ENV).ok().as_deref(),
    )
}

#[must_use]
fn owner_webauthn_network_enabled_from_value(raw: Option<&str>) -> bool {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        Some("1") => true,
        None | Some("0") => false,
        Some(_) => {
            tracing::warn!(
                env = OWNER_WEBAUTHN_NETWORK_ENV,
                "unknown owner-webauthn network value; keeping the network surface closed"
            );
            false
        }
    }
}

fn owner_webauthn_registration_anchor_store(
    state_dir: &Path,
) -> Arc<dyn keystore_rs::KeystoreBackend> {
    Arc::new(keystore_rs::FileKeystore::new(
        state_dir,
        keystore_rs::SERVICE,
    ))
}

#[cfg(any(target_os = "macos", test))]
fn macos_local_owner_webauthn_registration_state(
    state: handlers_owner_events::OwnerEventsRouterState,
    runtime: &OwnerWebauthnRuntime,
    verifier: Arc<dyn crate::macos_local_caller_auth::MacosLocalCallerAuth>,
) -> handlers_owner_events::OwnerEventsRouterState {
    runtime.apply(state).with_macos_local_caller_auth(verifier)
}

fn claw_share_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("claw_share").join("mesh_log.ndjson")
}

fn csv_has_entries(raw: Option<&str>) -> bool {
    raw.is_some_and(|value| value.split(',').any(|part| !part.trim().is_empty()))
}

fn relay_urls_from_env_value(raw: Option<&str>) -> Vec<String> {
    raw.map(crate::claw_share_relay_loop::parse_relay_list)
        .unwrap_or_default()
}

fn open_claw_share_mesh_log(state_dir: &Path) -> Arc<MeshLogStore> {
    let log_path = claw_share_log_path(state_dir);
    match MeshLogStore::open(&log_path) {
        Ok(log) => Arc::new(log),
        Err(e) => {
            tracing::error!(
                stage = "claw_share.mesh_log.open_failed",
                path = %log_path.display(),
                error = %e,
                "falling back to in-memory claw-share membership log; restarts will lose relay state",
            );
            Arc::new(MeshLogStore::new())
        }
    }
}

fn prepare_engine_relay_identity(
    state_dir: &Path,
    relay_urls: &[String],
) -> Result<Option<EngineRelayIdentity>, std::io::Error> {
    if relay_urls.is_empty() {
        return Ok(None);
    }
    let keys = crate::claw_share_relay_loop::load_or_create_nostr_key(state_dir)?;
    let npub_hex = keys.public_key().to_hex();
    Ok(Some(EngineRelayIdentity { keys, npub_hex }))
}

fn prepare_claw_share_bootstrap_state(
    state_dir: &Path,
    relay_env: Option<&str>,
    claim_relays_env: Option<&str>,
) -> ClawShareBootstrapState {
    let mesh_log = open_claw_share_mesh_log(state_dir);
    let projection = mesh_log.project();
    let slot_store = Arc::new(ClawShareSlotStore::seeded_from(&projection));
    let replayguard = Arc::new(ReplayGuard::new());
    let relay_offer_challenges = Arc::new(RelayOfferChallengeTable::new());
    let group_claim_nonces = Arc::new(GroupClaimNonceTable::new());
    let relay_offer_abuse = Arc::new(Mutex::new(RelayAbuseState::default()));
    let relay_urls = relay_urls_from_env_value(relay_env);

    if relay_urls.is_empty() && csv_has_entries(claim_relays_env) {
        tracing::warn!(
            stage = "claw_share.relay.claim_relays_without_listener",
            "THEYOS_CLAIM_RELAYS is configured but THEYOS_NOSTR_RELAY is empty; invite minting will fail closed",
        );
    }

    let engine_relay_identity = match prepare_engine_relay_identity(state_dir, &relay_urls) {
        Ok(identity) => identity,
        Err(e) => {
            tracing::error!(
                stage = "claw_share.relay.key_load_failed",
                error = %e,
                "engine Nostr relay key could not be loaded; relay claim path disabled and minting fails closed",
            );
            None
        }
    };

    ClawShareBootstrapState {
        runtime: ClawShareRuntimeHandles {
            slot_store,
            mesh_log,
            replayguard,
            relay_offer_challenges,
            group_claim_nonces,
            relay_offer_abuse,
        },
        engine_relay_identity,
        relay_urls,
    }
}

fn build_claw_share_router(
    household: HouseholdState,
    state_dir: PathBuf,
    runtime: &ClawShareRuntimeHandles,
    engine_relay_npub: Option<String>,
    shared_state: Option<SharedState>,
) -> axum::Router {
    handlers_claw_share::router(handlers_claw_share::ClawShareRouterState {
        household,
        slot_store: Arc::clone(&runtime.slot_store),
        mesh_log: Arc::clone(&runtime.mesh_log),
        engine_relay_npub,
        state_dir,
        relay_offer_challenges: Arc::clone(&runtime.relay_offer_challenges),
        relay_offer_abuse: Arc::clone(&runtime.relay_offer_abuse),
        shared_state,
    })
}

fn spawn_claw_share_relay_loop_if_configured(
    household: HouseholdState,
    state_dir: PathBuf,
    runtime: &ClawShareRuntimeHandles,
    engine_relay_identity: Option<EngineRelayIdentity>,
    relay_urls: Vec<String>,
) {
    if relay_urls.is_empty() {
        return;
    }
    let Some(identity) = engine_relay_identity else {
        tracing::error!(
            stage = "claw_share.relay.no_identity",
            "THEYOS_NOSTR_RELAY is set but engine Nostr identity is unavailable; relay loop not spawned",
        );
        return;
    };
    tracing::info!(
        stage = "claw_share.relay.spawned",
        relay_count = relay_urls.len(),
        "engine relay loops spawned",
    );
    crate::claw_share_relay_loop::spawn(crate::claw_share_relay_loop::EngineRelayState {
        household,
        slot_store: Arc::clone(&runtime.slot_store),
        mesh_log: Arc::clone(&runtime.mesh_log),
        engine_keys: identity.keys,
        relay_urls,
        state_dir,
        group_claim_nonces: Arc::clone(&runtime.group_claim_nonces),
    });
}

async fn mount_claw_share_relay_stream_live_if_enabled(
    state_dir: PathBuf,
    household: HouseholdState,
    runtime: &ClawShareRuntimeHandles,
    shared_state: Option<SharedState>,
) {
    if let Err(e) = crate::claw_share_relay_stream_mount::mount_relay_stream_live_if_enabled(
        state_dir,
        household,
        Arc::clone(&runtime.mesh_log),
        Arc::clone(&runtime.slot_store),
        Arc::clone(&runtime.replayguard),
        shared_state,
    )
    .await
    {
        tracing::warn!(
            stage = "claw_share.relay_stream.mount_failed",
            error = %e,
            "relay_stream live mount failed; continuing household bootstrap",
        );
    }
}

/// Default pairing-window TTL (seconds) when the override env var is unset, not a
/// number, or out of [`PAIR_WINDOW_TTL_MIN_SECS`]..=[`PAIR_WINDOW_TTL_MAX_SECS`].
/// Short enough (5 min) that a leaked pair QR/URI does not sit valid for hours.
pub const DEFAULT_PAIR_WINDOW_TTL_SECS: u64 = 5 * 60;
/// Lower bound for an operator pairing-window TTL override (seconds).
pub const PAIR_WINDOW_TTL_MIN_SECS: u64 = 60;
/// Upper bound for an operator pairing-window TTL override (seconds). The clamp
/// keeps an accidental absurd value from weakening prod beyond the documented
/// threat surface.
pub const PAIR_WINDOW_TTL_MAX_SECS: u64 = 3600;

/// Clamp a parsed pairing-window TTL: an in-range value passes through; `None` or
/// an out-of-range value falls back to [`DEFAULT_PAIR_WINDOW_TTL_SECS`]. Split out
/// from the env read so the parse/clamp/default policy is unit-testable without
/// mutating process env.
#[must_use]
fn clamp_pair_window_ttl_secs(parsed: Option<u64>) -> u64 {
    parsed
        .filter(|secs| (PAIR_WINDOW_TTL_MIN_SECS..=PAIR_WINDOW_TTL_MAX_SECS).contains(secs))
        .unwrap_or(DEFAULT_PAIR_WINDOW_TTL_SECS)
}

/// Read a pairing-window TTL (seconds) from `env_var`, clamped to
/// [`PAIR_WINDOW_TTL_MIN_SECS`]..=[`PAIR_WINDOW_TTL_MAX_SECS`] and defaulting to
/// [`DEFAULT_PAIR_WINDOW_TTL_SECS`]. Single owner for the
/// `THEYOS_PAIR_DEVICE_TTL_SECS` / `THEYOS_PAIR_MACHINE_TTL_SECS` reads — do not
/// re-implement the parse/clamp/default at call sites.
#[must_use]
pub fn pair_window_ttl_secs_from_env(env_var: &str) -> u64 {
    clamp_pair_window_ttl_secs(
        std::env::var(env_var)
            .ok()
            .and_then(|s| s.parse::<u64>().ok()),
    )
}

/// Resolve the Phase-3 recovery timeout used by the actual server bootstrap.
/// Keeping this helper on the call path makes the production wiring directly
/// testable and prevents the bootstrap from drifting back to a fixed constant.
#[must_use]
fn phase3_recovery_timeout() -> household_rs::pair_machine::RecoveryTimeoutResolution {
    household_rs::pair_machine::recovery_timeout_from_env()
}

/// Publication decision produced by boot-time Phase-3 recovery.
#[derive(Debug)]
#[must_use]
pub enum BootstrapPhase3Recovery {
    /// Recovery completed (including the no-evidence fast path); startup may
    /// continue toward authority and listener publication.
    Continue(household_rs::pair_machine::RecoveryOutcome),
    /// Recovery remained indeterminate; startup persisted `Recovering` and must
    /// return without publishing authority or listeners.
    RefusePublication,
}

/// Run Phase-3 recovery with the same resolved policy used by server startup.
///
/// Keeping policy resolution, tracing, fail-closed persistence, and the
/// recovery call in one function gives integration tests the exact production
/// path without starting a listener. The caller must hold the startup
/// lifecycle-exclusive guard.
pub async fn recover_phase3_with_bootstrap_policy(
    state_dir: &Path,
    pair_machine_window: &PairMachineWindow,
    lifecycle_guard: &LifecycleWriteGuard,
) -> BootstrapPhase3Recovery {
    let recovery_timeout = phase3_recovery_timeout();
    tracing::info!(
        stage = "bootstrap.phase3_recovery_policy",
        timeout_secs = recovery_timeout.timeout.as_secs(),
        timeout_source = recovery_timeout.source.as_str(),
        timeout_env = household_rs::pair_machine::RECOVERY_TIMEOUT_ENV,
        "resolved boot-time Phase 3 recovery policy"
    );
    match pair_machine_window
        .recover_phase3_under_lifecycle(state_dir, lifecycle_guard, recovery_timeout.timeout)
        .await
    {
        Ok(outcome) => {
            tracing::info!(
                stage = "bootstrap.phase3_recovery",
                outcome = ?outcome,
                "boot-time Phase 3 recovery inspection completed"
            );
            BootstrapPhase3Recovery::Continue(outcome)
        }
        Err(error) => {
            tracing::error!(
                stage = "bootstrap.phase3_recovery_failed",
                error = %error,
                "boot-time Phase 3 recovery is indeterminate; refusing to \
                 publish identity or listeners"
            );
            if let Err(state_error) =
                bootstrap_state::persist(state_dir, BootstrapState::Recovering)
            {
                tracing::error!(
                    stage = "bootstrap.phase3_recovery_fail_stop_persist_failed",
                    error = %state_error,
                );
            } else if let Err(sync_error) = lifecycle_guard.sync_state_root() {
                tracing::error!(
                    stage = "bootstrap.phase3_recovery_fail_stop_sync_failed",
                    error = %sync_error,
                );
            }
            BootstrapPhase3Recovery::RefusePublication
        }
    }
}

/// Bring up the household identity listener at server startup.
///
/// On a fresh, uninitialized state directory, `/identity` returns 503 until
/// `theyos install` writes identity records; a watcher then hot-loads them.
///
/// `shared_state` is `Some(state)` when called from the main daemon path
/// (mounts household-namespaced Claw Store routes at
/// `/api/v1/household/claws*` using the engine's main `SharedState`).
/// Pass `None` from short-lived bring-up paths that don't have a full
/// `SharedState` yet (e.g. `theyos install`'s post-commit listener) —
/// Claw Store routes will be omitted, but identity / snapshot / pair /
/// bootstrap remain available.
///
/// The household listener is independent from the main `cfg.addr`
/// listener (FR-010 untouched).
///
/// # Panics
///
/// Panics if the on-disk identity is corrupted or fails chain verification —
/// refuse-to-start (US1 acceptance C6). The structured-log envelope at
/// `bootstrap.error` carries the underlying cause before the panic.
pub async fn bootstrap_household(
    startup: &household_listener::ProcessStartupToken,
    shared_state: Option<SharedState>,
) {
    let state_dir = resolve_household_state_dir();
    if let Err(e) = std::fs::create_dir_all(&state_dir) {
        tracing::warn!(
            "failed to create household state dir {}: {e}",
            state_dir.display()
        );
    }

    let port = household_port_from_env();

    let key_policy = household_rs::KeyBackingPolicy::from_env();

    // The disk observation and its in-memory publication are one lifecycle
    // transaction. In particular, a concurrent teardown cannot detach
    // household A after we load it and before the handler state publishes A.
    let lifecycle_state_dir = state_dir.clone();
    let lifecycle_guard = match tokio::task::spawn_blocking(move || {
        acquire_recovered_household_lifecycle(&lifecycle_state_dir)
    })
    .await
    {
        Ok(Ok(guard)) => guard,
        Ok(Err(error)) => {
            tracing::error!(
                stage = "bootstrap.lifecycle_acquire_failed",
                error = %error,
                "household startup lifecycle transaction failed"
            );
            panic!("household startup lifecycle transaction failed: {error}");
        }
        Err(error) => {
            tracing::error!(
                stage = "bootstrap.lifecycle_worker_failed",
                error = %error,
                "household startup lifecycle worker failed"
            );
            panic!("household startup lifecycle worker failed: {error}");
        }
    };

    // Recover the stable install breadcrumb before opening a *current*
    // pair-window namespace. A crash after terminal G0->G1 rotation but
    // before breadcrumb cleanup still needs to validate G0's committed
    // snapshot; current-namespace construction deliberately sweeps retired
    // generations and therefore must happen only after this recovery.
    let install_rotated = handlers_pair_machine::recover_candidate_install_under_lifecycle(
        &state_dir,
        &lifecycle_guard,
        key_policy,
    )
    .await
    .unwrap_or_else(|error| panic!("household install recovery failed closed: {error}"));
    if install_rotated {
        tracing::info!(
            stage = "bootstrap.household_install_recovered",
            "terminal install generation recovered before authority publication"
        );
    }

    // Resolve both ceremony namespaces while the startup-exclusive guard is
    // still retained. Falling back to an in-memory window would silently
    // discard durable pre-household authority and would let later writes
    // escape generation binding, so an unsafe/corrupt namespace is a
    // refuse-to-start condition.
    let pair_device_window = Arc::new(
        household_rs::pair_device::PairDeviceWindow::with_persistence_under_lifecycle(
            state_dir.clone(),
            &lifecycle_guard,
        )
        .unwrap_or_else(|error| panic!("pair-device namespace recovery failed: {error}")),
    );
    let pair_machine_window = Arc::new(
        PairMachineWindow::with_persistence_under_lifecycle(state_dir.clone(), &lifecycle_guard)
            .unwrap_or_else(|error| panic!("pair-machine namespace recovery failed: {error}")),
    );

    // T074: Phase-3 in-flight ceremony recovery driver. Runs BEFORE
    // `try_load_existing` consumes the on-disk record so that any
    // committed-but-unfinished ceremony rolls forward (post-Shamir
    // record on disk, with this process picking up the N=2 identity)
    // before the household listener binds. If durable recovery evidence is
    // absent this is a no-op fast path. Once finalize may have reached M2,
    // timeout is indeterminate and must never become an N=1 rollback.
    //
    // The probe operates on disk and over HTTP only; no in-memory
    // state from this process is required. Any error while recovery evidence
    // exists is fail-stop: publishing the pre-Shamir N=1 identity after M2 may
    // have committed N=2 would create two live authorities.
    let phase3_recovery_completed = match recover_phase3_with_bootstrap_policy(
        &state_dir,
        &pair_machine_window,
        &lifecycle_guard,
    )
    .await
    {
        BootstrapPhase3Recovery::Continue(outcome) => !matches!(
            outcome,
            household_rs::pair_machine::RecoveryOutcome::NotApplicable
        ),
        BootstrapPhase3Recovery::RefusePublication => {
            // Drop lifecycle-exclusive without constructing or publishing
            // LoadedIdentity, routers, Bonjour, or any listener. A later cold
            // start retries the retained exact recovery evidence.
            return;
        }
    };

    let load_state_dir = state_dir.clone();
    let identity_load = match tokio::task::spawn_blocking(move || {
        load_identity_under_lifecycle(lifecycle_guard, &load_state_dir, key_policy)
    })
    .await
    {
        Ok(Ok(load)) => load,
        Ok(Err(error)) => {
            if let LifecycleIdentityLoadError::Bootstrap(source) = &error {
                household_rs::bootstrap::log_error(source);
            } else {
                tracing::error!(
                    stage = "bootstrap.lifecycle_load_failed",
                    error = %error,
                    "household identity lifecycle load failed"
                );
            }
            panic!("household identity load failed: {error}");
        }
        Err(error) => {
            tracing::error!(
                stage = "bootstrap.lifecycle_load_worker_failed",
                error = %error,
                "household identity lifecycle load worker failed"
            );
            panic!("household identity load worker failed: {error}");
        }
    };
    let loaded_arc = identity_load.loaded.clone();
    let terminal_replay_endpoint = active_terminal_replay_addr(
        identity_load.lifecycle_guard(),
        &state_dir,
        loaded_arc.as_deref(),
    )
    .unwrap_or_else(|error| panic!("pair-machine terminal replay recovery failed: {error}"));
    if loaded_arc.is_none() {
        info!(
            stage = "bootstrap.cold",
            "no household identity on disk; /identity will return 503 until `theyos install` runs"
        );
    }
    let identity_state = HouseholdState::empty();
    identity_load.publish_into(&identity_state).await;

    // Give the seeded `mac-host` row the household scope it was born without.
    //
    // `seed_mac_host_instance` runs in `main` well before this point — the
    // household is not loaded yet there, so the row is inserted with a null
    // `household_id`. `list_for_household` filters on that column, so the row
    // stays invisible to the owner's Share picker and sharing an app reports
    // "No apps to share yet" on a machine that plainly has a running mac-host.
    //
    // This is the first moment the household id is actually known, so it is
    // where the scope can honestly be applied. The alternative — teaching
    // `list_for_household` to accept unscoped rows — was rejected: an unscoped
    // row belongs to no household, and the list should keep saying so. Stamping
    // fixes the row; widening the query would move a boundary.
    //
    // `stamp_mac_host_household` only touches a row that is still fully
    // unscoped, and reports whether it did, so a partially scoped row (which is
    // ambiguous about its owner) is left alone rather than guessed at.
    if let (Some(arc), Some(state)) = (loaded_arc.as_ref(), shared_state.as_ref()) {
        adopt_seeded_mac_host(state, arc.record.hh_id.as_str(), arc.cert.m_id.as_str());
    }

    // ── Bootstrap state machine (T007 / T011) ─────────────────────────────
    //
    // Load the persisted BootstrapState. On legacy engines (no state file on
    // disk) we infer the state from the loaded identity:
    //   - identity present + owner auth present → Ready
    //   - identity present, no owner auth       → NamedAwaitingPair
    //   - no identity                           → Uninitialized
    let initial_bootstrap_state = {
        match bootstrap_state::load(&state_dir) {
            Ok(s) => s,
            Err(household_rs::bootstrap_state::BootstrapStateError::Unknown(ref raw)) => {
                tracing::warn!(
                    stage = "bootstrap_state.unknown",
                    raw = raw.as_str(),
                    "unrecognised bootstrap_state on disk; treating as Uninitialized"
                );
                BootstrapState::Uninitialized
            }
            Err(e) => {
                tracing::warn!(
                    stage = "bootstrap_state.load_error",
                    error = %e,
                    "failed to load bootstrap_state; inferring from identity"
                );
                infer_bootstrap_state(loaded_arc.as_ref(), &identity_state).await
            }
        }
    };
    // For legacy engines: if the file says Uninitialized but we already have
    // identity+auth on disk, promote to the correct live state and persist it.
    let mut initial_bootstrap_state =
        if initial_bootstrap_state == BootstrapState::Uninitialized && loaded_arc.is_some() {
            let inferred = infer_bootstrap_state(loaded_arc.as_ref(), &identity_state).await;
            if inferred == BootstrapState::Uninitialized {
                initial_bootstrap_state
            } else {
                bootstrap_state_after_inferred_persist(
                    initial_bootstrap_state,
                    inferred,
                    persist_bootstrap_state_under_lifecycle(
                        identity_load.lifecycle_guard(),
                        &state_dir,
                        inferred,
                    ),
                )
            }
        } else {
            initial_bootstrap_state
        };
    info!(
        stage = "bootstrap_state.loaded",
        state = initial_bootstrap_state.as_str(),
        "bootstrap state machine initialised"
    );
    let bootstrap_state_arc: BootstrapStateArc = Arc::new(RwLock::new(initial_bootstrap_state));
    // Install into the global; panics only if called twice (impossible in
    // single-server use).
    if BOOTSTRAP_STATE
        .set(Arc::clone(&bootstrap_state_arc))
        .is_err()
    {
        tracing::warn!("BOOTSTRAP_STATE already installed; keeping first handle");
    }
    // Synchronize the retained generation's pair-device snapshot into memory
    // before lifecycle publication ends. A sibling `theyos install` process
    // can only publish into this exact generation, and teardown cannot rotate
    // it between the disk observation and the in-memory adoption.
    if identity_state.current_owner_auth().await.is_some() {
        pair_device_window
            .close_under_lifecycle(identity_load.lifecycle_guard())
            .await
            .unwrap_or_else(|error| {
                panic!("failed to close owner-complete pair-device window: {error}")
            });
    } else {
        load_persisted_pair_device_window_under_lifecycle(
            &pair_device_window,
            identity_load.lifecycle_guard(),
        )
        .await
        .unwrap_or_else(|error| panic!("pair-device snapshot recovery failed closed: {error}"));
    }

    // Owner events are installed authority, so opening the log requires the
    // same startup-exclusive transaction and exact loaded household id. In a
    // cold state there is deliberately no log handle and no directory to
    // create.
    let owner_event_broadcaster = OwnerEventsBroadcaster::new();
    let owner_event_log = identity_load.loaded.as_ref().map(|loaded| {
        OwnerEventLog::open_with_broadcaster_under_lifecycle(
            identity_load.lifecycle_guard(),
            state_dir.clone(),
            loaded.record.hh_id.as_str(),
            owner_event_broadcaster.clone(),
        )
    });

    // The Phase-3 manifest survives local promotion as a durable terminal
    // outbox. Reconcile it while the startup lifecycle writer and exact
    // installed identity/log binding are still retained, before any listener
    // or Bonjour authority can become observable.
    let phase3_outbox_present = household_rs::storage::phase3_recovery_manifest_exists(&state_dir);
    let machine_joined_reconciled = match (identity_load.loaded.as_ref(), owner_event_log.as_ref())
    {
        (Some(loaded), Some(Ok(log))) => {
            match handlers_owner_events::reconcile_phase3_machine_joined_outbox_under_lifecycle(
                &state_dir,
                identity_load.lifecycle_guard(),
                loaded,
                log,
            ) {
                Ok(reconciled) => reconciled,
                Err(error) => {
                    tracing::error!(
                        stage = "bootstrap.phase3_machine_joined_outbox_failed",
                        error = %error,
                        "terminal Phase-3 side effect is unresolved; refusing all listeners",
                    );
                    if let Err(state_error) =
                        bootstrap_state::persist(&state_dir, BootstrapState::Recovering)
                    {
                        tracing::error!(
                            stage = "bootstrap.phase3_outbox_fail_stop_persist_failed",
                            error = %state_error,
                        );
                    } else if let Err(sync_error) =
                        identity_load.lifecycle_guard().sync_state_root()
                    {
                        tracing::error!(
                            stage = "bootstrap.phase3_outbox_fail_stop_sync_failed",
                            error = %sync_error,
                        );
                    }
                    return;
                }
            }
        }
        (_, _) if phase3_outbox_present => {
            // A retained terminal outbox is unresolved authority. In
            // particular, failure to open the owner-event log is not license
            // to publish identity/listeners while silently postponing
            // MachineJoined.
            tracing::error!(
                stage = "bootstrap.phase3_machine_joined_outbox_dependencies_unavailable",
                "terminal Phase-3 outbox exists but its exact identity/log binding is unavailable; refusing all listeners",
            );
            if let Err(state_error) =
                bootstrap_state::persist(&state_dir, BootstrapState::Recovering)
            {
                tracing::error!(
                    stage = "bootstrap.phase3_outbox_fail_stop_persist_failed",
                    error = %state_error,
                );
            } else if let Err(sync_error) = identity_load.lifecycle_guard().sync_state_root() {
                tracing::error!(
                    stage = "bootstrap.phase3_outbox_fail_stop_sync_failed",
                    error = %sync_error,
                );
            }
            return;
        }
        _ => false,
    };

    if machine_joined_reconciled {
        // A prior Phase-3 recovery failure may have latched the generic
        // fail-stop state. Repair it before clearing the manifest breadcrumb,
        // so a crash can never leave `Recovering` with no evidence identifying
        // which subsystem is now safe to resume.
        if initial_bootstrap_state == BootstrapState::Recovering {
            if !phase3_recovery_completed {
                tracing::error!(
                    stage = "bootstrap.phase3_recovery_state_unscoped",
                    "refusing to clear a Phase-3 outbox without a successful Phase-3 recovery in this boot",
                );
                return;
            }
            let recovered_state = infer_bootstrap_state(loaded_arc.as_ref(), &identity_state).await;
            if matches!(
                recovered_state,
                BootstrapState::Recovering | BootstrapState::Uninitialized
            ) {
                tracing::error!(
                    stage = "bootstrap.phase3_recovery_state_inference_failed",
                    state = recovered_state.as_str(),
                    "installed Phase-3 identity cannot be resumed safely",
                );
                return;
            }
            if let Err(error) = persist_bootstrap_state_under_lifecycle(
                identity_load.lifecycle_guard(),
                &state_dir,
                recovered_state,
            ) {
                tracing::error!(
                    stage = "bootstrap.phase3_recovery_state_persist_failed",
                    error = %error,
                );
                return;
            }
            if let Err(error) = identity_load.lifecycle_guard().sync_state_root() {
                tracing::error!(
                    stage = "bootstrap.phase3_recovery_state_sync_failed",
                    error = %error,
                );
                return;
            }
            initial_bootstrap_state = recovered_state;
            *bootstrap_state_arc.write().await = recovered_state;
        }

        if let Err(error) = household_rs::storage::clear_phase3_recovery_manifest(
            identity_load.lifecycle_guard(),
            &state_dir,
        ) {
            tracing::error!(
                stage = "bootstrap.phase3_machine_joined_outbox_clear_failed",
                error = %error,
                "event is idempotently durable but outbox absence is unresolved; refusing all listeners",
            );
            if let Err(state_error) =
                bootstrap_state::persist(&state_dir, BootstrapState::Recovering)
            {
                tracing::error!(
                    stage = "bootstrap.phase3_outbox_fail_stop_persist_failed",
                    error = %state_error,
                );
            } else if let Err(sync_error) = identity_load.lifecycle_guard().sync_state_root() {
                tracing::error!(
                    stage = "bootstrap.phase3_outbox_fail_stop_sync_failed",
                    error = %sync_error,
                );
            }
            return;
        }
    }

    let phase3_runtime = Phase3RuntimeController::new(
        state_dir.clone(),
        identity_state.clone(),
        Arc::clone(&pair_machine_window),
        key_policy,
        shared_state.clone(),
    );
    if let Some(loaded) = identity_load.loaded.as_ref() {
        let event_log = match owner_event_log.as_ref() {
            Some(Ok(event_log)) => event_log,
            // The open error used to be discarded without a binding, so an
            // installed household that could not open its own owner-event log
            // stopped here leaving no line saying why, and no listener. Bind
            // it, name the file, and latch the same fail-stop state the other
            // terminal Phase-3 branches persist.
            Some(Err(error)) => {
                let path = log_path(&state_dir);
                tracing::error!(
                    stage = "phase3_runtime.owner_event_log_open_failed",
                    error = %error,
                    path = %path.display(),
                    log_file = %describe_owner_event_log_file(&path),
                    "installed household cannot open its owner-event log; refusing all listeners",
                );
                persist_phase3_fail_stop(&state_dir, identity_load.lifecycle_guard());
                return;
            }
            None => {
                tracing::error!(
                    stage = "phase3_runtime.startup_dependencies_unavailable",
                    "installed household cannot start without its Phase 3 runtime"
                );
                persist_phase3_fail_stop(&state_dir, identity_load.lifecycle_guard());
                return;
            }
        };
        if let Err(error) = phase3_runtime
            .install_with_resources_under_lifecycle(
                identity_load.lifecycle_guard(),
                Arc::clone(loaded),
                Arc::clone(event_log),
                owner_event_broadcaster.clone(),
            )
            .await
        {
            tracing::error!(
                stage = "phase3_runtime.startup_install_failed",
                error = %error,
                "installed household cannot start without its Phase 3 runtime"
            );
            return;
        }
    }

    // `identity_state`, `bootstrap_state_arc`, both ceremony windows, and the
    // generation-bound Phase 3 bundle now all describe the exact disk
    // generation observed under this transaction. Only now may teardown
    // detach it.
    drop(identity_load);

    if machine_joined_reconciled {
        handlers_owner_events::dispatch_owner_event_tickle_if_idle(
            state_dir.clone(),
            &owner_event_broadcaster,
        );
    }

    spawn_pair_device_window_snapshot_watcher(
        state_dir.clone(),
        Arc::clone(&pair_device_window),
        identity_state.clone(),
    );

    let identity_router = axum::Router::new()
        .route(
            "/api/v1/household/identity",
            axum::routing::get(handlers_household::get_identity),
        )
        .route(
            "/api/v1/household/snapshot",
            axum::routing::get(handlers_household::snapshot).post(handlers_household::snapshot),
        )
        .with_state(identity_state.clone());

    // R101: owner-authed list of the household's own machine certs (surfaces
    // the base/self engine machine). Same PoP gate as `snapshot`, but the
    // handler also reads `machine_certs/<m_id>.cbor`, so it needs the combined
    // (identity + state_dir) state.
    let machines_router = axum::Router::new()
        .route(
            "/api/v1/household/machines",
            axum::routing::get(handlers_household::machines),
        )
        .with_state(handlers_household::MachinesRouterState {
            household: identity_state.clone(),
            state_dir: state_dir.clone(),
        });

    // B0a/B0b: read-only machine roster currency and signed roster evidence,
    // authorized as the owner **or** as an admitted household device delegated
    // by that owner (D2c). The same (identity + state_dir) state shape as
    // `machines`, but the wire is canonical CBOR rather than JSON — see
    // `handlers_household_roster`. Distinct router so the roster surface can be
    // mounted/omitted on its own.
    let roster_router = axum::Router::new()
        .route(
            handlers_household_roster::CURRENCY_PATH,
            axum::routing::get(handlers_household_roster::currency),
        )
        .route(
            handlers_household_roster::EVIDENCE_PATH,
            axum::routing::post(handlers_household_roster::evidence),
        )
        .with_state(handlers_household_roster::RosterRouterState {
            household: identity_state.clone(),
            state_dir: state_dir.clone(),
        });

    let pair_router = axum::Router::new()
        .route(
            "/api/v1/household/pair-device/initiate",
            axum::routing::post(handlers_pair_device::initiate),
        )
        .route(
            "/api/v1/household/pair-device/confirm",
            axum::routing::post(handlers_pair_device::confirm),
        )
        .with_state(handlers_pair_device::PairDeviceState {
            window: Arc::clone(&pair_device_window),
            household: identity_state.clone(),
            state_dir: state_dir.clone(),
        });

    // ── Bootstrap router (T008 / T009 / T010 / T011) ─────────────────────
    // ── Bootstrap router (T008 / T009 / T010 / T011) ─────────────────────
    // Always live — even on a cold, uninitialized engine.
    let mut bootstrap_handler_state = BootstrapHandlerState::new(
        Arc::clone(&bootstrap_state_arc),
        identity_state.clone(),
        state_dir.clone(),
        Arc::clone(&pair_device_window),
        Arc::clone(&pair_machine_window),
        port,
    )
    .with_phase3_runtime(phase3_runtime.clone());
    // The pair-code limiter is durable `SharedState` plumbing; bring-up paths
    // without it leave the field `None` and the by-code route fails closed.
    if let Some(state) = shared_state.as_ref() {
        bootstrap_handler_state =
            bootstrap_handler_state.with_pair_code_rate_limiter(Arc::clone(&state.rate_limiter));
    }
    // The setup-invitation browser turns a phone's `_soyeht-setup._tcp.`
    // beacon into a cache entry. Only two routes ever read that cache, and
    // both refuse outside onboarding: `POST /bootstrap/claim-setup-invitation`
    // answers 409 `already_initialized` unless the engine is `Uninitialized`
    // (handlers_bootstrap.rs, "1. State gate"), and `POST
    // /bootstrap/accept-household` answers 409 unless it is `Uninitialized` or
    // `ReadyForNaming`. So the spawn stays tied to those states: on a Ready
    // engine a running browser would fill a cache nothing can claim, which is
    // cost and log noise, not reachability.
    //
    // What the two-situation rule changes here is the ONE gate that was
    // silently dropping beacons: `BrowserConfig::default()` sets
    // `include_local_network = false`, so a beacon carrying nothing but
    // `192.168.x` -- exactly what a phone with no Tailscale publishes -- was
    // discarded and logged as `setup_browser.suppressed reason=non_tailnet`
    // (bonjour_browser.rs). A browser that cannot see the phone it is looking
    // for is not a gate, it is a bug.
    //
    // The flag is derived from the SAME policy the listener binds through --
    // `allows_with(state, Lan, window)` -- rather than from a second rule
    // written here, so "the home is on the local network in exactly two
    // situations" has exactly one implementation. In the two states this
    // browser runs in, situation 1 (INSTALL) already grants LAN, so the answer
    // is `true` in both window positions; expressing it through the policy is
    // what keeps it true if either half of the rule ever moves.
    //
    // The reachability half of the fix is the listener bind, not this browser:
    // `HouseholdExposurePolicy` re-admits `InterfaceClass::Lan` after
    // onboarding while a pair-device window is open, which is what gives a
    // LAN-only phone an address to dial on a Ready engine.

    // The Mac's "I am showing an Add iPhone sheet" fact, and the routes that
    // set and clear it. ONE instance: the same `Arc` reaches the routes, the
    // listener reconciler and the Bonjour publish, so what the Mac says and
    // what the exposure policy reads cannot drift. It holds no token and no
    // identity, which is why it is its own small router rather than another
    // field on `BootstrapHandlerState` -- see `local_network_visibility`.
    let local_network_visibility =
        Arc::new(crate::local_network_visibility::LocalNetworkVisibility::new());
    let local_network_visibility_rt =
        crate::local_network_visibility::local_network_visibility_router(Arc::clone(
            &local_network_visibility,
        ));

    let pairing_window = household_listener::PairingWindow::observe(
        pair_device_window.as_ref(),
        local_network_visibility.as_ref(),
    )
    .await;
    if matches!(
        initial_bootstrap_state,
        BootstrapState::Uninitialized | BootstrapState::ReadyForNaming
    ) {
        let include_local_network = household_listener::HouseholdExposurePolicy::allows_with(
            initial_bootstrap_state,
            household_listener::InterfaceClass::Lan,
            pairing_window,
        );
        info!(
            stage = "setup_browser.spawn",
            pairing_window = pairing_window.as_str(),
            include_local_network,
            bootstrap_state = initial_bootstrap_state.as_str(),
        );
        drop(bonjour_browser::spawn_setup_invitation_browser_with_cache(
            bootstrap_handler_state.setup_invitation_cache.clone(),
            BrowserConfig {
                include_local_network,
            },
        ));
    }
    let bootstrap_rt = crate::handlers_bootstrap::bootstrap_router(bootstrap_handler_state);

    // Household-namespaced Claw Store router. Wraps the shared handlers
    // (`handlers_claws::*`, also mounted on the Bearer-authenticated admin
    // router in `main.rs`) with a per-handler PoP authorization gate, so
    // every route here is restricted to delegated household devices
    // (iPhone Soyeht client) whose certs carry the matching `Operation::Claws*`
    // capability. The wrappers live in `handlers_household_claws.rs` and
    // mirror the per-handler auth pattern used by `handlers_pair_machine`
    // and `handlers_household::snapshot`. See `handlers_household_claws.rs`
    // for the route → `Operation` mapping.
    //
    // Wire format is `application/json` — the iOS Claw Store decoder is a
    // `JSONDecoder`; do not switch to CBOR here.
    //
    // Only mounted when caller supplies `SharedState` (main daemon path).
    // Short-lived bring-up paths (e.g. `theyos install` post-commit
    // listener) pass `None` and omit these routes.
    let claws_router = shared_state.clone().map(|state| {
        let claws_state = handlers_household_claws::HouseholdClawsState {
            shared: state,
            household: identity_state.clone(),
            attach_tokens: Arc::new(
                crate::household_attach_token::HouseholdAttachTokenStore::new(),
            ),
        };
        crate::claw_store_routes::household_routes()
            .route(
                "/api/v1/household/instances",
                axum::routing::get(handlers_household_claws::handle_household_list_instances)
                    .post(handlers_household_claws::handle_household_create_instance),
            )
            .route(
                "/api/v1/household/instances/{id}/status",
                axum::routing::get(handlers_household_claws::handle_household_instance_status),
            )
            .route(
                "/api/v1/household/instances/{id}/stop",
                axum::routing::post(handlers_household_claws::handle_household_stop_instance),
            )
            .route(
                "/api/v1/household/instances/{id}/restart",
                axum::routing::post(handlers_household_claws::handle_household_restart_instance),
            )
            .route(
                "/api/v1/household/instances/{id}/rebuild",
                axum::routing::post(handlers_household_claws::handle_household_rebuild_instance),
            )
            .route(
                "/api/v1/household/instances/{id}",
                axum::routing::delete(handlers_household_claws::handle_household_delete_instance),
            )
            .route(
                "/api/v1/household/terminals/{container}/workspaces",
                axum::routing::get(handlers_household_claws::handle_household_list_workspaces)
                    .post(handlers_household_claws::handle_household_create_workspace),
            )
            .route(
                "/api/v1/household/terminals/{container}/workspaces/{id}",
                axum::routing::patch(handlers_household_claws::handle_household_rename_workspace)
                    .delete(handlers_household_claws::handle_household_delete_workspace),
            )
            .route(
                "/api/v1/household/terminals/{container}/attach-token",
                axum::routing::post(handlers_household_claws::handle_household_mint_attach_token),
            )
            .route(
                "/api/v1/household/terminals/{container}/pty",
                axum::routing::get(handlers_household_claws::handle_household_terminal_pty),
            )
            .with_state(claws_state)
    });

    // Pre-household router. Carries the candidate-side `/pair-machine/local/*`
    // endpoints (`seed`, `anchor`, `finalize`) plus `/pair-machine/anchor-handoff`.
    // These were previously bound on a separate `TcpListener` inside
    // `pair_machine_local::stage` — that collided with the daemon's existing
    // bind (`addr:engine_port` is owned by `spawn_household_listeners` below).
    // Mounting them here on the SAME router that serves `/bootstrap/*` reuses
    // the daemon's listeners, shares the `Arc<PairMachineWindow>` with the
    // stage handler so the seed lookup is a zero-cost memory read, and lets
    // `local_finalize_handler` consult the engine `BootstrapState` to refuse
    // a finalize that would race a sibling `accept_household_confirm`.
    let pre_household_rt = handlers_pair_machine::pre_household_routes(
        handlers_pair_machine::PreHouseholdRouterState {
            window: Arc::clone(&pair_machine_window),
            state_dir: state_dir.clone(),
            key_policy,
            bootstrap: Some(Arc::clone(&bootstrap_state_arc)),
            runtime_signal: None,
        },
    );

    // Guest-image prepare endpoint — `POST /api/v1/household/guest-image/prepare`.
    // PoP-gated under the existing `Operation::ClawsCreate` caveat (see
    // module docs in `handlers_household_guest_image.rs` for the rationale
    // — letting already-issued owner certs initiate guest-image prep
    // without forcing a re-pair). Mounted on every host (not only when
    // `shared_state` is provided) because it relies on `init-state.json`
    // and the launcher trait, not on `SharedState`.
    let guest_image_router = {
        let guest_image_state = handlers_household_guest_image::GuestImagePrepareState {
            household: identity_state.clone(),
            inspector: Arc::new(handlers_household_guest_image::DefaultInspector),
            launcher: Arc::new(handlers_household_guest_image::MacosPrepareLauncher),
            in_flight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        axum::Router::new()
            .route(
                "/api/v1/household/guest-image/prepare",
                axum::routing::post(
                    handlers_household_guest_image::handle_household_prepare_guest_image,
                ),
            )
            .with_state(guest_image_state)
    };

    // Claw-share / relay HTTP surface. This is the mesh-free Product A relay
    // mount: the durable membership log is the source of truth, the slot store is
    // rehydrated from it on startup, and relay claim identity is loaded only when
    // the engine is actually configured to listen to Nostr relays.
    let claim_relays_env = std::env::var("THEYOS_CLAIM_RELAYS").ok();
    let nostr_relay_env = std::env::var("THEYOS_NOSTR_RELAY").ok();
    let claw_share_bootstrap = prepare_claw_share_bootstrap_state(
        &state_dir,
        nostr_relay_env.as_deref(),
        claim_relays_env.as_deref(),
    );
    let claw_share_runtime = claw_share_bootstrap.runtime.clone();
    let claw_share_router = build_claw_share_router(
        identity_state.clone(),
        state_dir.clone(),
        &claw_share_runtime,
        claw_share_bootstrap
            .engine_relay_identity
            .as_ref()
            .map(|identity| identity.npub_hex.clone()),
        shared_state.clone(),
    );
    mount_claw_share_relay_stream_live_if_enabled(
        state_dir.clone(),
        identity_state.clone(),
        &claw_share_runtime,
        shared_state.clone(),
    )
    .await;
    spawn_claw_share_relay_loop_if_configured(
        identity_state.clone(),
        state_dir.clone(),
        &claw_share_runtime,
        claw_share_bootstrap.engine_relay_identity,
        claw_share_bootstrap.relay_urls,
    );

    let mut household_router = identity_router
        .merge(pair_router)
        .merge(machines_router) // R101
        .merge(roster_router) // B0a machine roster currency
        .merge(bootstrap_rt)
        .merge(local_network_visibility_rt)
        .merge(pre_household_rt)
        .merge(guest_image_router)
        .merge(claw_share_router);
    if let Some(r) = claws_router {
        household_router = household_router.merge(r);
    }
    let phase3_fallback = phase3_runtime.clone();
    household_router = household_router.fallback(move |request| {
        let phase3_fallback = phase3_fallback.clone();
        async move { phase3_fallback.route_or_reject(request).await }
    });

    let bound_set = household_listener::BoundSet::default();
    // Re-observed here rather than reusing the value taken above for the
    // setup browser: `theyos install` can persist a live token that this
    // process adopts during bootstrap, and the initial bind must reflect the
    // window as it is at bind time, not as it was earlier in this function.
    let startup_pairing_window = household_listener::PairingWindow::observe(
        pair_device_window.as_ref(),
        local_network_visibility.as_ref(),
    )
    .await;
    let initial_bound = household_listener::spawn_household_listeners(
        startup,
        household_router.clone(),
        port,
        Arc::clone(&bootstrap_state_arc),
        &bound_set,
        startup_pairing_window,
    )
    .await;
    info!(
        stage = "bootstrap.endpoint.live",
        bound_count = initial_bound.len(),
        port = port,
        "household listeners up"
    );
    if let Some((terminal_addr, terminal_transport)) = terminal_replay_endpoint
        && (terminal_transport == household_rs::pair_machine::JoinTransport::Lan
            || terminal_addr.port() != port)
        && matches!(
            *bootstrap_state_arc.read().await,
            BootstrapState::PairMachineInstallRestartRequired | BootstrapState::Ready
        )
    {
        let exact_addr_is_already_served = initial_bound
            .iter()
            .any(|(ip, _)| SocketAddr::new(*ip, port) == terminal_addr);
        if exact_addr_is_already_served {
            tracing::info!(
                stage = "pair_machine.terminal_replay_listener_shared",
                address = %terminal_addr,
                "the policy-approved household listener already carries the terminal-only route"
            );
        } else {
            // Ready intentionally excludes the regular household router from
            // LAN. Keep only the exact retained finalize endpoint reachable
            // across the indistinguishable pre-flush/post-flush crash cuts.
            let terminal_state = handlers_pair_machine::PreHouseholdRouterState {
                window: Arc::clone(&pair_machine_window),
                state_dir: state_dir.clone(),
                key_policy,
                bootstrap: Some(Arc::clone(&bootstrap_state_arc)),
                runtime_signal: None,
            };
            let initial =
                match bind_terminal_replay_listener(terminal_addr, terminal_state.clone()).await {
                    Ok((listener, router)) => {
                        tracing::info!(
                            stage = "pair_machine.terminal_replay_listener_live",
                            address = %terminal_addr,
                        );
                        Some((listener, router))
                    }
                    Err(error) => {
                        tracing::warn!(
                            stage = "pair_machine.terminal_replay_bind_deferred",
                            address = %terminal_addr,
                            error = %error,
                            "daemon remains live and retries the exact terminal-only bind"
                        );
                        None
                    }
                };
            spawn_supervised_terminal_replay_listener(
                terminal_addr,
                terminal_transport,
                terminal_state,
                initial,
            );
        }
    }
    publish_setup_beacon_for_startup(
        Arc::clone(&bootstrap_state_arc),
        initial_bound.clone(),
        bound_set.clone(),
        port,
    )
    .await;

    // Periodic refresh — picks up new Tailscale / Wi-Fi addresses every 60s.
    // It is also the reconciler for the pair-device window, which is why it
    // now takes one: the window is what decides whether a post-onboarding
    // household is on the local network, and this loop is the only thing that
    // can bind or withdraw a listener while the engine runs.
    {
        let router = household_router;
        let bound = bound_set.clone();
        let bootstrap = Arc::clone(&bootstrap_state_arc);
        let window = Arc::clone(&pair_device_window);
        let visibility = Arc::clone(&local_network_visibility);
        tokio::spawn(async move {
            household_listener::refresh_loop(router, port, bootstrap, bound, window, visibility)
                .await;
        });
    }

    // Bonjour publisher (FR-017). Only published once identity is loaded —
    // the announcement carries hh_id/m_id and there is nothing meaningful
    // to advertise on a cold install. If the daemon starts cold, a watcher
    // hot-loads identity records written by `theyos install` and starts
    // Bonjour without requiring a restart.
    if let Some(loaded) = &loaded_arc {
        publish_household_bonjour_for_identity(
            Arc::clone(loaded),
            Arc::clone(&pair_device_window),
            Arc::clone(&pair_machine_window),
            Arc::clone(&local_network_visibility),
            initial_bound,
            port,
        )
        .await;
    } else {
        let deps = HouseholdIdentityWatcherDeps {
            pair_device_window: Arc::clone(&pair_device_window),
            pair_machine_window: Arc::clone(&pair_machine_window),
            local_network_visibility: Arc::clone(&local_network_visibility),
            targets: initial_bound,
            port,
            claw_share: Some(claw_share_runtime),
            phase3_runtime: phase3_runtime.clone(),
            shared_state: shared_state.clone(),
        };
        spawn_household_identity_watcher(state_dir, identity_state, key_policy, deps);
    }
}

async fn publish_setup_beacon_for_startup(
    bootstrap: BootstrapStateArc,
    targets: Vec<(IpAddr, InterfaceClass)>,
    bound_set: household_listener::BoundSet,
    port: u16,
) {
    let raw_hostname = gethostname::gethostname();
    let params = startup_wiring::setup_beacon_params_for_host(
        crate::handlers_bootstrap::detect_host_label(),
        raw_hostname.to_string_lossy().as_ref(),
        port,
    );

    match setup_beacon::publish_setup_beacon_with_bound_set(
        params,
        bootstrap,
        targets,
        Some(bound_set),
    )
    .await
    {
        Ok(Some(handle)) => {
            drop(tokio::spawn(async move {
                std::future::pending::<()>().await;
                drop(handle);
            }));
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(
                stage = "setup_beacon.start_failed",
                error = %e,
                "setup beacon publish failed; continuing without announcement"
            );
        }
    }
}

async fn publish_household_bonjour_for_identity(
    loaded: Arc<household_rs::LoadedIdentity>,
    pair_device_window: Arc<household_rs::pair_device::PairDeviceWindow>,
    pair_machine_window: Arc<household_rs::pair_machine::PairMachineWindow>,
    local_network_visibility: Arc<crate::local_network_visibility::LocalNetworkVisibility>,
    targets: Vec<(IpAddr, InterfaceClass)>,
    port: u16,
) {
    if !targets
        .iter()
        .any(|(_, class)| *class != InterfaceClass::Loopback)
    {
        info!(
            stage = "bonjour.skipped",
            reason = "no_non_loopback_targets",
            "household Bonjour publish skipped; no peer-reachable interface is bound"
        );
        return;
    }
    let raw_hostname = gethostname::gethostname().to_string_lossy().into_owned();
    let host_label = raw_hostname.replace(['.', ' '], "-");
    // Read current bootstrap state for the TXT enrichment field.
    let bootstrap_state = global_bootstrap_state().map_or(BootstrapState::Ready, |arc| {
        *arc.try_read().unwrap_or_else(|_| arc.blocking_read())
    });
    let bs_str = bootstrap_state.as_str().to_string();
    let params = bonjour_publisher::PublishParams {
        hh_id: loaded.record.hh_id.to_string(),
        hh_name: loaded.record.name.clone(),
        m_id: loaded.cert.m_id.to_string(),
        port,
        host_label,
        host_dns: raw_hostname,
        // Filled by `publish_household_bonjour` from the post-policy bind set.
        tailnet_addr: None,
        pair_machine_role: Some(bonjour_publisher::PairMachineBonjourRole::Founder),
        owner_display_name: String::new(), // populated by agente-front after iCloud name is known
        device_count: u32::from(bs_str == "ready"),
        bootstrap_state: bs_str,
    };
    match bonjour_publisher::publish_household_bonjour(
        params,
        pair_device_window,
        pair_machine_window,
        local_network_visibility,
        targets,
        bootstrap_state,
    )
    .await
    {
        Ok(handle) => {
            bonjour_publisher::install_household_bonjour(handle);
        }
        Err(e) => {
            tracing::warn!(
                stage = "bonjour.start_failed",
                error = %e,
                "household Bonjour publish failed; continuing without announcement"
            );
        }
    }
}

#[derive(Clone)]
struct HouseholdIdentityWatcherDeps {
    pair_device_window: Arc<household_rs::pair_device::PairDeviceWindow>,
    pair_machine_window: Arc<household_rs::pair_machine::PairMachineWindow>,
    /// The shared "Add iPhone sheet is open" fact. Carried so a Bonjour
    /// publish that happens after a hot-load observes the same two facts the
    /// listener binds on, rather than only the token half.
    local_network_visibility: Arc<crate::local_network_visibility::LocalNetworkVisibility>,
    targets: Vec<(IpAddr, InterfaceClass)>,
    port: u16,
    claw_share: Option<ClawShareRuntimeHandles>,
    phase3_runtime: Phase3RuntimeController,
    /// Carried solely so the two post-pairing REMOUNTS below can hand it to the
    /// relay-stream mount. The watcher closure cannot reach `bootstrap_household`'s
    /// `shared_state` any other way, and without it those remounts would silently
    /// mount with `None` while the first mount had it.
    shared_state: Option<SharedState>,
}

fn spawn_household_identity_watcher(
    state_dir: PathBuf,
    identity_state: HouseholdState,
    key_policy: KeyBackingPolicy,
    deps: HouseholdIdentityWatcherDeps,
) {
    let _watcher = spawn_household_identity_watcher_with_interval(
        state_dir,
        identity_state,
        key_policy,
        Duration::from_secs(2),
        deps,
    );
}

fn spawn_household_identity_watcher_with_interval(
    state_dir: PathBuf,
    identity_state: HouseholdState,
    key_policy: KeyBackingPolicy,
    poll_interval: Duration,
    deps: HouseholdIdentityWatcherDeps,
) -> tokio::task::JoinHandle<()> {
    let HouseholdIdentityWatcherDeps {
        pair_device_window,
        pair_machine_window,
        local_network_visibility,
        targets,
        port,
        claw_share,
        phase3_runtime,
        shared_state,
    } = deps;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        loop {
            interval.tick().await;
            if let Some(loaded) = identity_state.current().await {
                info!(
                    stage = "bootstrap.hot_loaded",
                    hh_id = %loaded.record.hh_id,
                    name = %loaded.record.name,
                    created_at = loaded.record.created_at,
                    source = "in_process_initialize",
                );
                publish_household_bonjour_for_identity(
                    Arc::clone(&loaded),
                    Arc::clone(&pair_device_window),
                    Arc::clone(&pair_machine_window),
                    Arc::clone(&local_network_visibility),
                    targets.clone(),
                    port,
                )
                .await;
                if let Some(runtime) = &claw_share {
                    mount_claw_share_relay_stream_live_if_enabled(
                        state_dir.clone(),
                        identity_state.clone(),
                        runtime,
                        shared_state.clone(),
                    )
                    .await;
                }
                break;
            }
            let load_state_dir = state_dir.clone();
            match tokio::task::spawn_blocking(move || {
                acquire_and_load_identity_under_lifecycle(&load_state_dir, key_policy)
            })
            .await
            {
                Ok(Ok(identity_load)) if identity_load.loaded.is_some() => {
                    let loaded = Arc::clone(
                        identity_load
                            .loaded
                            .as_ref()
                            .expect("guarded by match condition"),
                    );
                    // Set identity + owner_auth atomically so no reader sees the
                    // intermediate state (identity=Some, owner_auth=None) that
                    // causes infer_bootstrap_state to return NamedAwaitingPair.
                    // The lifecycle exclusive remains owned by `identity_load`
                    // until both pieces of memory authority are published.
                    let close_window = identity_load.owner_auth.is_some();
                    identity_load.publish_into(&identity_state).await;
                    if let Err(error) = phase3_runtime
                        .install_under_lifecycle(
                            identity_load.lifecycle_guard(),
                            Arc::clone(&loaded),
                        )
                        .await
                    {
                        tracing::error!(
                            stage = "phase3_runtime.hot_install_failed",
                            error = %error,
                            "hot-loaded household remains fail-closed without Phase 3"
                        );
                        return;
                    }
                    if close_window {
                        let _ = pair_device_window.close().await;
                    }
                    drop(identity_load);
                    if let Some(runtime) = &claw_share {
                        mount_claw_share_relay_stream_live_if_enabled(
                            state_dir.clone(),
                            identity_state.clone(),
                            runtime,
                            shared_state.clone(),
                        )
                        .await;
                    }
                    info!(
                        stage = "bootstrap.hot_loaded",
                        hh_id = %loaded.record.hh_id,
                        name = %loaded.record.name,
                        created_at = loaded.record.created_at,
                    );
                    publish_household_bonjour_for_identity(
                        loaded,
                        Arc::clone(&pair_device_window),
                        Arc::clone(&pair_machine_window),
                        Arc::clone(&local_network_visibility),
                        targets,
                        port,
                    )
                    .await;
                    break;
                }
                Ok(Ok(_cold)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(
                        stage = "bootstrap.hot_load_failed",
                        error = %error,
                        "household identity hot-load failed; retrying"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        stage = "bootstrap.hot_load_worker_failed",
                        error = %error,
                        "household identity hot-load worker failed; retrying"
                    );
                }
            }
        }
    })
}

fn load_owner_auth_for_identity(
    state_dir: &Path,
    loaded: &household_rs::LoadedIdentity,
) -> Option<Arc<household_rs::HouseholdAuthState>> {
    let now = time_util::unix_now_secs_checked("owner_auth.load.clock")?;
    match household_rs::HouseholdAuthState::load_optional(state_dir, &loaded.record, now) {
        Ok(Some(auth)) => {
            info!(
                stage = "owner_auth.loaded",
                hh_id = %auth.hh_id,
                p_id = %auth.owner_person_cert.p_id.0,
            );
            Some(Arc::new(auth))
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(
                stage = "owner_auth.load_failed",
                error = %e,
                "owner auth state not trusted"
            );
            None
        }
    }
}

fn spawn_pair_device_window_snapshot_watcher(
    state_dir: PathBuf,
    pair_device_window: Arc<household_rs::pair_device::PairDeviceWindow>,
    identity_state: HouseholdState,
) {
    let _watcher = spawn_pair_device_window_snapshot_watcher_with_interval(
        state_dir,
        pair_device_window,
        identity_state,
        Duration::from_secs(2),
    );
}

fn spawn_pair_device_window_snapshot_watcher_with_interval(
    _state_dir: PathBuf,
    pair_device_window: Arc<household_rs::pair_device::PairDeviceWindow>,
    identity_state: HouseholdState,
    poll_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        loop {
            interval.tick().await;
            if identity_state.current_owner_auth().await.is_some() {
                if let Err(error) = pair_device_window.close().await {
                    tracing::error!(
                        stage = "pair_device_window.owner_close_failed",
                        error = %error,
                        "pair-device authority closed in memory but its exact-generation snapshot could not be durably removed"
                    );
                }
                break;
            }

            match load_pair_device_window_snapshot_if_new(&pair_device_window).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(
                        stage = "pair_device_window.snapshot_reload_failed",
                        error = %e,
                        "closing the exact-generation pair-window snapshot"
                    );
                    if let Err(close_error) = pair_device_window.close().await {
                        tracing::error!(
                            stage = "pair_device_window.snapshot_close_failed",
                            error = %close_error,
                            "pair-device authority closed in memory but cleanup remains indeterminate"
                        );
                    }
                }
            }
        }
    })
}

async fn load_pair_device_window_snapshot_if_new(
    pair_device_window: &household_rs::pair_device::PairDeviceWindow,
) -> Result<(), String> {
    let snap = pair_device_window.read_persisted_snapshot()?;
    let Some(snap) = snap else {
        return Ok(());
    };
    let Some(token) = household_rs::pair_device::PairToken::from_snapshot(&snap)
        .map_err(|e| format!("decode pair-window snapshot: {e}"))?
    else {
        pair_device_window.close().await?;
        return Ok(());
    };
    let expires_at_unix = token.expires_at_unix;
    let installed = pair_device_window
        .install_token_from_current_snapshot(token, &snap)
        .await?;
    if installed {
        info!(
            stage = "pair_device_window.opened",
            source = "snapshot_reload",
            expires_at_unix = expires_at_unix,
        );
    }
    Ok(())
}

/// Read a persisted pair-window snapshot (if any) and install it into the
/// in-memory `PairDeviceWindow`. Returns `Ok(())` on success or absence,
/// `Err(String)` on parse / decode errors.
async fn load_persisted_pair_device_window_under_lifecycle(
    pair_device_window: &household_rs::pair_device::PairDeviceWindow,
    lifecycle: &LifecycleWriteGuard,
) -> Result<(), String> {
    let snap = pair_device_window.read_persisted_snapshot_under_lifecycle(lifecycle)?;
    let Some(snap) = snap else {
        return Ok(());
    };
    let token = household_rs::pair_device::PairToken::from_snapshot(&snap)
        .map_err(|e| format!("decode pair-window snapshot: {e}"))?;
    match token {
        Some(token) => {
            info!(
                stage = "pair_device_window.opened",
                source = "snapshot",
                expires_at_unix = snap.expires_at_unix,
            );
            let _ = pair_device_window
                .install_token_from_current_snapshot_under_lifecycle(token, &snap, lifecycle)
                .await?;
        }
        None => {
            // Expired snapshot: clean it up.
            pair_device_window.close_under_lifecycle(lifecycle).await?;
        }
    }
    Ok(())
}

/// Infer the `BootstrapState` from the loaded identity.
///
/// Used as a fallback when no `identity.bootstrap_state` file exists (legacy
/// engines, or state-dir corruption). The inferred state is only a best-effort
/// approximation; the file-based state is authoritative.
async fn infer_bootstrap_state(
    loaded: Option<&Arc<household_rs::LoadedIdentity>>,
    household: &HouseholdState,
) -> BootstrapState {
    if loaded.is_none() {
        return BootstrapState::Uninitialized;
    }
    if household.current_owner_auth().await.is_some() {
        BootstrapState::Ready
    } else {
        BootstrapState::NamedAwaitingPair
    }
}

fn bootstrap_state_after_inferred_persist(
    current: BootstrapState,
    inferred: BootstrapState,
    persist_result: Result<(), household_rs::bootstrap_state::BootstrapStateError>,
) -> BootstrapState {
    match persist_result {
        Ok(()) => inferred,
        Err(error) => {
            tracing::warn!(
                stage = "bootstrap_state.infer_persist_failed",
                error = %error,
                retained_state = current.as_str(),
                rejected_inference = inferred.as_str(),
                "refusing to publish an inferred bootstrap state that was not durably persisted"
            );
            current
        }
    }
}

fn persist_bootstrap_state_under_lifecycle(
    lifecycle: &LifecycleWriteGuard,
    state_dir: &Path,
    state: BootstrapState,
) -> Result<(), household_rs::bootstrap_state::BootstrapStateError> {
    if state != BootstrapState::Ready {
        return bootstrap_state::persist(state_dir, state);
    }
    let generation = lifecycle
        .lifecycle_generation()?
        .ok_or(household_rs::bootstrap_state::BootstrapStateError::ReadyGenerationChanged)?;
    bootstrap_state::persist_ready_under_lifecycle(lifecycle, state_dir, generation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, Request, StatusCode};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
    use household_rs::claw_share::{SlotId, SlotState};
    use household_rs::household_mesh_log::{LogEntry, MeshEvent};
    use household_rs::keys::{IdentityKey, P256Keypair};
    use household_rs::person_cert::SignOwnerOptions;
    use household_rs::pop::{PairingProofContext, RequestSigningContext};
    use serde::Serialize;

    static RECOVERY_TIMEOUT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static PHASE3_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[test]
    fn phase3_surface_has_one_production_factory() {
        let source = include_str!("household_bootstrap.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert_eq!(production.matches("fn phase3_router(").count(), 1);
        assert!(!production.contains("pair_machine_router"));
        for path in [
            "/api/v1/household/join-request",
            "/api/v1/household/owner-events",
            "/api/v1/household/owner-device/push-token",
            "/api/v1/household/owner-webauthn/registration/start",
            "/api/v1/household/owner-webauthn/registration/finish",
            "/api/v1/household/owner-webauthn/registration/status",
            "/api/v1/household/owner-webauthn/revoke/start",
            "/api/v1/household/owner-webauthn/revoke/finish",
            "/api/v1/household/owner-webauthn/add-credential/start",
            "/api/v1/household/owner-webauthn/add-credential/finish",
            "/api/v1/household/owner-webauthn/recovery/status",
            "/api/v1/household/owner-webauthn/recovery/start",
            "/api/v1/household/owner-webauthn/recovery/finish",
            "/api/v1/household/owner-webauthn/recovery/consume/start",
            "/api/v1/household/owner-webauthn/recovery/consume/finish",
            "/api/v1/household/owner-events/{cursor}/approve",
            "/api/v1/household/owner-events/{cursor}/approval-v2/start",
            "/api/v1/household/owner-events/{cursor}/decline",
            "/api/v1/household/device-pairing/request",
            "/api/v1/household/device-pairing/approve",
            "/api/v1/household/device-pairing/requests",
            "/api/v1/household/device-pairing/reject",
            "/api/v1/household/device-pairing/{request_id}",
        ] {
            let literal = format!("\"{path}\"");
            assert_eq!(
                production.matches(&literal).count(),
                1,
                "Phase 3 path must be declared only by the single factory: {path}"
            );
        }
        for symbol in [
            "SECURE_UPGRADE_APP_ATTEST_START_PATH",
            "SECURE_UPGRADE_APP_ATTEST_FINISH_PATH",
            "sign_machine_cert_router(",
            "spawn_owner_timeout_watchdog(",
            "spawn_macos_local_registration_listener(",
            "spawn_bonjour_browser(",
            "OwnerWebauthnRuntime::build(",
            ".with_owner_webauthn_rp_shared(",
            ".with_owner_webauthn_anchor(",
            "let owner_webauthn_network = owner_webauthn_network_enabled();",
        ] {
            assert_eq!(
                production.matches(symbol).count(),
                1,
                "Phase 3 resource/route must have one production owner: {symbol}"
            );
        }
        // Building a second RP is how the two routers would silently end up
        // with a challenge store each.
        assert!(
            !production.contains(".with_owner_webauthn_rp("),
            "owner passkey RP must reach both routers as one shared instance"
        );
    }

    #[tokio::test]
    async fn phase3_router_slot_rejects_a_router_from_an_old_generation() {
        let temp = tempfile::tempdir().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        let generation = write.ensure_lifecycle_generation().unwrap();
        drop(write);

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&calls);
        let router = axum::Router::new().fallback(move || {
            let calls = Arc::clone(&calls_for_handler);
            async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                StatusCode::NO_CONTENT
            }
        });
        let slot = Phase3RouterSlot::new(temp.path().to_path_buf());
        slot.publish(generation, router).await;

        let live = slot
            .route_or_reject(Request::new(axum::body::Body::empty()))
            .await;
        assert_eq!(live.status(), StatusCode::NO_CONTENT);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        std::fs::create_dir(temp.path().join("household")).unwrap();
        std::fs::write(
            temp.path().join("household/household_record.cbor"),
            b"generation-rotation-fixture",
        )
        .unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        assert!(write.rename_household_to_tearing_down().unwrap());
        drop(write);

        let stale = slot
            .route_or_reject(Request::new(axum::body::Body::empty()))
            .await;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the stale generation must be rejected before its handler runs"
        );
    }

    #[tokio::test]
    async fn phase3_retire_cancels_a_pending_request_before_exclusive_rotation() {
        let temp = tempfile::tempdir().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        let generation = write.ensure_lifecycle_generation().unwrap();
        drop(write);

        let entered = Arc::new(tokio::sync::Notify::new());
        let entered_by_handler = Arc::clone(&entered);
        let router = axum::Router::new().route(
            "/pending",
            axum::routing::get(move || {
                let entered = Arc::clone(&entered_by_handler);
                async move {
                    entered.notify_one();
                    std::future::pending::<StatusCode>().await
                }
            }),
        );
        let slot = Phase3RouterSlot::new(temp.path().to_path_buf());
        slot.publish(generation, router).await;
        let request_slot = slot.clone();
        let request = tokio::spawn(async move {
            request_slot
                .route_or_reject(
                    Request::builder()
                        .uri("/pending")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("pending handler entered");

        tokio::time::timeout(Duration::from_secs(2), slot.retire())
            .await
            .expect("retire cancels and joins the pending route lease");
        let response = tokio::time::timeout(Duration::from_secs(2), request)
            .await
            .expect("request cancellation completes")
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        std::fs::create_dir(temp.path().join("household")).unwrap();
        std::fs::write(
            temp.path().join("household/household_record.cbor"),
            b"concurrent-generation-rotation-fixture",
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::task::spawn_blocking({
                let state_dir = temp.path().to_path_buf();
                move || {
                    let lifecycle = HouseholdLifecycleLock::open_verified(&state_dir).unwrap();
                    let write = lifecycle.lock_exclusive().unwrap();
                    assert!(write.rename_household_to_tearing_down().unwrap());
                }
            })
            .await
            .unwrap();
        })
        .await
        .expect("exclusive lifecycle rotation is not starved by the long-poll");

        let stale = slot
            .route_or_reject(Request::new(axum::body::Body::empty()))
            .await;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
    }

    #[derive(Serialize)]
    struct TestInitializeRequest<'a> {
        v: u8,
        name: &'a str,
    }

    #[allow(unsafe_code)]
    async fn initialize_and_confirm_phase3_owner(
        state: BootstrapHandlerState,
        household: &HouseholdState,
        pair_device_window: &Arc<household_rs::pair_device::PairDeviceWindow>,
        state_dir: &Path,
    ) -> P256Keypair {
        let prior_force_software = std::env::var_os("THEYOS_FORCE_SOFTWARE_KEYS");
        // SAFETY: the value is restored immediately after the initialize
        // request. Existing first-owner tests use the same process fixture.
        unsafe { std::env::set_var("THEYOS_FORCE_SOFTWARE_KEYS", "1") };
        let initialize_body = household_rs::cbor::to_canonical_vec(&TestInitializeRequest {
            v: 1,
            name: "Phase Three Home",
        })
        .unwrap();
        let initialized = crate::handlers_bootstrap::bootstrap_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/bootstrap/initialize")
                    .body(axum::body::Body::from(initialize_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        match prior_force_software {
            Some(value) => unsafe { std::env::set_var("THEYOS_FORCE_SOFTWARE_KEYS", value) },
            None => unsafe { std::env::remove_var("THEYOS_FORCE_SOFTWARE_KEYS") },
        }
        assert_eq!(initialized.status(), StatusCode::OK);

        let identity = household.current().await.expect("identity published");
        let token = pair_device_window
            .current_token()
            .await
            .expect("initialize opened pair-device window");
        let owner = P256Keypair::generate();
        let pairing_context =
            PairingProofContext::new(identity.record.hh_id.clone(), token.nonce.0, owner.public());
        let proof = owner
            .sign(&pairing_context.canonical_bytes().unwrap())
            .unwrap();
        let confirm_body = serde_json::json!({
            "v": 1,
            "nonce": token.nonce.as_b64(),
            "p_pub": B64URL.encode(owner.public().as_bytes()),
            "display_name": "Owner",
            "proof_sig": B64URL.encode(proof.as_bytes()),
        });
        let confirmed = axum::Router::new()
            .route(
                "/api/v1/household/pair-device/confirm",
                axum::routing::post(handlers_pair_device::confirm),
            )
            .with_state(handlers_pair_device::PairDeviceState {
                window: Arc::clone(pair_device_window),
                household: household.clone(),
                state_dir: state_dir.to_path_buf(),
            })
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/household/pair-device/confirm")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&confirm_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(confirmed.status(), StatusCode::OK);
        assert!(household.current_owner_auth().await.is_some());
        owner
    }

    #[tokio::test]
    async fn cold_initialize_confirm_installs_the_full_phase3_router_before_success() {
        let _phase3_test = PHASE3_TEST_LOCK.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let bootstrap = Arc::new(RwLock::new(BootstrapState::Uninitialized));
        let household = HouseholdState::empty();
        let pair_device_window = Arc::new(
            household_rs::pair_device::PairDeviceWindow::with_persistence(
                temp.path().to_path_buf(),
            )
            .unwrap(),
        );
        let pair_machine_window = Arc::new(PairMachineWindow::new_in_memory());
        let runtime = Phase3RuntimeController::new(
            temp.path().to_path_buf(),
            household.clone(),
            Arc::clone(&pair_machine_window),
            KeyBackingPolicy::ForceSoftware,
            None,
        );
        let state = BootstrapHandlerState::new(
            Arc::clone(&bootstrap),
            household.clone(),
            temp.path().to_path_buf(),
            Arc::clone(&pair_device_window),
            Arc::clone(&pair_machine_window),
            8091,
        )
        .with_phase3_runtime(runtime.clone());

        let pre_initialize_dispatch =
            PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        let before = runtime
            .route_or_reject(
                Request::builder()
                    .uri("/api/v1/household/owner-events?since=AA")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(before.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            pre_initialize_dispatch,
            "an absent cold runtime must reject before any Phase 3 handler"
        );

        let owner = initialize_and_confirm_phase3_owner(
            state,
            &household,
            &pair_device_window,
            temp.path(),
        )
        .await;
        let generation0 = runtime.inner.read().await.as_ref().unwrap().generation;

        let dispatch_before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        let invented = runtime
            .route_or_reject(
                Request::builder()
                    .uri("/api/v1/household/not-a-route")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(invented.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            dispatch_before,
            "an invented route must not enter the Phase 3 handler surface"
        );

        let invalid_pop = runtime
            .route_or_reject(
                Request::builder()
                    .uri("/api/v1/household/owner-events?since=AA")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(invalid_pop.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            dispatch_before + 1,
            "invalid PoP must reach the mounted owner-events handler"
        );

        let complete_surface = [
            (Method::POST, "/api/v1/household/join-request"),
            (Method::POST, "/api/v1/household/owner-device/push-token"),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/registration/start",
            ),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/registration/finish",
            ),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/registration/status",
            ),
            (
                Method::POST,
                handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_START_PATH,
            ),
            (
                Method::POST,
                handlers_owner_events::SECURE_UPGRADE_APP_ATTEST_FINISH_PATH,
            ),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/revoke/start",
            ),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/revoke/finish",
            ),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/add-credential/start",
            ),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/add-credential/finish",
            ),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/recovery/status",
            ),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/recovery/start",
            ),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/recovery/finish",
            ),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/recovery/consume/start",
            ),
            (
                Method::POST,
                "/api/v1/household/owner-webauthn/recovery/consume/finish",
            ),
            (Method::POST, "/api/v1/household/owner-events/AA/approve"),
            (
                Method::POST,
                "/api/v1/household/owner-events/AA/approval-v2/start",
            ),
            (Method::POST, "/api/v1/household/owner-events/AA/decline"),
            (Method::POST, "/api/v1/household/device-pairing/request"),
            (Method::POST, "/api/v1/household/device-pairing/approve"),
            (Method::GET, "/api/v1/household/device-pairing/requests"),
            (Method::POST, "/api/v1/household/device-pairing/reject"),
            (
                Method::GET,
                "/api/v1/household/device-pairing/request-alpha",
            ),
            (Method::POST, "/api/v1/household/sign-machine-cert"),
        ];
        for (method, path) in complete_surface {
            let before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                runtime.route_or_reject(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("Phase 3 route did not complete: {path}"));
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "missing route: {path}"
            );
            assert_ne!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "wrong method binding: {path}"
            );
            assert_eq!(
                PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
                before + 1,
                "route bypassed the sole Phase 3 factory: {path}"
            );
        }

        let uri = "/api/v1/household/owner-events?since=AA";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signing = RequestSigningContext::new("GET", uri, now, b"");
        let signature = owner.sign(&signing.canonical_bytes().unwrap()).unwrap();
        let authorization = format!(
            "Soyeht-PoP v1:{}:{}:{}",
            household_rs::derive_person_id(&owner.public()).0,
            now,
            B64URL.encode(signature.as_bytes())
        );
        let pending_runtime = runtime.clone();
        let pending = tokio::spawn(async move {
            pending_runtime
                .route_or_reject(
                    Request::builder()
                        .uri(uri)
                        .header(axum::http::header::AUTHORIZATION, authorization)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !pending.is_finished(),
            "valid owner-events request must remain in long-poll"
        );
        tokio::time::timeout(Duration::from_secs(2), runtime.deactivate())
            .await
            .expect("teardown cancels the owner-events long-poll")
            .unwrap();
        assert_eq!(pending.await.unwrap().status(), StatusCode::UNAUTHORIZED);

        let state_dir = temp.path().to_path_buf();
        tokio::task::spawn_blocking({
            let state_dir = state_dir.clone();
            move || {
                let lifecycle = HouseholdLifecycleLock::open_verified(&state_dir).unwrap();
                let write = lifecycle.lock_exclusive().unwrap();
                assert!(write.rename_household_to_tearing_down().unwrap());
                assert!(write.remove_tearing_down().unwrap());
            }
        })
        .await
        .unwrap();
        household.clear().await;
        household_rs::bootstrap_or_load(
            &state_dir,
            household_rs::BootstrapOpts {
                household_name: "Generation One Home".to_string(),
                hostname_label: Some("engine-beta".to_string()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();
        let generation1_load =
            acquire_and_load_identity_under_lifecycle(&state_dir, KeyBackingPolicy::ForceSoftware)
                .unwrap();
        let generation1_identity = Arc::clone(generation1_load.loaded.as_ref().unwrap());
        generation1_load.publish_into(&household).await;
        runtime
            .install_under_lifecycle(generation1_load.lifecycle_guard(), generation1_identity)
            .await
            .unwrap();
        let generation1 = runtime.inner.read().await.as_ref().unwrap().generation;
        assert_ne!(
            generation1, generation0,
            "reinitialize must rotate generation"
        );
        drop(generation1_load);

        let old_owner_before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old_owner_signing = RequestSigningContext::new("GET", uri, now, b"");
        let old_owner_signature = owner
            .sign(&old_owner_signing.canonical_bytes().unwrap())
            .unwrap();
        let old_owner_authorization = format!(
            "Soyeht-PoP v1:{}:{}:{}",
            household_rs::derive_person_id(&owner.public()).0,
            now,
            B64URL.encode(old_owner_signature.as_bytes())
        );
        let old_owner_response = runtime
            .route_or_reject(
                Request::builder()
                    .uri(uri)
                    .header(axum::http::header::AUTHORIZATION, old_owner_authorization)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(old_owner_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            old_owner_before + 1,
            "G1 handles the request but must reject G0 owner authority"
        );
        runtime.deactivate().await.unwrap();
    }

    #[tokio::test]
    async fn cold_initialize_without_runtime_install_stays_on_generic_401() {
        let _phase3_test = PHASE3_TEST_LOCK.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let bootstrap = Arc::new(RwLock::new(BootstrapState::Uninitialized));
        let household = HouseholdState::empty();
        let pair_device_window = Arc::new(
            household_rs::pair_device::PairDeviceWindow::with_persistence(
                temp.path().to_path_buf(),
            )
            .unwrap(),
        );
        let pair_machine_window = Arc::new(PairMachineWindow::new_in_memory());
        let runtime = Phase3RuntimeController::new(
            temp.path().to_path_buf(),
            household.clone(),
            Arc::clone(&pair_machine_window),
            KeyBackingPolicy::ForceSoftware,
            None,
        );
        let state_without_install = BootstrapHandlerState::new(
            bootstrap,
            household.clone(),
            temp.path().to_path_buf(),
            Arc::clone(&pair_device_window),
            pair_machine_window,
            8091,
        );
        initialize_and_confirm_phase3_owner(
            state_without_install,
            &household,
            &pair_device_window,
            temp.path(),
        )
        .await;

        let before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        let response = runtime
            .route_or_reject(
                Request::builder()
                    .uri("/api/v1/household/owner-events?since=AA")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            before,
            "mutant without the cold install must never reach owner-events"
        );
    }

    #[tokio::test]
    async fn warm_identity_installs_and_retires_the_complete_phase3_bundle() {
        let _phase3_test = PHASE3_TEST_LOCK.lock().await;
        let temp = tempfile::tempdir().unwrap();
        household_rs::bootstrap_or_load(
            temp.path(),
            household_rs::BootstrapOpts {
                household_name: "Warm Home".to_string(),
                hostname_label: Some("engine-alpha".to_string()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();
        let household = HouseholdState::empty();
        let pair_machine_window =
            Arc::new(PairMachineWindow::with_persistence(temp.path().to_path_buf()).unwrap());
        let runtime = Phase3RuntimeController::new(
            temp.path().to_path_buf(),
            household.clone(),
            pair_machine_window,
            KeyBackingPolicy::ForceSoftware,
            None,
        );
        let identity_load =
            acquire_and_load_identity_under_lifecycle(temp.path(), KeyBackingPolicy::ForceSoftware)
                .unwrap();
        let loaded = Arc::clone(identity_load.loaded.as_ref().unwrap());
        identity_load.publish_into(&household).await;
        runtime
            .install_under_lifecycle(identity_load.lifecycle_guard(), loaded)
            .await
            .unwrap();
        let expected_generation = identity_load
            .lifecycle_guard()
            .lifecycle_generation()
            .unwrap()
            .unwrap();
        assert_eq!(
            runtime.inner.read().await.as_ref().unwrap().generation,
            expected_generation
        );
        #[cfg(target_os = "macos")]
        let socket_path = runtime
            .inner
            .read()
            .await
            .as_ref()
            .unwrap()
            .macos_local_listener
            .as_ref()
            .unwrap()
            .socket_path()
            .to_path_buf();
        #[cfg(target_os = "macos")]
        assert!(socket_path.exists(), "warm bundle owns the local UDS");
        drop(identity_load);

        let before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        let invalid_pop = runtime
            .route_or_reject(
                Request::builder()
                    .uri("/api/v1/household/owner-events?since=AA")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(invalid_pop.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            before + 1,
            "warm startup must publish the complete Phase 3 factory"
        );

        runtime.deactivate().await.unwrap();
        assert!(runtime.inner.read().await.is_none());
        #[cfg(target_os = "macos")]
        assert!(
            !socket_path.exists(),
            "retiring the warm bundle removes its owned local UDS"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn phase3_deactivate_propagates_replaced_uds_ownership_failure() {
        let _phase3_test = PHASE3_TEST_LOCK.lock().await;
        let temp = tempfile::tempdir().unwrap();
        household_rs::bootstrap_or_load(
            temp.path(),
            household_rs::BootstrapOpts {
                household_name: "Socket Ownership Home".to_string(),
                hostname_label: Some("engine-alpha".to_string()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();
        let household = HouseholdState::empty();
        let runtime = Phase3RuntimeController::new(
            temp.path().to_path_buf(),
            household.clone(),
            Arc::new(PairMachineWindow::with_persistence(temp.path().to_path_buf()).unwrap()),
            KeyBackingPolicy::ForceSoftware,
            None,
        );
        let identity_load =
            acquire_and_load_identity_under_lifecycle(temp.path(), KeyBackingPolicy::ForceSoftware)
                .unwrap();
        let loaded = Arc::clone(identity_load.loaded.as_ref().unwrap());
        identity_load.publish_into(&household).await;
        runtime
            .install_under_lifecycle(identity_load.lifecycle_guard(), loaded)
            .await
            .unwrap();
        let socket_path = runtime
            .inner
            .read()
            .await
            .as_ref()
            .unwrap()
            .macos_local_listener
            .as_ref()
            .unwrap()
            .socket_path()
            .to_path_buf();
        drop(identity_load);

        std::fs::remove_file(&socket_path).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let error = runtime.deactivate().await.unwrap_err();
        assert!(
            error.contains("refusing to remove replaced macOS local socket identity"),
            "ownership failure must propagate through the runtime: {error}"
        );
        assert!(
            socket_path.exists(),
            "runtime must not unlink a replacement socket"
        );
        drop(replacement);
        std::fs::remove_file(socket_path).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn phase3_replace_stops_before_binding_over_any_replaced_uds_path() {
        let _phase3_test = PHASE3_TEST_LOCK.lock().await;
        for replacement_kind in ["file", "symlink", "socket"] {
            let temp = tempfile::tempdir().unwrap();
            household_rs::bootstrap_or_load(
                temp.path(),
                household_rs::BootstrapOpts {
                    household_name: format!("Replacement {replacement_kind} Home"),
                    hostname_label: Some("engine-alpha".to_string()),
                },
                KeyBackingPolicy::ForceSoftware,
            )
            .unwrap();
            let household = HouseholdState::empty();
            let runtime = Phase3RuntimeController::new(
                temp.path().to_path_buf(),
                household.clone(),
                Arc::new(PairMachineWindow::with_persistence(temp.path().to_path_buf()).unwrap()),
                KeyBackingPolicy::ForceSoftware,
                None,
            );
            let identity_load = acquire_and_load_identity_under_lifecycle(
                temp.path(),
                KeyBackingPolicy::ForceSoftware,
            )
            .unwrap();
            let loaded = Arc::clone(identity_load.loaded.as_ref().unwrap());
            identity_load.publish_into(&household).await;
            runtime
                .install_under_lifecycle(identity_load.lifecycle_guard(), Arc::clone(&loaded))
                .await
                .unwrap();
            let old_generation = runtime.inner.read().await.as_ref().unwrap().generation;
            let socket_path = runtime
                .inner
                .read()
                .await
                .as_ref()
                .unwrap()
                .macos_local_listener
                .as_ref()
                .unwrap()
                .socket_path()
                .to_path_buf();
            std::fs::remove_file(&socket_path).unwrap();

            let mut replacement_socket = None;
            let mut symlink_target = None;
            match replacement_kind {
                "file" => std::fs::write(&socket_path, b"replacement").unwrap(),
                "symlink" => {
                    let target = temp.path().join("replacement-target");
                    std::fs::write(&target, b"target").unwrap();
                    std::os::unix::fs::symlink(&target, &socket_path).unwrap();
                    symlink_target = Some(target);
                }
                "socket" => {
                    replacement_socket =
                        Some(std::os::unix::net::UnixListener::bind(&socket_path).unwrap());
                }
                _ => unreachable!(),
            }

            let error = runtime
                .install_under_lifecycle(identity_load.lifecycle_guard(), loaded)
                .await
                .unwrap_err();
            assert!(
                error.contains("refusing to remove replaced macOS local socket"),
                "{replacement_kind} ownership failure must stop replacement install: {error}"
            );
            assert!(runtime.inner.read().await.is_none());
            assert!(runtime.router.router.read().await.is_none());
            assert!(
                socket_path.exists() || socket_path.symlink_metadata().is_ok(),
                "{replacement_kind} path must not be removed or rebound"
            );
            assert_ne!(
                runtime
                    .inner
                    .read()
                    .await
                    .as_ref()
                    .map(|bundle| bundle.generation),
                Some(old_generation),
                "no old or new generation may remain published after failed replacement"
            );

            drop(replacement_socket);
            std::fs::remove_file(&socket_path).unwrap();
            drop(symlink_target);
        }
    }

    struct RecoveryTimeoutEnvRestore(Option<std::ffi::OsString>);

    #[allow(unsafe_code)]
    impl Drop for RecoveryTimeoutEnvRestore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => {
                    // SAFETY: every mutation of this process-global variable in
                    // this test binary is serialized by RECOVERY_TIMEOUT_ENV_LOCK.
                    unsafe {
                        std::env::set_var(household_rs::pair_machine::RECOVERY_TIMEOUT_ENV, value);
                    }
                }
                None => {
                    // SAFETY: see the serialized-environment invariant above.
                    unsafe {
                        std::env::remove_var(household_rs::pair_machine::RECOVERY_TIMEOUT_ENV);
                    }
                }
            }
        }
    }

    #[allow(unsafe_code)]
    fn with_recovery_timeout_env<T>(value: Option<&str>, inspect: impl FnOnce() -> T) -> T {
        let _lock = RECOVERY_TIMEOUT_ENV_LOCK
            .lock()
            .expect("recovery-timeout env lock poisoned");
        let _restore = RecoveryTimeoutEnvRestore(std::env::var_os(
            household_rs::pair_machine::RECOVERY_TIMEOUT_ENV,
        ));
        match value {
            Some(value) => {
                // SAFETY: this helper holds RECOVERY_TIMEOUT_ENV_LOCK until the
                // original value is restored by _restore.
                unsafe {
                    std::env::set_var(household_rs::pair_machine::RECOVERY_TIMEOUT_ENV, value);
                }
            }
            None => {
                // SAFETY: see the serialized-environment invariant above.
                unsafe {
                    std::env::remove_var(household_rs::pair_machine::RECOVERY_TIMEOUT_ENV);
                }
            }
        }
        inspect()
    }

    #[test]
    fn server_bootstrap_uses_the_shared_recovery_timeout_policy() {
        use household_rs::pair_machine::{
            RECOVERY_TIMEOUT, RecoveryTimeoutResolution, RecoveryTimeoutSource,
        };

        for raw in [None, Some("invalid"), Some("0"), Some("301")] {
            let resolved = with_recovery_timeout_env(raw, phase3_recovery_timeout);
            let expected_source = if raw.is_none() {
                RecoveryTimeoutSource::Default
            } else {
                RecoveryTimeoutSource::RejectedEnvironment
            };
            assert_eq!(
                resolved,
                RecoveryTimeoutResolution {
                    timeout: RECOVERY_TIMEOUT,
                    source: expected_source,
                },
                "raw value {raw:?} must preserve the production ceiling"
            );
        }
        for (raw, seconds) in [("1", 1), ("300", 300)] {
            assert_eq!(
                with_recovery_timeout_env(Some(raw), phase3_recovery_timeout),
                RecoveryTimeoutResolution {
                    timeout: Duration::from_secs(seconds),
                    source: RecoveryTimeoutSource::Environment,
                }
            );
        }
    }

    #[test]
    fn terminal_replay_keeps_the_listener_only_for_real_lock_contention() {
        assert!(terminal_replay_lock_failure_is_contention(
            HouseholdLifecycleLockError::LockTimeout
        ));
        for permanent in [
            HouseholdLifecycleLockError::UnsafePath,
            HouseholdLifecycleLockError::UnsupportedFilesystem,
            HouseholdLifecycleLockError::RecoveryRequired,
            HouseholdLifecycleLockError::Io,
        ] {
            assert!(
                !terminal_replay_lock_failure_is_contention(permanent),
                "{permanent:?} must shut the retained listener down fail-closed"
            );
        }
    }

    #[test]
    fn failed_inferred_bootstrap_persist_never_publishes_the_inference() {
        let result = bootstrap_state_after_inferred_persist(
            BootstrapState::Uninitialized,
            BootstrapState::NamedAwaitingPair,
            Err(household_rs::bootstrap_state::BootstrapStateError::Io(
                std::io::Error::other("injected persistence failure"),
            )),
        );
        assert_eq!(result, BootstrapState::Uninitialized);

        let committed = bootstrap_state_after_inferred_persist(
            BootstrapState::Uninitialized,
            BootstrapState::NamedAwaitingPair,
            Ok(()),
        );
        assert_eq!(committed, BootstrapState::NamedAwaitingPair);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lifecycle_load_blocks_teardown_until_identity_is_published() {
        let td = tempfile::tempdir().unwrap();
        household_rs::bootstrap_or_load(
            td.path(),
            household_rs::BootstrapOpts {
                household_name: "Lifecycle Home".to_string(),
                hostname_label: Some("lifecycle-host".to_string()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .expect("install fixture household");

        // This is the same transaction used by both cold startup and the hot
        // watcher. It has observed household A but has not published A yet.
        let identity_load = acquire_and_load_identity_under_lifecycle(
            td.path(),
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .expect("load fixture under lifecycle exclusive");
        let expected_hh_id = identity_load
            .loaded
            .as_ref()
            .expect("fixture identity is present")
            .record
            .hh_id
            .clone();

        let state_dir = td.path().to_path_buf();
        let (attempting_tx, attempting_rx) = std::sync::mpsc::sync_channel(1);
        let (renamed_tx, renamed_rx) = std::sync::mpsc::sync_channel(1);
        let contender = std::thread::spawn(move || {
            let lifecycle = HouseholdLifecycleLock::open_verified(&state_dir)
                .expect("teardown opens stable lifecycle lock");
            attempting_tx
                .send(())
                .expect("signal teardown acquisition attempt");
            let guard = lifecycle
                .lock_exclusive_until(Instant::now() + Duration::from_secs(5))
                .expect("teardown eventually acquires lifecycle exclusive");
            let renamed = guard
                .rename_household_to_tearing_down()
                .expect("teardown rename succeeds after publication");
            renamed_tx
                .send(renamed)
                .expect("report teardown rename result");
        });

        attempting_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("teardown contender started");
        assert!(
            matches!(
                renamed_rx.recv_timeout(Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "teardown must not rename after load and before memory publication"
        );

        let identity_state = HouseholdState::empty();
        identity_load.publish_into(&identity_state).await;
        assert_eq!(
            identity_state
                .current()
                .await
                .expect("identity is published before lifecycle release")
                .record
                .hh_id,
            expected_hh_id
        );
        drop(identity_load);

        assert!(
            renamed_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("teardown completes after publication"),
            "installed household should be detached"
        );
        contender.join().expect("teardown contender does not panic");
    }

    #[test]
    fn clamp_pair_window_ttl_secs_passes_through_in_range() {
        assert_eq!(clamp_pair_window_ttl_secs(Some(900)), 900);
        assert_eq!(
            clamp_pair_window_ttl_secs(Some(PAIR_WINDOW_TTL_MIN_SECS)),
            PAIR_WINDOW_TTL_MIN_SECS
        );
        assert_eq!(
            clamp_pair_window_ttl_secs(Some(PAIR_WINDOW_TTL_MAX_SECS)),
            PAIR_WINDOW_TTL_MAX_SECS
        );
    }

    #[test]
    fn clamp_pair_window_ttl_secs_defaults_when_absent_or_out_of_range() {
        assert_eq!(
            clamp_pair_window_ttl_secs(None),
            DEFAULT_PAIR_WINDOW_TTL_SECS
        );
        assert_eq!(
            clamp_pair_window_ttl_secs(Some(PAIR_WINDOW_TTL_MIN_SECS - 1)),
            DEFAULT_PAIR_WINDOW_TTL_SECS
        );
        assert_eq!(
            clamp_pair_window_ttl_secs(Some(PAIR_WINDOW_TTL_MAX_SECS + 1)),
            DEFAULT_PAIR_WINDOW_TTL_SECS
        );
        // The historical default the migrated sites used.
        assert_eq!(DEFAULT_PAIR_WINDOW_TTL_SECS, 300);
    }

    /// SSOT guard for the pairing-window TTL clamp. Both the anti-literal check
    /// (no site re-inlines the `60..=3600` clamp) and the positive-consumption
    /// check (each site actually calls the owner) are required: a site that drops
    /// the literal but also stops resolving the TTL would pass the former alone.
    #[test]
    fn pair_window_ttl_clamp_has_a_single_owner() {
        let sites = [
            (
                "server-rs/src/install_cli.rs",
                include_str!("install_cli.rs"),
            ),
            (
                "server-rs/src/pair_machine_local.rs",
                include_str!("pair_machine_local.rs"),
            ),
        ];
        for (path, source) in sites {
            assert!(
                !source.contains("60..=3600"),
                "{path} re-inlined the pairing-window TTL clamp `60..=3600`; \
                 call household_bootstrap::pair_window_ttl_secs_from_env instead"
            );
            assert!(
                source.contains("pair_window_ttl_secs_from_env"),
                "{path} no longer consumes the pairing-window TTL owner \
                 (household_bootstrap::pair_window_ttl_secs_from_env); a site that \
                 stops calling the owner can silently drift from its clamp/default"
            );
        }
    }

    #[test]
    fn macos_local_app_profile_tracks_state_namespace() {
        use crate::macos_local_caller_auth::MacosLocalAppProfile;

        let prod = Path::new("/Users/example/Library/Application Support/Soyeht/household-state");
        assert_eq!(
            macos_local_app_profile_for_state_dir(prod),
            MacosLocalAppProfile::Production
        );

        let dev = Path::new("/Users/example/Library/Application Support/SoyehtDev/household-state");
        assert_eq!(
            macos_local_app_profile_for_state_dir(dev),
            MacosLocalAppProfile::Development
        );

        let prefixed = Path::new(
            "/Users/example/Library/Application Support/SoyehtDevelopment/household-state",
        );
        assert_eq!(
            macos_local_app_profile_for_state_dir(prefixed),
            MacosLocalAppProfile::Production,
            "dev selection must require an exact SoyehtDev path component"
        );

        let username_match =
            Path::new("/Users/SoyehtDev/Library/Application Support/Soyeht/household-state");
        assert_eq!(
            macos_local_app_profile_for_state_dir(username_match),
            MacosLocalAppProfile::Production,
            "dev selection must use the state namespace, not an earlier path component"
        );

        let explicit_dev_state_dir =
            Path::new("/Users/example/Library/Application Support/SoyehtDev");
        assert_eq!(
            macos_local_app_profile_for_state_dir(explicit_dev_state_dir),
            MacosLocalAppProfile::Development
        );
    }

    #[test]
    fn owner_webauthn_registration_state_shares_one_rp_across_both_routers() {
        let td = tempfile::tempdir().unwrap();
        let identity = household_rs::bootstrap_or_load(
            td.path(),
            household_rs::BootstrapOpts {
                household_name: "Owner Events Test".into(),
                hostname_label: Some("owner-events-test".into()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(td.path()).unwrap();
        let lifecycle_guard = lifecycle.lock_exclusive().unwrap();
        let broadcaster = OwnerEventsBroadcaster::new();
        let event_log = OwnerEventLog::open_with_broadcaster_under_lifecycle(
            &lifecycle_guard,
            td.path().to_path_buf(),
            identity.record.hh_id.as_str(),
            broadcaster.clone(),
        )
        .unwrap();
        drop(lifecycle_guard);
        let window = Arc::new(PairMachineWindow::new_in_memory());
        let state = handlers_owner_events::OwnerEventsRouterState::new(
            HouseholdState::empty(),
            window,
            event_log,
            broadcaster,
            td.path().to_path_buf(),
            household_rs::KeyBackingPolicy::ForceSoftware,
        );
        let verifier: Arc<dyn crate::macos_local_caller_auth::MacosLocalCallerAuth> =
            Arc::new(crate::macos_local_caller_auth::FailClosedMacosLocalCallerAuth);

        let runtime = OwnerWebauthnRuntime::build(td.path()).unwrap();
        let network_state = runtime.apply(state.clone());
        let local_state = macos_local_owner_webauthn_registration_state(state, &runtime, verifier);

        assert!(local_state.macos_local_caller_auth.is_some());
        assert!(local_state.owner_webauthn_anchor.is_some());
        assert!(network_state.owner_webauthn_anchor.is_some());
        // The phone presents no SecCode, so the macOS caller check must not
        // ride along onto the network router; owner Soyeht-PoP authenticates
        // that side.
        assert!(network_state.macos_local_caller_auth.is_none());
        // A registration started on one router has to be finishable on the
        // other, and the challenge store lives inside the RP: two instances
        // would turn every cross-router finish into an unknown challenge.
        assert!(Arc::ptr_eq(
            local_state
                .owner_webauthn_rp
                .as_ref()
                .expect("local registration runtime state wires RP"),
            network_state
                .owner_webauthn_rp
                .as_ref()
                .expect("network registration runtime state wires RP"),
        ));
        let rp = local_state
            .owner_webauthn_rp
            .as_ref()
            .expect("local registration runtime state wires RP")
            .try_lock()
            .expect("RP lock is uncontended in unit test");
        assert_eq!(rp.config().rp_id(), DEFAULT_OWNER_WEBAUTHN_RP_ID);
        assert_eq!(
            rp.config().rp_origin().as_str(),
            "https://household.example.test/"
        );
    }

    #[test]
    fn owner_webauthn_rp_defaults_to_the_placeholder_when_no_domain_is_configured() {
        let rp = owner_webauthn_rp_from_values(None, None).unwrap();
        assert_eq!(rp.config().rp_id(), DEFAULT_OWNER_WEBAUTHN_RP_ID);
        assert_eq!(
            rp.config().rp_origin().as_str(),
            "https://household.example.test/"
        );
    }

    #[test]
    fn owner_webauthn_rp_takes_the_configured_tenant_domain() {
        let rp = owner_webauthn_rp_from_values(
            Some("passkeys.example.org"),
            Some("https://passkeys.example.org"),
        )
        .unwrap();
        assert_eq!(rp.config().rp_id(), "passkeys.example.org");
        assert_eq!(
            rp.config().rp_origin().as_str(),
            "https://passkeys.example.org/"
        );
    }

    #[test]
    fn owner_webauthn_rp_rejects_an_origin_outside_the_rp_id() {
        // webauthn-rs refuses the pair, so a mistyped domain fails the phase-3
        // install instead of minting credentials no origin can present.
        assert!(
            owner_webauthn_rp_from_values(
                Some("passkeys.example.org"),
                Some("https://unrelated.example.net"),
            )
            .is_err()
        );
    }

    #[test]
    fn owner_webauthn_network_surface_is_closed_unless_explicitly_opened() {
        for closed in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("yes"),
            Some("on"),
        ] {
            assert!(
                !owner_webauthn_network_enabled_from_value(closed),
                "{closed:?} must leave the network passkey surface closed"
            );
        }
        assert!(owner_webauthn_network_enabled_from_value(Some("1")));
        assert!(owner_webauthn_network_enabled_from_value(Some(" 1 ")));
    }

    #[test]
    fn claw_share_bootstrap_state_rehydrates_slots_from_persisted_log() {
        let td = tempfile::tempdir().unwrap();
        let log = MeshLogStore::open(&claw_share_log_path(td.path())).unwrap();
        let owner = P256Keypair::from_secret_scalar(&[0x11u8; 32]).unwrap();
        let guest = P256Keypair::from_secret_scalar(&[0x22u8; 32]).unwrap();
        let now = 1_800_000_000;

        let open_slot = SlotId([0x01u8; 16]);
        let consumed_slot = SlotId([0x02u8; 16]);
        let revoked_slot = SlotId([0x03u8; 16]);
        append_log_event(
            &log,
            &owner,
            now,
            MeshEvent::ClawShareSlotMinted {
                slot_id: open_slot.clone(),
                claw_id: "claw-open".to_string(),
                expires_at: now + 600,
                app_presentation: None,
            },
        );
        append_log_event(
            &log,
            &owner,
            now + 1,
            MeshEvent::ClawShareSlotMinted {
                slot_id: consumed_slot.clone(),
                claw_id: "claw-consumed".to_string(),
                expires_at: now + 600,
                app_presentation: None,
            },
        );
        append_log_event(
            &log,
            &owner,
            now + 2,
            MeshEvent::ClawShareSlotConsumed {
                slot_id: consumed_slot.clone(),
                guest_device_pub: guest.public(),
                claw_id: "claw-consumed".to_string(),
                expires_at: now + 600,
                participant_npub: None,
            },
        );
        append_log_event(
            &log,
            &owner,
            now + 3,
            MeshEvent::ClawShareSlotMinted {
                slot_id: revoked_slot.clone(),
                claw_id: "claw-revoked".to_string(),
                expires_at: now + 600,
                app_presentation: None,
            },
        );
        append_log_event(
            &log,
            &owner,
            now + 4,
            MeshEvent::ClawShareSlotRevoked {
                slot_id: revoked_slot.clone(),
            },
        );
        drop(log);

        let state = prepare_claw_share_bootstrap_state(td.path(), None, None);

        assert!(state.engine_relay_identity.is_none());
        assert!(state.relay_urls.is_empty());
        assert!(matches!(
            state.runtime.slot_store.get(&open_slot).unwrap().state,
            SlotState::Open
        ));
        let consumed = state.runtime.slot_store.get(&consumed_slot).unwrap();
        match consumed.state {
            SlotState::Consumed {
                guest_device_pub, ..
            } => assert_eq!(guest_device_pub, guest.public()),
            other => panic!("expected consumed slot, got {other:?}"),
        }
        assert!(matches!(
            state.runtime.slot_store.get(&revoked_slot).unwrap().state,
            SlotState::Revoked { .. }
        ));
    }

    #[test]
    fn engine_relay_identity_is_default_off_and_pins_advertised_npub_to_subscription_key() {
        let td = tempfile::tempdir().unwrap();

        let disabled = prepare_engine_relay_identity(td.path(), &[]).unwrap();
        assert!(disabled.is_none());
        assert!(!td.path().join("nostr_engine_key.hex").exists());

        let relay_urls = vec!["wss://relay.example.test".to_string()];
        let identity = prepare_engine_relay_identity(td.path(), &relay_urls)
            .unwrap()
            .unwrap();
        assert_eq!(identity.npub_hex, identity.keys.public_key().to_hex());
        assert!(td.path().join("nostr_engine_key.hex").exists());

        let reloaded = prepare_engine_relay_identity(td.path(), &relay_urls)
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.npub_hex, identity.npub_hex);
    }

    #[test]
    fn household_bootstrap_relay_mount_stays_mesh_runtime_free() {
        let source = include_str!("household_bootstrap.rs");
        let forbidden = [
            concat!("mesh", "_rs"),
            concat!("THEYOS", "_MESH"),
            concat!("transit", "_bootstrap_store"),
            concat!("community", "_relay_catalog"),
            concat!("mesh", "_admin_dir"),
            concat!("mesh", ".clone"),
            concat!("private_share", "_transit"),
        ];
        for symbol in forbidden {
            assert!(
                !source.contains(symbol),
                "household_bootstrap.rs reintroduced forbidden relay mount dependency `{symbol}`"
            );
        }
        assert!(source.contains(".merge(claw_share_router)"));
        assert!(source.contains("mount_claw_share_relay_stream_live_if_enabled"));
    }

    #[tokio::test]
    async fn snapshot_watcher_installs_reissued_token_without_restart() {
        let td = tempfile::tempdir().unwrap();
        let daemon_window = Arc::new(
            household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf())
                .unwrap(),
        );
        let cli_window =
            household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf())
                .unwrap();

        let watcher = spawn_pair_device_window_snapshot_watcher_with_interval(
            td.path().to_path_buf(),
            Arc::clone(&daemon_window),
            HouseholdState::empty(),
            Duration::from_millis(20),
        );

        let first = cli_window
            .mint_token(Duration::from_secs(60), None)
            .await
            .unwrap();
        wait_for_nonce(&daemon_window, first.nonce.as_b64()).await;

        let second = cli_window
            .mint_token(Duration::from_secs(60), None)
            .await
            .unwrap();
        wait_for_nonce(&daemon_window, second.nonce.as_b64()).await;
        assert_ne!(first.nonce.as_b64(), second.nonce.as_b64());

        watcher.abort();
    }

    #[tokio::test]
    async fn snapshot_watcher_closes_and_exits_after_owner_auth_exists() {
        let td = tempfile::tempdir().unwrap();
        // Installing household authority rotates the lifecycle generation.
        // Open both watcher handles only after that rotation so they retain
        // the same generation-scoped namespace the watcher is allowed to
        // close.
        let identity = household_rs::bootstrap_or_load(
            td.path(),
            household_rs::BootstrapOpts {
                household_name: "Sample Home".to_string(),
                hostname_label: Some("studio-mac".to_string()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap identity from install path");
        let daemon_window = Arc::new(
            household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf())
                .unwrap(),
        );
        let cli_window =
            household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf())
                .unwrap();
        let owner_auth = owner_auth_for(&identity);
        let identity_state =
            HouseholdState::loaded_with_owner_auth(Arc::new(identity), Some(Arc::new(owner_auth)));

        cli_window
            .mint_token(Duration::from_secs(60), None)
            .await
            .unwrap();
        assert!(cli_window.read_persisted_snapshot().unwrap().is_some());

        let watcher = spawn_pair_device_window_snapshot_watcher_with_interval(
            td.path().to_path_buf(),
            Arc::clone(&daemon_window),
            identity_state,
            Duration::from_millis(20),
        );

        tokio::time::timeout(Duration::from_secs(2), watcher)
            .await
            .expect("snapshot watcher should stop after owner auth exists")
            .expect("snapshot watcher should not panic");
        assert!(!daemon_window.is_open().await);
        assert!(cli_window.read_persisted_snapshot().unwrap().is_none());
    }

    #[tokio::test]
    async fn identity_watcher_hot_loads_after_install_without_restart() {
        let _phase3_test = PHASE3_TEST_LOCK.lock().await;
        let td = tempfile::tempdir().unwrap();
        let identity_state = HouseholdState::empty();
        let pair_device_window = Arc::new(
            household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf())
                .unwrap(),
        );
        let pair_machine_window = Arc::new(
            household_rs::pair_machine::PairMachineWindow::with_persistence(
                td.path().to_path_buf(),
            )
            .unwrap(),
        );
        let phase3_runtime = Phase3RuntimeController::new(
            td.path().to_path_buf(),
            identity_state.clone(),
            Arc::clone(&pair_machine_window),
            household_rs::KeyBackingPolicy::ForceSoftware,
            None,
        );
        let phase3_runtime_for_assertion = phase3_runtime.clone();
        let watcher = spawn_household_identity_watcher_with_interval(
            td.path().to_path_buf(),
            identity_state.clone(),
            household_rs::KeyBackingPolicy::ForceSoftware,
            Duration::from_millis(20),
            HouseholdIdentityWatcherDeps {
                pair_device_window,
                pair_machine_window,
                local_network_visibility: Arc::new(
                    crate::local_network_visibility::LocalNetworkVisibility::new(),
                ),
                targets: Vec::new(),
                port: 8091,
                claw_share: None,
                phase3_runtime,
                shared_state: None,
            },
        );

        assert!(identity_state.current().await.is_none());
        household_rs::bootstrap_or_load(
            td.path(),
            household_rs::BootstrapOpts {
                household_name: "Sample Home".to_string(),
                hostname_label: Some("studio-mac".to_string()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap identity from install path");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(identity) = identity_state.current().await {
                assert_eq!(identity.record.name, "Sample Home");
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for household identity hot-load"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::timeout(Duration::from_secs(2), watcher)
            .await
            .expect("hot-load watcher completed")
            .expect("hot-load watcher did not panic");
        let before = PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        let invalid_pop = phase3_runtime_for_assertion
            .route_or_reject(
                Request::builder()
                    .uri("/api/v1/household/owner-events?since=AA")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(invalid_pop.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            PHASE3_TEST_DISPATCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            before + 1,
            "hot-loaded identity must install the whole Phase 3 router before the watcher exits"
        );
        phase3_runtime_for_assertion.deactivate().await.unwrap();
    }

    async fn wait_for_nonce(
        window: &household_rs::pair_device::PairDeviceWindow,
        expected_nonce_b64: String,
    ) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(token) = window.current_token().await {
                if token.nonce.as_b64() == expected_nonce_b64 {
                    return;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for daemon pair-window snapshot reload"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn owner_auth_for(identity: &household_rs::LoadedIdentity) -> household_rs::HouseholdAuthState {
        let person = P256Keypair::generate();
        let cert = household_rs::PersonCert::sign_owner(
            identity
                .hh_priv
                .as_deref()
                .expect("hh_priv present in single-machine household"),
            SignOwnerOptions {
                hh_id: identity.record.hh_id.clone(),
                p_pub: person.public(),
                display_name: "Owner".into(),
                issued_at: identity.record.created_at + 1,
            },
        )
        .unwrap();
        household_rs::HouseholdAuthState::new(&identity.record, cert)
    }

    fn append_log_event(log: &MeshLogStore, owner: &P256Keypair, timestamp: u64, event: MeshEvent) {
        let entry = LogEntry::sign(timestamp, owner.public(), event, owner).unwrap();
        log.append(entry).unwrap();
    }
}
