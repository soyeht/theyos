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

use crate::bonjour::trust::BrowserConfig;
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
use crate::{bonjour::browser, bonjour::publisher, setup_beacon, startup_wiring};
use household_rs::KeyBackingPolicy;
use household_rs::bootstrap::{
    recover_interrupted_household_teardown_under_lifecycle, try_load_existing_under_lifecycle,
};
use household_rs::bootstrap_state::{self, BootstrapState};
use household_rs::claw_share::ClawShareSlotStore;
use household_rs::claw_share::data_tunnel::ReplayGuard;
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
        // One RP/anchor per generation. The macOS UDS router always needs it;
        // over the network it reaches ONLY the three enrollment routes, and
        // only when the operator opened THEYOS_OWNER_WEBAUTHN_NETWORK.
        //
        // The scoping is the point, not a nicety. `owner_webauthn_anchor` and
        // `owner_webauthn_rp` are read far outside enrollment
        // (`handlers_owner_events.rs`):
        //  - `pair_machine_owner_webauthn_policy_snapshot` returns
        //    `anchor_invalid()` when the anchor is `None`. Under
        //    `THEYOS_OWNER_AUTH_V2_ROLLOUT=reviewed-core-v2` that is the
        //    difference between `RejectFailClosed` and `LegacyV1` on
        //    `/owner-events/{cursor}/approve` — i.e. whether machine approval
        //    is refused outright or accepted with a legacy body.
        //  - `/owner-webauthn/revoke/{start,finish}` and
        //    `/owner-webauthn/add-credential/{start,finish}` reject on
        //    `rp_unavailable` / `missing_anchor_verifier` today; both fields on
        //    the shared state would let them run.
        // Handing the RP/anchor to the one state behind every owner-events
        // route would therefore change machine-approval enforcement and open
        // four surfaces this switch never promised.
        let owner_webauthn_network = owner_webauthn_network_enabled();
        let owner_webauthn_runtime = if cfg!(target_os = "macos") || owner_webauthn_network {
            Some(
                OwnerWebauthnRuntime::build(&self.state_dir)
                    .map_err(|error| format!("build owner passkey registration state: {error}"))?,
            )
        } else {
            None
        };
        let owner_webauthn_enrollment_state = owner_webauthn_enrollment_router_state(
            &owner_events_state,
            owner_webauthn_runtime.as_ref(),
            owner_webauthn_network,
        )?;
        let router = phase3_router(
            pair_machine_state.clone(),
            owner_events_state.clone(),
            owner_webauthn_enrollment_state,
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
            .then(|| browser::spawn_bonjour_browser(pair_machine_state));

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

/// Build the Phase-3 surface.
///
/// `owner_webauthn_enrollment_state` is the state for the three
/// `owner-webauthn/registration/*` routes and nothing else. It is a separate
/// parameter so that the passkey RP and anchor can reach enrollment without
/// reaching `/owner-events/{cursor}/approve`, `/owner-webauthn/revoke/*` or
/// `/owner-webauthn/add-credential/*`, all of which branch on the same two
/// fields — see the wiring comment in `install_with_resources_under_lifecycle`.
/// Pass `owner_events_state` here to leave enrollment exactly as it was.
fn phase3_router(
    pair_machine_state: handlers_pair_machine::PairMachineRouterState,
    owner_events_state: handlers_owner_events::OwnerEventsRouterState,
    owner_webauthn_enrollment_state: handlers_owner_events::OwnerEventsRouterState,
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
                .with_state(owner_events_state.clone()),
        )
        .merge(handlers_device_pairing::device_pairing_router(owner_events_state))
        // Owner passkey enrollment, and only enrollment, carries
        // `owner_webauthn_enrollment_state`. Adding a route here hands it the
        // RP and the anchor whenever THEYOS_OWNER_WEBAUTHN_NETWORK is open.
        .merge(
            axum::Router::new()
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
                .with_state(owner_webauthn_enrollment_state),
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
/// Sharing one instance is NOT what makes a ceremony work, and an earlier
/// version of this comment claimed it was. The two routers never touch the
/// same ceremony: the network side serves the three
/// `owner-webauthn/registration` paths and the macOS UDS side serves the three
/// `registration.local` ones (the source guard in `tests/owner_events.rs`
/// forbids spelling the local path here, which is how the network router is
/// kept off it). The challenge kinds are disjoint too.
/// `start_registration` stores under the registration kind while
/// `start_macos_local_attested_registration_from` stores under the
/// local-attested kind, which `finish_registration` cannot consume
/// (`household-rs/src/owner_webauthn.rs`); its matching
/// `finish_macos_local_attested_registration` has no caller in server-rs at all
/// (`owner_webauthn_registration_local_finish_handler` rejects before it).
///
/// It is one instance because a household generation has exactly one
/// relying-party identity and one anchor file. Building a second would repeat
/// the same fallible construction over the same inputs and leave two challenge
/// stores, two TTL clocks and two `Mutex`es to reason about, for no ceremony
/// that needs them.
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

/// The state for the three network `owner-webauthn/registration/*` routes.
///
/// `base` is returned untouched unless the operator opened
/// `THEYOS_OWNER_WEBAUTHN_NETWORK`, and `base` itself is never modified: the
/// caller keeps handing that same value to every other owner-events route, so
/// machine approval, revoke and add-credential stay on the behaviour they had
/// before this switch existed.
fn owner_webauthn_enrollment_router_state(
    base: &handlers_owner_events::OwnerEventsRouterState,
    runtime: Option<&OwnerWebauthnRuntime>,
    network_open: bool,
) -> Result<handlers_owner_events::OwnerEventsRouterState, String> {
    if !network_open {
        return Ok(base.clone());
    }
    let runtime =
        runtime.ok_or_else(|| "owner passkey runtime missing for network router".to_string())?;
    tracing::info!(
        stage = "owner_webauthn.network_surface_open",
        env = OWNER_WEBAUTHN_NETWORK_ENV,
        "owner passkey enrollment is reachable over the network router"
    );
    Ok(runtime.apply(base.clone()))
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

    let pair_router = handlers_pair_device::pair_device_router(handlers_pair_device::PairDeviceState {
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
        drop(browser::spawn_setup_invitation_browser_with_cache(
            bootstrap_handler_state.setup_invitation_cache.clone(),
            BrowserConfig {
                include_local_network,
            },
        ));
    }
    let bound_set = household_listener::BoundSet::default();
    let pairing_addresses_rt = crate::pairing_addresses::router(
        crate::pairing_addresses::PairingAddressesState::new(
            bound_set.clone(), Arc::clone(&bootstrap_state_arc), identity_state.clone(),
            Arc::clone(&pair_device_window), Arc::clone(&local_network_visibility),
            bootstrap_handler_state.installation.clone(),
        ),
    );
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
        .merge(pairing_addresses_rt)
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
            bound_set.clone(),
            port,
        )
        .await;
    } else {
        let deps = HouseholdIdentityWatcherDeps {
            pair_device_window: Arc::clone(&pair_device_window),
            pair_machine_window: Arc::clone(&pair_machine_window),
            local_network_visibility: Arc::clone(&local_network_visibility),
            targets: bound_set,
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
    targets: household_listener::BoundSet,
    port: u16,
) {
    let raw_hostname = gethostname::gethostname().to_string_lossy().into_owned();
    let host_label = raw_hostname.replace(['.', ' '], "-");
    // Read current bootstrap state for the TXT enrichment field.
    let bootstrap_state_source = global_bootstrap_state()
        .unwrap_or_else(|| Arc::new(tokio::sync::RwLock::new(BootstrapState::Ready)));
    let bootstrap_state = *bootstrap_state_source.read().await;
    let bs_str = bootstrap_state.as_str().to_string();
    let params = publisher::PublishParams {
        hh_id: loaded.record.hh_id.to_string(),
        hh_name: loaded.record.name.clone(),
        m_id: loaded.cert.m_id.to_string(),
        port,
        host_label,
        host_dns: raw_hostname,
        // Filled by `publish_household_bonjour` from the post-policy bind set.
        tailnet_addr: None,
        pair_machine_role: Some(publisher::PairMachineBonjourRole::Founder),
        owner_display_name: String::new(), // populated by agente-front after iCloud name is known
        device_count: u32::from(bs_str == "ready"),
        bootstrap_state: bs_str,
    };
    match publisher::publish_household_bonjour(
        params,
        pair_device_window,
        pair_machine_window,
        local_network_visibility,
        targets,
        bootstrap_state_source,
    )
    .await
    {
        Ok(handle) => {
            publisher::install_household_bonjour(handle);
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
    targets: household_listener::BoundSet,
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
mod tests;
