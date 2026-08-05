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
use household_rs::owner_events::{OwnerEventLog, OwnerEventsBroadcaster};
use household_rs::pair_machine::PairMachineWindow;
use nostr_relay_rs::nostr::Keys;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::info;

const TERMINAL_REPLAY_REBIND_INTERVAL: Duration = Duration::from_millis(100);

/// Global bootstrap state — shared by all handlers that need to read or
/// transition the onboarding state machine. Set once at engine startup.
static BOOTSTRAP_STATE: OnceLock<BootstrapStateArc> = OnceLock::new();

const HOUSEHOLD_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(30);

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

#[cfg(any(target_os = "macos", test))]
type LocalOwnerWebauthnRp = household_rs::owner_webauthn::OwnerWebauthnRp;

#[cfg(any(target_os = "macos", test))]
fn owner_webauthn_local_registration_rp() -> Result<LocalOwnerWebauthnRp, String> {
    let origin = webauthn_rs::prelude::Url::parse("https://household.example.test")
        .map_err(|e| e.to_string())?;
    let config = household_rs::owner_webauthn::OwnerWebauthnConfig::new(
        "household.example.test",
        origin,
        "Soyeht",
    )
    .map_err(|e| e.to_string())?;
    household_rs::owner_webauthn::OwnerWebauthnRp::new(config).map_err(|e| e.to_string())
}

#[cfg(any(target_os = "macos", test))]
fn owner_webauthn_local_registration_anchor_store(
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
    state_dir: &Path,
    verifier: Arc<dyn crate::macos_local_caller_auth::MacosLocalCallerAuth>,
) -> Result<handlers_owner_events::OwnerEventsRouterState, String> {
    Ok(state
        .with_owner_webauthn_rp(owner_webauthn_local_registration_rp()?)
        .with_owner_webauthn_anchor(owner_webauthn_local_registration_anchor_store(state_dir))
        .with_macos_local_caller_auth(verifier))
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
) -> axum::Router {
    handlers_claw_share::router(handlers_claw_share::ClawShareRouterState {
        household,
        slot_store: Arc::clone(&runtime.slot_store),
        mesh_log: Arc::clone(&runtime.mesh_log),
        engine_relay_npub,
        state_dir,
        relay_offer_challenges: Arc::clone(&runtime.relay_offer_challenges),
        relay_offer_abuse: Arc::clone(&runtime.relay_offer_abuse),
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
) {
    if let Err(e) = crate::claw_share_relay_stream_mount::mount_relay_stream_live_if_enabled(
        state_dir,
        household,
        Arc::clone(&runtime.mesh_log),
        Arc::clone(&runtime.slot_store),
        Arc::clone(&runtime.replayguard),
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
    let phase3_recovery_completed = match pair_machine_window
        .recover_phase3_under_lifecycle(
            &state_dir,
            &lifecycle_guard,
            household_rs::pair_machine::RECOVERY_TIMEOUT,
        )
        .await
    {
        Ok(outcome) => {
            let completed = !matches!(
                outcome,
                household_rs::pair_machine::RecoveryOutcome::NotApplicable
            );
            tracing::info!(
                stage = "bootstrap.phase3_recovery",
                outcome = ?outcome,
                "boot-time Phase 3 recovery inspection completed"
            );
            completed
        }
        Err(e) => {
            tracing::error!(
                stage = "bootstrap.phase3_recovery_failed",
                error = %e,
                "boot-time Phase 3 recovery is indeterminate; refusing to \
                 publish identity or listeners"
            );
            if let Err(state_error) =
                bootstrap_state::persist(&state_dir, BootstrapState::Recovering)
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

    // `identity_state`, `bootstrap_state_arc`, both ceremony windows, and the
    // optional owner-event handle now all describe the exact disk generation
    // observed under this transaction. Only now may teardown detach it.
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

    // Phase 3 join-request endpoint (T042–T046). Distinct router so the
    // shared `PairMachineRouterState` (window + event log + broadcaster +
    // household identity slot) lives independently of the Phase 2
    // pair-device state.
    let mut bonjour_browser_state = None;
    let pair_machine_router = match owner_event_log {
        Some(Ok(owner_event_log)) => {
            let pair_machine_state = handlers_pair_machine::PairMachineRouterState {
                window: Arc::clone(&pair_machine_window),
                household: identity_state.clone(),
                event_log: Arc::clone(&owner_event_log),
                event_broadcaster: owner_event_broadcaster.clone(),
                state_dir: state_dir.clone(),
            };
            bonjour_browser_state = Some(pair_machine_state.clone());
            let owner_approval_policy = handlers_owner_events::owner_approval_policy_from_env();
            let mut owner_events_state = handlers_owner_events::OwnerEventsRouterState::new(
                identity_state.clone(),
                Arc::clone(&pair_machine_window),
                owner_event_log,
                owner_event_broadcaster,
                state_dir.clone(),
                key_policy,
            )
            .with_owner_approval_policy(owner_approval_policy.clone());
            if owner_approval_policy.secure_upgrade_strong_minting_enabled() {
                match handlers_owner_events::secure_upgrade_runtime_config_from_env() {
                    Ok(config) => {
                        owner_events_state = owner_events_state.with_secure_upgrade_runtime(config);
                    }
                    Err(e) => {
                        tracing::warn!(
                            stage = "secure_upgrade.runtime_unavailable",
                            reason = %e,
                            "Secure/Upgrade rollout is enabled but runtime config is unavailable"
                        );
                    }
                }
            }
            if let Some(state) = shared_state.as_ref() {
                owner_events_state = owner_events_state
                    .with_recovery_consume_rate_limiter(Arc::clone(&state.rate_limiter));
            }
            let sign_machine_cert_state =
                crate::handlers_sign_machine_cert::SignMachineCertRouterState {
                    household: identity_state.clone(),
                    event_log: Arc::clone(&pair_machine_state.event_log),
                    state_dir: state_dir.clone(),
                };
            let sign_machine_cert_router =
                crate::handlers_sign_machine_cert::sign_machine_cert_router(
                    sign_machine_cert_state,
                );
            // Spawn the runtime owner-timeout watchdog (FR-019 active
            // half: the in-process counterpart to load_state_dir's
            // boot recovery).
            //
            // The cancel sender is `Box::leak`'d into `'static`. Two
            // reasons:
            //
            // 1. The watchdog's `watch::Receiver::changed()` returns
            //    `Err` when ALL senders drop. If we let the local
            //    `cancel_tx` go out of scope at end of this match
            //    arm, the watchdog would observe the drop and exit
            //    immediately — defeating its purpose.
            // 2. Production currently relies on `tokio::Runtime` drop
            //    on SIGTERM to abort the watchdog (no in-process
            //    restart path yet). Leaking the sender into `'static`
            //    means the daemon process owns it for its full
            //    lifetime, with no risk of accidental drop, and
            //    leaves a genuine hook (`&'static
            //    watch::Sender<bool>`) available to a future
            //    graceful-shutdown path that wants to call
            //    `cancel_tx.send(true)` instead of relying on runtime
            //    abort.
            //
            // The leak is bounded: one `watch::channel<bool>` per
            // household-router lifetime. Memory cost is constant.
            let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
            let _: &'static tokio::sync::watch::Sender<bool> = Box::leak(Box::new(cancel_tx));
            let _timeout_watchdog = handlers_owner_events::spawn_owner_timeout_watchdog(
                owner_events_state.clone(),
                cancel_rx,
            );
            #[cfg(target_os = "macos")]
            {
                let macos_local_verifier: Arc<
                    dyn crate::macos_local_caller_auth::MacosLocalCallerAuth,
                > = Arc::new(
                    crate::macos_local_caller_auth::DesignatedRequirementMacosLocalCallerAuth::new(
                        macos_local_app_profile_for_state_dir(&state_dir),
                    ),
                );
                match macos_local_owner_webauthn_registration_state(
                    owner_events_state.clone(),
                    &state_dir,
                    macos_local_verifier,
                ) {
                    Ok(macos_local_state) => {
                        let macos_local_router =
                            handlers_owner_events::owner_webauthn_macos_local_registration_router(
                                macos_local_state,
                            );
                        if let Err(e) =
                            crate::macos_local_registration_listener::spawn_macos_local_registration_listener(
                                &state_dir,
                                macos_local_router,
                            )
                        {
                            tracing::warn!(
                                stage = "macos_local_registration.listener_unavailable",
                                error = %e,
                                "macOS local registration listener unavailable"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            stage = "macos_local_registration.state_unavailable",
                            error = %e,
                            "macOS local registration state unavailable"
                        );
                    }
                }
            }
            Some(
                axum::Router::new()
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
                                axum::routing::post(
                                    handlers_owner_events::push_token_register_handler,
                                ),
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
                                axum::routing::post(
                                    handlers_owner_events::owner_approval_v2_start_handler,
                                ),
                            )
                            .route(
                                "/api/v1/household/owner-events/{cursor}/decline",
                                axum::routing::post(handlers_owner_events::owner_decline_handler),
                            )
                            .route(
                                "/api/v1/household/device-pairing/request",
                                axum::routing::post(
                                    handlers_device_pairing::device_pairing_request_handler,
                                ),
                            )
                            .route(
                                "/api/v1/household/device-pairing/approve",
                                axum::routing::post(
                                    handlers_device_pairing::device_pairing_approve_handler,
                                ),
                            )
                            .route(
                                "/api/v1/household/device-pairing/requests",
                                axum::routing::get(
                                    handlers_device_pairing::device_pairing_requests_handler,
                                ),
                            )
                            .route(
                                "/api/v1/household/device-pairing/reject",
                                axum::routing::post(
                                    handlers_device_pairing::device_pairing_reject_handler,
                                ),
                            )
                            .route(
                                "/api/v1/household/device-pairing/{request_id}",
                                axum::routing::get(
                                    handlers_device_pairing::device_pairing_poll_handler,
                                ),
                            )
                            .with_state(owner_events_state),
                    )
                    .merge(sign_machine_cert_router),
            )
        }
        Some(Err(e)) => {
            // Refuse to bring up the join-request endpoint without a
            // working append log: silently dropping events would leave
            // the iPhone long-poll permanently empty after a partial
            // boot. Surface the error, skip mounting the route, and
            // continue with the Phase 2 surface so the rest of the
            // identity stack stays available.
            tracing::error!(
                stage = "owner_event_log.open_failed",
                error = %e,
                "Phase 3 join-request endpoint will be unavailable until owner-events log opens cleanly",
            );
            None
        }
        None => None,
    };

    // ── Bootstrap router (T008 / T009 / T010 / T011) ─────────────────────
    // Always live — even on a cold, uninitialized engine.
    let bootstrap_handler_state = BootstrapHandlerState::new(
        Arc::clone(&bootstrap_state_arc),
        identity_state.clone(),
        state_dir.clone(),
        Arc::clone(&pair_device_window),
        Arc::clone(&pair_machine_window),
        port,
    );
    if matches!(
        initial_bootstrap_state,
        BootstrapState::Uninitialized | BootstrapState::ReadyForNaming
    ) {
        drop(bonjour_browser::spawn_setup_invitation_browser_with_cache(
            bootstrap_handler_state.setup_invitation_cache.clone(),
            BrowserConfig::default(),
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
    let claws_router = shared_state.map(|state| {
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
    let pre_household_rt = handlers_pair_machine::pre_household_router(
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
    );
    mount_claw_share_relay_stream_live_if_enabled(
        state_dir.clone(),
        identity_state.clone(),
        &claw_share_runtime,
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
        .merge(pre_household_rt)
        .merge(guest_image_router)
        .merge(claw_share_router);
    if let Some(r) = claws_router {
        household_router = household_router.merge(r);
    }
    if let Some(r) = pair_machine_router {
        household_router = household_router.merge(r);
    }

    let bound_set = household_listener::BoundSet::default();
    let initial_bound = household_listener::spawn_household_listeners(
        startup,
        household_router.clone(),
        port,
        Arc::clone(&bootstrap_state_arc),
        &bound_set,
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
    {
        let router = household_router;
        let bound = bound_set.clone();
        let bootstrap = Arc::clone(&bootstrap_state_arc);
        tokio::spawn(async move {
            household_listener::refresh_loop(router, port, bootstrap, bound).await;
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
            initial_bound,
            port,
        )
        .await;
        if loaded.record.shamir_n == 1 {
            if let Some(state) = bonjour_browser_state.clone() {
                drop(bonjour_browser::spawn_bonjour_browser(state));
            }
        }
    } else {
        let deps = HouseholdIdentityWatcherDeps {
            pair_device_window: Arc::clone(&pair_device_window),
            pair_machine_window: Arc::clone(&pair_machine_window),
            targets: initial_bound,
            port,
            bonjour_browser_state,
            claw_share: Some(claw_share_runtime),
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
    targets: Vec<(IpAddr, InterfaceClass)>,
    port: u16,
    bonjour_browser_state: Option<handlers_pair_machine::PairMachineRouterState>,
    claw_share: Option<ClawShareRuntimeHandles>,
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
        targets,
        port,
        bonjour_browser_state,
        claw_share,
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
                    targets.clone(),
                    port,
                )
                .await;
                if loaded.record.shamir_n == 1 {
                    if let Some(state) = bonjour_browser_state.clone() {
                        drop(bonjour_browser::spawn_bonjour_browser(state));
                    }
                }
                if let Some(runtime) = &claw_share {
                    mount_claw_share_relay_stream_live_if_enabled(
                        state_dir.clone(),
                        identity_state.clone(),
                        runtime,
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
                    if close_window {
                        let _ = pair_device_window.close().await;
                    }
                    drop(identity_load);
                    if let Some(runtime) = &claw_share {
                        mount_claw_share_relay_stream_live_if_enabled(
                            state_dir.clone(),
                            identity_state.clone(),
                            runtime,
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
                        targets,
                        port,
                    )
                    .await;
                    if identity_state
                        .current()
                        .await
                        .is_some_and(|id| id.record.shamir_n == 1)
                    {
                        if let Some(state) = bonjour_browser_state.clone() {
                            drop(bonjour_browser::spawn_bonjour_browser(state));
                        }
                    }
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
    use household_rs::claw_share::{SlotId, SlotState};
    use household_rs::household_mesh_log::{LogEntry, MeshEvent};
    use household_rs::keys::{IdentityKey, P256Keypair};
    use household_rs::person_cert::SignOwnerOptions;

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
    fn macos_local_registration_state_wires_runtime_webauthn_dependencies() {
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

        let state =
            macos_local_owner_webauthn_registration_state(state, td.path(), verifier).unwrap();

        assert!(state.macos_local_caller_auth.is_some());
        assert!(state.owner_webauthn_anchor.is_some());
        let rp = state
            .owner_webauthn_rp
            .as_ref()
            .expect("local registration runtime state wires RP")
            .try_lock()
            .expect("RP lock is uncontended in unit test");
        assert_eq!(rp.config().rp_id(), "household.example.test");
        assert_eq!(
            rp.config().rp_origin().as_str(),
            "https://household.example.test/"
        );
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
        let watcher = spawn_household_identity_watcher_with_interval(
            td.path().to_path_buf(),
            identity_state.clone(),
            household_rs::KeyBackingPolicy::ForceSoftware,
            Duration::from_millis(20),
            HouseholdIdentityWatcherDeps {
                pair_device_window,
                pair_machine_window,
                targets: Vec::new(),
                port: 8091,
                bonjour_browser_state: None,
                claw_share: None,
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

        watcher.abort();
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
