//! Household identity bring-up at server startup (Phase 1 cryptographic
//! skeleton).
//!
//! Wires together:
//!
//! - `try_load_existing` — load persisted `HouseholdRecord` + `MachineCert`
//!   (or stay cold until `theyos install` runs).
//! - [`PairDeviceWindow`](household_rs::pair_device::PairDeviceWindow) — single-use
//!   pair-receiving state machine, persisted as `pair_device_window.cbor`.
//! - Listener interface enumeration (loopback + LAN + Tailscale) and the
//!   60s refresh loop (FR-008).
//! - Bonjour publisher (FR-017) — only announces once identity is loaded.

use crate::bonjour_trust::BrowserConfig;
use crate::claw_share_relay_offer_challenge::RelayOfferChallengeTable;
use crate::claw_share_relay_stream_abuse::RelayAbuseState;
use crate::handlers_bootstrap::{BootstrapHandlerState, BootstrapStateArc};
use crate::handlers_claw_share;
use crate::handlers_household;
use crate::handlers_household_claws;
use crate::handlers_household_guest_image;
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
use household_rs::bootstrap_state::{self, BootstrapState};
use household_rs::claw_share::ClawShareSlotStore;
use household_rs::claw_share_data_tunnel::ReplayGuard;
use household_rs::household_mesh_log::MeshLogStore;
use household_rs::owner_events::{OwnerEventLog, OwnerEventsBroadcaster};
use household_rs::pair_machine::PairMachineWindow;
use nostr_relay_rs::nostr::Keys;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::info;

/// Global bootstrap state — shared by all handlers that need to read or
/// transition the onboarding state machine. Set once at engine startup.
static BOOTSTRAP_STATE: OnceLock<BootstrapStateArc> = OnceLock::new();

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
    replay_guard: Arc<ReplayGuard>,
    relay_offer_challenges: Arc<RelayOfferChallengeTable>,
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
    let replay_guard = Arc::new(ReplayGuard::new());
    let relay_offer_challenges = Arc::new(RelayOfferChallengeTable::new());
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
            replay_guard,
            relay_offer_challenges,
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
        Arc::clone(&runtime.replay_guard),
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
pub async fn bootstrap_household(shared_state: Option<SharedState>) {
    let state_dir = resolve_household_state_dir();
    if let Err(e) = std::fs::create_dir_all(&state_dir) {
        tracing::warn!(
            "failed to create household state dir {}: {e}",
            state_dir.display()
        );
    }

    let port = household_port_from_env();

    let key_policy = household_rs::KeyBackingPolicy::from_env();

    // T074: Phase-3 in-flight ceremony recovery driver. Runs BEFORE
    // `try_load_existing` consumes the on-disk record so that any
    // committed-but-unfinished ceremony rolls forward (post-Shamir
    // record on disk, with this process picking up the N=2 identity)
    // before the household listener binds. If the marker is absent
    // this is a no-op fast path. Past `RECOVERY_TIMEOUT` the driver
    // rolls back per `FR-013a` and the household stays N=1.
    //
    // The probe operates on disk and over HTTP only; no in-memory
    // state from this process is required. Errors are logged but do
    // NOT panic — a failed probe falls back to "household stays in
    // its current on-disk state" and the operator can retry on the
    // next boot.
    if household_rs::storage::phase3_finalize_ack_marker_exists(&state_dir) {
        match household_rs::pair_machine::recover_phase3_ceremony(
            &state_dir,
            household_rs::pair_machine::RECOVERY_TIMEOUT,
        )
        .await
        {
            Ok(outcome) => {
                tracing::info!(
                    stage = "bootstrap.phase3_recovery",
                    outcome = ?outcome,
                    "boot-time Phase 3 in-flight ceremony recovery completed"
                );
            }
            Err(e) => {
                tracing::error!(
                    stage = "bootstrap.phase3_recovery_failed",
                    error = %e,
                    "boot-time Phase 3 in-flight ceremony recovery failed; \
                     identity will load from current on-disk state"
                );
            }
        }
    }

    let loaded_arc: Option<Arc<household_rs::LoadedIdentity>> =
        match household_rs::try_load_existing(&state_dir, key_policy) {
            Ok(Some(loaded)) => Some(Arc::new(loaded)),
            Ok(None) => {
                info!(
                    stage = "bootstrap.cold",
                    "no household identity on disk; /identity will return 503 until `theyos install` runs"
                );
                None
            }
            Err(e) => {
                household_rs::bootstrap::log_error(&e);
                panic!("household identity load failed: {e}");
            }
        };
    let identity_state = match loaded_arc.as_ref() {
        Some(arc) => {
            let owner_auth = load_owner_auth_for_identity(&state_dir, arc);
            HouseholdState::loaded_with_owner_auth(Arc::clone(arc), owner_auth)
        }
        None => HouseholdState::empty(),
    };

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
    let initial_bootstrap_state =
        if initial_bootstrap_state == BootstrapState::Uninitialized && loaded_arc.is_some() {
            let inferred = infer_bootstrap_state(loaded_arc.as_ref(), &identity_state).await;
            if inferred == BootstrapState::Uninitialized {
                initial_bootstrap_state
            } else {
                if let Err(e) = bootstrap_state::persist(&state_dir, inferred) {
                    tracing::warn!(
                        stage = "bootstrap_state.infer_persist_failed",
                        error = %e,
                    );
                }
                inferred
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

    // Build the persistent PairDeviceWindow — synchronizes on-disk snapshot with
    // in-memory state so that `theyos install` (separate process) and the
    // daemon agree on which token is currently live.
    let pair_device_window =
        Arc::new(household_rs::pair_device::PairDeviceWindow::with_persistence(state_dir.clone()));
    if identity_state.current_owner_auth().await.is_some() {
        pair_device_window.close().await;
    } else if let Err(e) = load_persisted_pair_device_window(&state_dir, &pair_device_window).await
    {
        // Stale or corrupt snapshot: drop it, log, and proceed with closed
        // window. The operator can rerun `theyos install --reissue-pair-qr`.
        tracing::warn!(
            stage = "pair_device_window.snapshot_load_failed",
            error = %e,
            "discarding pair-window snapshot"
        );
        let _ = household_rs::storage::delete_pair_device_window_snapshot(&state_dir);
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
    let pair_machine_window = match PairMachineWindow::with_persistence(state_dir.clone()) {
        Ok(w) => Arc::new(w),
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine_window.load_failed",
                error = %e,
                "starting Phase 3 pair-machine window in idle (snapshot will be rewritten on first transition)",
            );
            // Construct an in-memory window so the router still mounts.
            // The next successful transition will persist a fresh snapshot.
            Arc::new(PairMachineWindow::new_in_memory())
        }
    };
    let owner_event_broadcaster = OwnerEventsBroadcaster::new();
    let mut bonjour_browser_state = None;
    let pair_machine_router = match OwnerEventLog::open_with_broadcaster(
        state_dir.clone(),
        owner_event_broadcaster.clone(),
    ) {
        Ok(owner_event_log) => {
            let pair_machine_state = handlers_pair_machine::PairMachineRouterState {
                window: Arc::clone(&pair_machine_window),
                household: identity_state.clone(),
                event_log: Arc::clone(&owner_event_log),
                event_broadcaster: owner_event_broadcaster.clone(),
                state_dir: state_dir.clone(),
            };
            bonjour_browser_state = Some(pair_machine_state.clone());
            let owner_events_state = handlers_owner_events::OwnerEventsRouterState::new(
                identity_state.clone(),
                Arc::clone(&pair_machine_window),
                owner_event_log,
                owner_event_broadcaster,
                state_dir.clone(),
                key_policy,
            );
            let sign_machine_cert_state =
                crate::handlers_sign_machine_cert::SignMachineCertRouterState {
                    household: identity_state.clone(),
                    event_log: Arc::clone(&pair_machine_state.event_log),
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
                                "/api/v1/household/owner-events/{cursor}/approve",
                                axum::routing::post(handlers_owner_events::owner_approve_handler),
                            )
                            .route(
                                "/api/v1/household/owner-events/{cursor}/decline",
                                axum::routing::post(handlers_owner_events::owner_decline_handler),
                            )
                            .with_state(owner_events_state),
                    )
                    .merge(sign_machine_cert_router),
            )
        }
        Err(e) => {
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
    let initial_bound =
        household_listener::spawn_household_listeners(household_router.clone(), port, &bound_set)
            .await;
    info!(
        stage = "bootstrap.endpoint.live",
        bound_count = initial_bound.len(),
        port = port,
        "household listeners up"
    );
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
        tokio::spawn(async move {
            household_listener::refresh_loop(router, port, bound).await;
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
    let bs_str = global_bootstrap_state()
        .map(|arc| {
            let val = *arc.try_read().unwrap_or_else(|_| arc.blocking_read());
            val.as_str().to_string()
        })
        .unwrap_or_default();
    let params = bonjour_publisher::PublishParams {
        hh_id: loaded.record.hh_id.to_string(),
        hh_name: loaded.record.name.clone(),
        m_id: loaded.cert.m_id.to_string(),
        port,
        host_label,
        host_dns: raw_hostname,
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
            match household_rs::try_load_existing(&state_dir, key_policy) {
                Ok(Some(loaded)) => {
                    let loaded = Arc::new(loaded);
                    let owner_auth = load_owner_auth_for_identity(&state_dir, &loaded);
                    // Set identity + owner_auth atomically so no reader sees the
                    // intermediate state (identity=Some, owner_auth=None) that
                    // causes infer_bootstrap_state to return NamedAwaitingPair.
                    let close_window = owner_auth.is_some();
                    identity_state
                        .set_loaded_with_owner_auth(Arc::clone(&loaded), owner_auth)
                        .await;
                    if close_window {
                        pair_device_window.close().await;
                    }
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
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        stage = "bootstrap.hot_load_failed",
                        error = %e,
                        "household identity hot-load failed; retrying"
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
    state_dir: PathBuf,
    pair_device_window: Arc<household_rs::pair_device::PairDeviceWindow>,
    identity_state: HouseholdState,
    poll_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        loop {
            interval.tick().await;
            if identity_state.current_owner_auth().await.is_some() {
                pair_device_window.close().await;
                break;
            }

            let path = household_rs::storage::pair_device_window_path(&state_dir);
            match std::fs::metadata(&path) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    tracing::warn!(
                        stage = "pair_device_window.snapshot_watch_failed",
                        path = %path.display(),
                        error = %e,
                    );
                    continue;
                }
            }

            match load_pair_device_window_snapshot_if_new(&state_dir, &pair_device_window).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(
                        stage = "pair_device_window.snapshot_reload_failed",
                        error = %e,
                        "discarding pair-window snapshot"
                    );
                    let _ = household_rs::storage::delete_pair_device_window_snapshot(&state_dir);
                }
            }
        }
    })
}

async fn load_pair_device_window_snapshot_if_new(
    state_dir: &Path,
    pair_device_window: &household_rs::pair_device::PairDeviceWindow,
) -> Result<(), String> {
    let snap_path = household_rs::storage::pair_device_window_path(state_dir);
    let snap: Option<household_rs::pair_device::PairDeviceWindowSnapshot> =
        household_rs::storage::read_optional_cbor(&snap_path)
            .map_err(|e| format!("read pair-window snapshot: {e}"))?;
    let Some(snap) = snap else {
        return Ok(());
    };
    let Some(token) = household_rs::pair_device::PairToken::from_snapshot(&snap)
        .map_err(|e| format!("decode pair-window snapshot: {e}"))?
    else {
        let _ = household_rs::storage::delete_pair_device_window_snapshot(state_dir);
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
async fn load_persisted_pair_device_window(
    state_dir: &Path,
    pair_device_window: &household_rs::pair_device::PairDeviceWindow,
) -> Result<(), String> {
    let snap_path = household_rs::storage::pair_device_window_path(state_dir);
    let snap: Option<household_rs::pair_device::PairDeviceWindowSnapshot> =
        household_rs::storage::read_optional_cbor(&snap_path)
            .map_err(|e| format!("read pair-window snapshot: {e}"))?;
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
            pair_device_window.install_token(token).await;
        }
        None => {
            // Expired snapshot: clean it up.
            let _ = household_rs::storage::delete_pair_device_window_snapshot(state_dir);
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

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::claw_share::{SlotId, SlotState};
    use household_rs::household_mesh_log::{LogEntry, MeshEvent};
    use household_rs::keys::{IdentityKey, P256Keypair};
    use household_rs::person_cert::SignOwnerOptions;

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
            household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf()),
        );
        let cli_window =
            household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf());

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
        let daemon_window = Arc::new(
            household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf()),
        );
        let cli_window =
            household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf());
        let identity = household_rs::bootstrap_or_load(
            td.path(),
            household_rs::BootstrapOpts {
                household_name: "Sample Home".to_string(),
                hostname_label: Some("studio-mac".to_string()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap identity from install path");
        let owner_auth = owner_auth_for(&identity);
        let identity_state =
            HouseholdState::loaded_with_owner_auth(Arc::new(identity), Some(Arc::new(owner_auth)));

        cli_window
            .mint_token(Duration::from_secs(60), None)
            .await
            .unwrap();
        assert!(household_rs::storage::pair_device_window_path(td.path()).exists());

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
        assert!(!household_rs::storage::pair_device_window_path(td.path()).exists());
    }

    #[tokio::test]
    async fn identity_watcher_hot_loads_after_install_without_restart() {
        let td = tempfile::tempdir().unwrap();
        let identity_state = HouseholdState::empty();
        let pair_device_window = Arc::new(
            household_rs::pair_device::PairDeviceWindow::with_persistence(td.path().to_path_buf()),
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
