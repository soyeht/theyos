//! Shared application state injected into every axum handler via `State<Arc<AppState>>`.
//!
//! Phase 1: session store, claw registry, jobs store, version cache.
//! Phase 2: instance DB, rate limiter, executor.
//! Phase 3: terminal manager, PTY manager, VM runner, log store.

use crate::handlers_llm::ProxyClient;
use crate::mobile_claw_vpn_relay_dial_config::MobileClawVpnRendezvousRelayDialConfig;
use crate::mobile_token::{MobileSessionDb, MobileTokenStore};
use crate::ratelimit::Limiter;
use executor_rs::Executor;
use household_rs::claw_vpn_mobile_mesh_store::ClawVpnMobileMeshStore;
use jobs_rs::Store as JobsStore;
use session_rs::SessionStore;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use store_rs::InstanceDb;
use terminal_rs::pty::PtyManager;
use vmrunner_rs::VmRunner;

/// Version cache — refreshed in the background every N minutes.
#[derive(Default)]
pub struct VersionCache {
    pub version: String,
    pub update_available: bool,
}

/// All shared services. Constructed once at startup and cloned cheaply via `Arc`.
///
/// Lock ordering (for the single remaining externally-locked field):
///   1. executor (Arc<Mutex<Executor>> — required because Executor holds IPC connections)
///
/// Note: `instance_db` and `jobs` have interior `Mutex<Connection>` and do NOT
/// need an outer Mutex — they are directly accessible on `AppState`.
pub struct AppState {
    // ── Phase 1 ──────────────────────────────────────────────────────────
    pub sessions: SessionStore,
    pub jobs: JobsStore,
    pub ver_cache: RwLock<VersionCache>,

    // ── Phase 2 ──────────────────────────────────────────────────────────
    /// SQLite-backed instances table (new instances created via async jobs).
    pub instance_db: InstanceDb,
    /// Rate limiter — per-user per-action hourly quota.
    pub rate_limiter: Arc<Limiter>,
    /// Executor — orchestrates VM lifecycle flows (create/delete/restart/stop).
    /// Wrapped in Arc<Mutex> because Executor holds IPC connections (not Clone).
    pub executor: Arc<Mutex<Executor>>,

    // ── Phase 3 ──────────────────────────────────────────────────────────
    /// PTY manager — real OS PTY sessions via pty-process.
    pub pty_mgr: Arc<PtyManager>,
    /// VM runner — lifecycle ops (restart, `fetch_logs`) via firecracker.
    pub vm_runner: Arc<VmRunner>,

    // ── Phase 5: Mobile QR Auth ─────────────────────────────────────────────
    /// In-memory token store for QR-based mobile authentication (QR tokens only).
    pub mobile_tokens: Arc<MobileTokenStore>,
    /// SQLite-backed mobile session store (persistent across restarts).
    pub mobile_sessions: MobileSessionDb,
    /// Persisted Product A mobile per-Claw VPN Mesh-C model. This is API-adjacent
    /// state only; owner-sensitive mutations stay behind explicit owner-approved
    /// store methods.
    pub mobile_claw_vpn_mesh: ClawVpnMobileMeshStore,
    /// Default-off Relay-R dial target config for mobile Claw VPN rendezvous
    /// preflight. Missing relay address keeps the handler on an inert sink.
    pub mobile_claw_vpn_relay_dial: MobileClawVpnRendezvousRelayDialConfig,

    // ── Phase 6: Claw Store ────────────────────────────────────────────────
    /// Dynamic per-host claw install state (ready / installing / `not_installed`).
    pub claw_store: claw_rs::ClawStore,

    // ── Config ────────────────────────────────────────────────────────────
    /// Repo root directory (from `THEYOS_DIR` env var).
    pub theyos_dir: PathBuf,

    // ── Maintenance mode ────────────────────────────────────────────────
    /// Directory for maintenance lock files (`<FIRECRACKER_STATE_DIR>/locks/`).
    /// Used by handlers to check if instance creation is blocked during
    /// artifact sync operations.
    pub locks_dir: PathBuf,

    // ── Capacity guard ─────────────────────────────────────────────────
    /// Serializes capacity check + DB insert to prevent over-commitment.
    pub capacity_lock: tokio::sync::Mutex<()>,

    // ── LLM proxy reverse-proxy client ──────────────────────────────────
    /// reqwest client pre-built for talking to the host-side
    /// `theyos-llm-proxy` daemon on loopback. Used by `handlers_llm` to
    /// forward `/api/v1/llm/*` admin requests after auth. Cheap to clone.
    pub llm_proxy_client: ProxyClient,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    /// Fire-and-forget audit log on a blocking thread.
    ///
    /// The caller moves `self: SharedState` (cheap Arc clone) and the owned
    /// strings into the closure. Failures are logged as warnings — audit events
    /// must never fail the parent request.
    pub fn spawn_audit(
        self: Arc<Self>,
        instance_id: Option<String>,
        username: String,
        action: impl Into<String> + Send + 'static,
        detail: Option<String>,
    ) {
        tokio::task::spawn_blocking(move || {
            let action = action.into();
            if let Err(e) = self.instance_db.record_audit_event(
                instance_id.as_deref(),
                &username,
                &action,
                detail.as_deref(),
            ) {
                tracing::warn!("[audit] log failed: {e}");
            }
        });
    }
}
