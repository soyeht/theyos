//! server-rs — Rust HTTP server (replaced Go admin backend).
//!
//! # Environment variables
//!
//! | Variable                    | Default                  | Description                        |
//! |-----------------------------|--------------------------|-------------------------------------|
//! | `ADDR`                      | `127.0.0.1:8090`         | Listen address                      |
//! | `WEB_DIR`                   | `web`                    | Built frontend assets directory     |
//! | `FRONTEND_ORIGIN`           | `http://localhost:5173`  | Allowed CORS origin                 |
//! | `THEYOS_SQLITE_DB`          | `/tmp/theyos.db`         | SQLite database path                |
//! | `THEYOS_BASE_DOMAIN`        | (required)               | Base domain — set in .env           |
//! | `THEYOS_PROVIDERS_DATA_DIR` | `/data`                  | Providers data directory            |
//! | `THEYOS_JOBS_DB`            | (derived from SQLITE_DB) | Jobs SQLite path                    |
//! | `THEYOS_RATELIMIT_DB`       | (derived from SQLITE_DB) | Rate limit SQLite path              |
//! | `FIRECRACKER_CTL`           | `fc-ssh`                 | PTY + terminal command control path |
//! | (executor env vars)         | —                        | Forwarded to executor::FlowConfig   |

use server_rs::auth;
use server_rs::claw_store_routes;
use server_rs::cloudflare_admin;
use server_rs::config;
use server_rs::handlers_admin;
use server_rs::handlers_instances;
use server_rs::handlers_invites;
use server_rs::handlers_jobs;
use server_rs::handlers_misc;
use server_rs::handlers_mobile;
use server_rs::handlers_network;
use server_rs::handlers_terminal;
use server_rs::handlers_terminal_attachments;
use server_rs::health;
use server_rs::install_worker;
use server_rs::jobs_worker;
use server_rs::mobile_token::{MobileSessionDb, MobileTokenStore};
use server_rs::public_sites;
use server_rs::state::{AppState, SharedState};
use server_rs::version;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    response::Html,
    routing::{delete, get, patch, post, put},
};
use executor_rs::{Executor, FlowConfig};
use jobs_rs::Store as JobsStore;
use server_rs::auth::require_auth;
use server_rs::ratelimit::Limiter;
use session_rs::SessionStore;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use store_rs::InstanceDb;
use terminal_rs::pty::PtyManager;
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use vmrunner_common_rs::VmCreateResourceSpec;
use vmrunner_rs::VmRunner;

const MOBILE_CLAW_VPN_OFFER_TTL_SECS_ENV: &str = "THEYOS_MOBILE_CLAW_VPN_OFFER_TTL_SECS";
const DEFAULT_MOBILE_CLAW_VPN_OFFER_TTL_SECS: u64 = 10 * 60;

/// Set `Cache-Control` headers for static assets and SPA HTML responses.
///
/// - `/assets/*` → `public, max-age=31536000, immutable` (content-hashed filenames)
/// - `text/html`  → `no-cache` (always revalidate — prevents CDN from caching stale HTML)
async fn set_cache_control(
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let is_asset = req.uri().path().starts_with("/assets/");
    let mut resp = next.run(req).await;

    if is_asset {
        resp.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    } else if resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html"))
    {
        resp.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-cache"),
        );
    }

    resp
}

/// Rewrite 404 responses that serve `text/html` (SPA fallback) to 200.
///
/// `ServeDir::not_found_service(ServeFile::new("index.html"))` in tower-http
/// 0.6 returns the correct body but with 404 status for SPA routes like
/// `/terminals`. This middleware fixes the status for HTML responses only,
/// leaving actual 404s (JSON API, missing assets) untouched.
async fn rewrite_spa_404_to_200(
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    if resp.status() == axum::http::StatusCode::NOT_FOUND {
        let is_html = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/html"));
        if is_html {
            *resp.status_mut() = axum::http::StatusCode::OK;
        }
    }
    resp
}

async fn handle_privacy() -> Html<&'static str> {
    Html(include_str!("privacy.html"))
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() {
    // Initialise structured logging. Respect RUST_LOG; default to INFO.
    //
    // `THEYOS_LOG_FORMAT` selects the formatter:
    //   - `json`  → `tracing_subscriber::fmt::layer().json()` (default in release / production)
    //   - `text`  → human-readable `tracing_subscriber::fmt::layer()` (default in debug)
    //
    // Phase 1's structured-log contract (FR-014) assumes JSON in production —
    // so `error.stage`, `error.kind`, `error.hint` round-trip cleanly into the
    // log shipper and the bootstrap-log assertion test (T024a) parses them.
    let log_format = std::env::var("THEYOS_LOG_FORMAT").unwrap_or_else(|_| {
        if cfg!(debug_assertions) {
            "text".to_string()
        } else {
            "json".to_string()
        }
    });
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        "server=info,server_rs=info,tower_http=info"
            .parse()
            .unwrap()
    });
    if log_format == "json" {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    // ─── `theyos install` CLI subcommand (Phase 1, T023) ─────────────────────
    //
    // When the binary is invoked with `install` as argv[1], we run the
    // install flow (bootstrap + emit pair-receiving QR) and exit. The daemon
    // is started separately by launchd/systemd without a subcommand.
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() >= 2 && (argv[1] == "--version" || argv[1] == "-V") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    if argv.len() >= 2 && argv[1] == "install" {
        let exit_code = server_rs::install_cli::run(&argv[2..]).await;
        std::process::exit(exit_code);
    }

    let cfg = config::Config::from_env();
    info!("Starting server-rs on {}", cfg.addr);
    info!("Serving SPA from {:?}", cfg.web_dir);

    // ─── Household identity (Phase 1) — separate listener, deferred ──
    //
    // Per spec/001-phase-1-crypto-skeleton: a dedicated listener serves
    // /api/v1/household/* on concrete loopback / LAN / Tailscale addresses,
    // narrowed at runtime by HouseholdExposurePolicy. This is independent of
    // the main `cfg.addr` listener (which carries the existing /api/v1/mobile/*
    // surface — FR-010 untouched).
    //
    // `bootstrap_household` is now invoked AFTER `SharedState` is built (see
    // below) so that household-namespaced Claw Store routes can be mounted
    // on the same listener. The household listener still comes up well
    // before the main `cfg.addr` listener at `axum::serve()` near EOF, so
    // iPhone onboarding via Bonjour discovery is unaffected.
    let _push_status = server_rs::startup_wiring::install_house_created_push_transport_from_env();
    let _claw_vpn_status = server_rs::startup_wiring::per_claw_vpn_startup_gate_from_env();

    // ─── Shared state construction ────────────────────────────────────────────

    let sqlite_db =
        std::env::var("THEYOS_SQLITE_DB").unwrap_or_else(|_| "/tmp/theyos.db".to_string());

    let session_db = {
        let mut p = PathBuf::from(&sqlite_db);
        p.set_extension("sessions.db");
        p.to_string_lossy().to_string()
    };

    let sessions = SessionStore::open(&session_db).expect("Failed to open session store");
    info!("Session store: {}", session_db);

    // Spawn SIGHUP handler for config hot-reload (Unix-only)
    #[cfg(unix)]
    server_rs::shutdown::spawn_sighup_handler();

    // ── Claw Store + Registry init ────────────────────────────────────────
    let theyos_dir = std::env::var("THEYOS_DIR").map_or_else(|_| PathBuf::from("."), PathBuf::from);

    // Create stub dirs and set default env vars for all manifest claws
    // so Registry::from_env() discovers them without per-claw hardcoding.
    // SAFETY: called during single-threaded startup, before tokio runtime
    // spawns any worker threads. No concurrent env access is possible.
    #[allow(unsafe_code)]
    unsafe {
        for name in core_rs::manifest::all_names() {
            let code_dir = theyos_dir.join(format!("claws/src/{name}"));
            let data_dir = theyos_dir.join(format!("claws/data/{name}"));
            let _ = std::fs::create_dir_all(&code_dir);
            let _ = std::fs::create_dir_all(data_dir.join("customers"));

            // Set env vars if not already provided (e.g. by launcher-rs).
            let upper = name.replace('-', "_").to_uppercase();
            let code_key = format!("{upper}_CODE_DIR");
            let data_key = format!("{upper}_DATA_DIR");
            if std::env::var(&code_key).is_err() {
                std::env::set_var(&code_key, code_dir.to_string_lossy().as_ref());
            }
            if std::env::var(&data_key).is_err() {
                std::env::set_var(&data_key, data_dir.to_string_lossy().as_ref());
            }
        }

        std::env::set_var("CLAW_TYPES", core_rs::manifest::all_names().join(","));
    }

    // Note: `claw_rs::Registry` is no longer carried on AppState.
    // The claw store (`state.claw_store`) and the manifest
    // (`core_rs::manifest`) are the authoritative sources for the HTTP
    // API. The Registry still exists in the claw-rs crate for use by
    // `claw_ipc` and the executor's internal path resolution — see the
    // comment in the unsafe set_var block above for why the CLAW_TYPES
    // env var is still populated. It's read by subprocesses, not by
    // this process.

    // ClawStore — dynamic per-host install state
    let state_file = std::env::var("THEYOS_CLAW_STATE_FILE").map_or_else(
        |_| theyos_dir.join(".run/installed_claws.json"),
        PathBuf::from,
    );
    let claw_store = claw_rs::ClawStore::new(&state_file).expect("Failed to open claw store");
    info!("Claw store: {}", state_file.display());

    let jobs_db = std::env::var("THEYOS_JOBS_DB").unwrap_or_else(|_| {
        let mut p = PathBuf::from(&sqlite_db);
        p.set_file_name("jobs-rs.db");
        p.to_string_lossy().to_string()
    });
    let jobs = JobsStore::new(&jobs_db).expect("Failed to open jobs store");
    info!("Jobs store: {}", jobs_db);

    let instance_db = InstanceDb::open(&sqlite_db).expect("Failed to open instance DB");
    info!("Instance DB: {}", sqlite_db);

    // Seed bootstrap admin if no admin user exists yet (idempotent on restarts)
    let admin_user = std::env::var("SOYEHT_ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
    let admin_id = match instance_db.seed_admin(&admin_user) {
        Ok(id) => {
            info!("Bootstrap admin ready: username={admin_user}, id={id}");
            id
        }
        Err(e) => {
            tracing::error!("Failed to seed bootstrap admin: {e}");
            String::new()
        }
    };

    // Seed the mac-host virtual container on macOS (idempotent).
    #[cfg(target_os = "macos")]
    if !admin_id.is_empty() {
        match instance_db.seed_mac_host_instance(&admin_id) {
            Ok(()) => info!("mac-host instance ready"),
            Err(e) => tracing::warn!("Failed to seed mac-host instance: {e}"),
        }
    }

    let ratelimit_db = std::env::var("THEYOS_RATELIMIT_DB").unwrap_or_else(|_| {
        let mut p = PathBuf::from(&sqlite_db);
        p.set_file_name("ratelimit-rs.db");
        p.to_string_lossy().to_string()
    });
    let ratelimit_per_hour: i64 = std::env::var("THEYOS_RATELIMIT_PER_HOUR")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let rate_limiter =
        Limiter::new(&ratelimit_db, ratelimit_per_hour).expect("Failed to open rate limiter");
    info!(
        "Rate limiter: {} (limit={}/hr)",
        ratelimit_db, ratelimit_per_hour
    );

    let flow_config = flow_config_from_env(&sqlite_db);
    let locks_dir = PathBuf::from(&flow_config.firecracker_state_dir).join("locks");
    let executor = Executor::new(flow_config).expect("Failed to start executor subprocesses");
    info!("Executor: all sub-subprocesses started");

    // On macOS, use THEYOS_SSH_CTL (→ theyos-ssh); on Linux, use FIRECRACKER_CTL (→ fc-ssh).
    #[cfg(target_os = "macos")]
    let ssh_ctl = std::env::var("THEYOS_SSH_CTL").unwrap_or_else(|_| "theyos-ssh".to_string());
    #[cfg(not(target_os = "macos"))]
    let ssh_ctl = std::env::var("FIRECRACKER_CTL").unwrap_or_else(|_| "fc-ssh".to_string());

    // v2 persistent: conversations (both the on-disk log files and the DB
    // `terminal_conversations` rows) survive backend restarts. The only way
    // to lose history is the user explicitly deleting a conversation via the
    // UI. `create_dir_all` is idempotent — safe to call on every boot.
    let conv_dir = resolve_conv_dir();
    if let Err(e) = std::fs::create_dir_all(&conv_dir) {
        panic!(
            "failed to create conversations dir {}: {e}",
            conv_dir.display()
        );
    }
    info!("conversation log dir: {}", conv_dir.display());

    let pty_mgr = Arc::new(PtyManager::new(&ssh_ctl, conv_dir));
    info!("PTY manager: ctl={}", ssh_ctl);

    let vm_runner = Arc::new(VmRunner::from_env().expect("Failed to construct VmRunner from env"));
    info!("VM runner: initialized");

    let mobile_tokens = Arc::new(MobileTokenStore::new());
    mobile_tokens.start_cleanup_task();
    info!("Mobile token store: initialized");

    let mobile_session_db = {
        let mut p = PathBuf::from(&sqlite_db);
        p.set_extension("mobile-sessions.db");
        p.to_string_lossy().to_string()
    };
    let mobile_sessions =
        MobileSessionDb::open(&mobile_session_db).expect("Failed to open mobile session DB");
    info!("Mobile session DB: {}", mobile_session_db);

    let household_state_dir = server_rs::household_bootstrap::resolve_household_state_dir();
    let mobile_claw_vpn_offer_ttl_secs = mobile_claw_vpn_offer_ttl_secs_from_env();
    let mobile_claw_vpn_mesh =
        household_rs::claw_vpn_mobile_mesh_store::ClawVpnMobileMeshStore::new(
            household_state_dir,
            mobile_claw_vpn_offer_ttl_secs,
        )
        .expect("Failed to initialize mobile Claw VPN mesh store");
    info!(
        "Mobile Claw VPN mesh store: initialized (offer_ttl={}s)",
        mobile_claw_vpn_offer_ttl_secs
    );

    // ─── Full shared state ────────────────────────────────────────────────────

    let state: SharedState = Arc::new(AppState {
        sessions,
        jobs,
        ver_cache: std::sync::RwLock::default(),
        instance_db,
        rate_limiter: Arc::new(rate_limiter),
        executor: Arc::new(Mutex::new(executor)),
        pty_mgr,
        vm_runner,
        mobile_tokens,
        mobile_sessions,
        mobile_claw_vpn_mesh,
        claw_store,
        theyos_dir,
        locks_dir,
        capacity_lock: tokio::sync::Mutex::new(()),
        llm_proxy_client: server_rs::handlers_llm::ProxyClient::from_env(),
    });

    // ── Household identity listener bring-up ─────────────────────────────
    // Deferred from line ~190 to here so the listener can mount the
    // household-namespaced Claw Store routes that require SharedState.
    // The household listener still comes up before the main api listener
    // at the bottom of `main`, so iPhone onboarding via Bonjour stays
    // unaffected (FR-008/FR-017 timing window preserved).
    server_rs::household_bootstrap::bootstrap_household(Some(Arc::clone(&state))).await;

    // ── Cloudflared sync ─────────────────────────────────────────────────
    // Reconcile the on-disk cloudflared config.yml against the public_sites
    // table at startup. Handles drift (e.g. backend wrote sites while
    // cloudflared was off, or the file was edited manually). Env-gated:
    // silently no-ops when THEYOS_CLOUDFLARED_CONFIG is unset.
    server_rs::cloudflared_sync::sync_cloudflared_config(&state).await;

    // ── Phase 1: snapshot active instances, then sweep orphans + reconcile DB ──
    // Save the list of Active containers BEFORE sweep/reconcile marks them as Stopped.
    let previously_active: Vec<(String, String, i64, i64)> = {
        let st = Arc::clone(&state);
        tokio::task::spawn_blocking(move || {
            let create_defaults = VmCreateResourceSpec::default().resolve();
            match st.instance_db.list() {
                Ok(rows) => {
                    let active: Vec<(String, String, i64, i64)> = rows
                        .into_iter()
                        .filter(|r| r.status == store_rs::InstanceStatus::Active)
                        .filter(|r| r.claw_type != "mac-host") // no VM restart needed
                        .map(|r| {
                            (
                                r.id,
                                r.container,
                                r.cpu_cores.unwrap_or(i64::from(create_defaults.cpu_cores)),
                                r.ram_config_mb.unwrap_or(i64::from(create_defaults.ram_mb)),
                            )
                        })
                        .collect();
                    tracing::info!(
                        "[startup] found {} active instance(s) to restart after sweep",
                        active.len()
                    );
                    active
                }
                Err(e) => {
                    tracing::error!("[startup] failed to list instances for auto-restart: {e}");
                    vec![]
                }
            }
        })
        .await
        .unwrap_or_default()
    };

    {
        let st = Arc::clone(&state);
        let result = tokio::task::spawn_blocking(move || {
            let report = st.vm_runner.sweep_orphans();
            if report.instances_cleaned > 0 || report.dirs_removed > 0 {
                tracing::warn!(
                    "[sweep] startup: instances_cleaned={} dirs_removed={} containers={:?}",
                    report.instances_cleaned,
                    report.dirs_removed,
                    report.cleaned_containers,
                );
            } else {
                tracing::info!("[sweep] startup: no orphans found");
            }
            server_rs::reconcile::reconcile_after_sweep(
                &st.instance_db,
                &st.vm_runner.env.state_dir,
                &report,
            );
        })
        .await;
        if let Err(e) = result {
            tracing::error!("[startup] sweep+reconcile panicked: {e}");
        }
    }

    // ── Phase 2: auto-restart instances that were Active before the restart ──
    if !previously_active.is_empty() {
        let st = Arc::clone(&state);
        tokio::task::spawn(async move {
            tracing::info!(
                "[startup] auto-restarting {} instance(s) that were active before shutdown",
                previously_active.len()
            );

            for (instance_id, container, cpu_cores, ram_mb) in &previously_active {
                tracing::info!("[startup] restarting {container} ({instance_id})...");

                let result = tokio::task::spawn_blocking({
                    let st3 = Arc::clone(&st);
                    let instance_id = instance_id.clone();
                    let container = container.clone();
                    let cpu_cores = *cpu_cores;
                    let ram_mb = *ram_mb;
                    move || {
                        let Ok(exec) = st3.executor.lock() else {
                            return Err("executor lock".into());
                        };
                        let req = executor_rs::ExecuteFlowRequest {
                            flow_type: executor_rs::FlowType::Restart,
                            instance_id: instance_id.clone(),
                            name: String::new(),
                            container,
                            claw_type: String::new(),
                            attempt_errors: vec![],
                            attempt_ports: vec![],
                            max_port_retries: 0,
                            tools: vec![],
                            guest_os: String::new(),
                            cpu_cores: None,
                            ram_mb: None,
                            disk_gb: None,
                        };
                        let result = exec.execute_flow(&req);
                        if result.status == executor_rs::FlowStatus::Completed {
                            let created = server_rs::reconcile::ensure_restarted_runtime_lease(
                                &st3.instance_db,
                                &instance_id,
                                cpu_cores,
                                ram_mb,
                            )
                            .map_err(|e| format!("ensure runtime lease: {e}"))?;
                            if created {
                                tracing::info!(
                                    "[startup] restored runtime lease for restarted instance {instance_id}"
                                );
                            }
                            Ok(())
                        } else {
                            Err(result.error.unwrap_or_else(|| "unknown".into()))
                        }
                    }
                })
                .await;

                match result {
                    Ok(Ok(())) => {
                        tracing::info!("[startup] {container} restarted successfully");
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("[startup] {container} restart failed: {e}");
                    }
                    Err(e) => {
                        tracing::warn!("[startup] {container} restart panicked: {e}");
                    }
                }

                // Rate-limit: wait between restarts
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }

            tracing::info!(
                "[startup] auto-restart complete ({} instance(s))",
                previously_active.len()
            );
        });
    }

    // Start background version cache refresher (every 5 minutes).
    let version_interval = std::env::var("THEYOS_VERSION_REFRESH_INTERVAL")
        .ok()
        .and_then(|v| core_rs::env::parse_duration_str(&v))
        .unwrap_or(Duration::from_secs(5 * 60));
    version::start_version_refresher(Arc::clone(&state), version_interval);

    // Start periodic session cleanup (every hour).
    {
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                let st2 = Arc::clone(&st);
                match tokio::task::spawn_blocking(move || st2.sessions.cleanup_expired()).await {
                    Ok(Ok(0)) => {}
                    Ok(Ok(n)) => tracing::info!("[sessions] cleaned up {n} expired session(s)"),
                    Ok(Err(e)) => tracing::warn!("[sessions] cleanup error: {e}"),
                    Err(e) => tracing::warn!("[sessions] cleanup task panicked: {e}"),
                }
                // Clean up expired mobile sessions (SQLite).
                match st.mobile_sessions.cleanup_expired() {
                    Ok(0) => {}
                    Ok(n) => {
                        tracing::info!("[mobile-sessions] cleaned up {n} expired session(s)");
                    }
                    Err(e) => tracing::warn!("[mobile-sessions] cleanup error: {e}"),
                }
                let stale_count = st.pty_mgr.cleanup_stale();
                if stale_count > 0 {
                    tracing::info!("[maintenance] cleaned up {stale_count} stale PTY session(s)");
                }
                // Expire terminal workspaces idle for >90 days.
                let st3 = Arc::clone(&st);
                match tokio::task::spawn_blocking(move || {
                    st3.instance_db.cleanup_stale_conversations(90)
                })
                .await
                {
                    Ok(Ok(0)) => {}
                    Ok(Ok(n)) => {
                        tracing::info!("[maintenance] expired {n} stale terminal workspace(s)");
                    }
                    Ok(Err(e)) => tracing::warn!("[maintenance] workspace cleanup error: {e}"),
                    Err(e) => tracing::warn!("[maintenance] workspace cleanup panicked: {e}"),
                }
            }
        });
    }

    // Seed claw store from existing assets (auto-marks ready for pre-built claws)
    #[cfg(target_os = "macos")]
    state.claw_store.seed_from_macos_base();

    #[cfg(not(target_os = "macos"))]
    {
        // locks_dir is <FC_STATE_DIR>/locks; assets are at <FC_STATE_DIR>/../assets
        if let Some(fc_state_dir) = state.locks_dir.parent() {
            if let Some(fc_root) = fc_state_dir.parent() {
                let assets_dir = fc_root.join("assets");
                state.claw_store.seed_from_assets(&assets_dir);
            }
        }
    }

    // Warm pool: if disabled, drain any leftover slots from a previous run.
    // Otherwise, the reconciler loop will fill slots on its own schedule.
    {
        let pool_enabled = !matches!(
            std::env::var("THEYOS_WARM_POOL_SIZE").as_deref(),
            Ok("0" | "disabled")
        );
        if !pool_enabled {
            info!("[startup] warm pool disabled: draining existing slots");
            let st = Arc::clone(&state);
            match tokio::task::spawn_blocking(move || {
                let exec = st
                    .executor
                    .lock()
                    .map_err(|_| "executor lock poisoned".to_string())?;
                exec.warm_pool_drain().map_err(|e| e.to_string())
            })
            .await
            {
                Ok(Ok(v)) => info!("[startup] warm_pool_drain: {v}"),
                Ok(Err(e)) => tracing::warn!("[startup] warm_pool_drain failed: {e}"),
                Err(e) => tracing::warn!("[startup] warm_pool_drain task panicked: {e}"),
            }
        }
    }

    // Start background jobs worker — capture handle to detect panics.
    let jobs_handle = jobs_worker::start_jobs_worker(Arc::clone(&state));

    // Start background install worker (separate from jobs worker — D4)
    let _install_handle = install_worker::start_install_worker(Arc::clone(&state));

    // Start warm pool reconciler — the only source of refill dispatches.
    let reconciler_handle =
        server_rs::warm_pool_reconciler::start_warm_pool_reconciler(Arc::clone(&state));

    // Start lease reaper — cleans up expired provisioning leases.
    let _reaper_handle = server_rs::lease_reaper::start_lease_reaper(Arc::clone(&state));

    // Monitor jobs worker for panics in a separate tokio task.
    tokio::spawn(async move {
        match jobs_handle.await {
            Ok(()) => tracing::error!("[monitor] jobs worker exited unexpectedly"),
            Err(e) => tracing::error!("[monitor] jobs worker panicked: {e}"),
        }
    });

    // Monitor reconciler for panics.
    tokio::spawn(async move {
        match reconciler_handle.await {
            Ok(()) => tracing::info!("[monitor] warm pool reconciler exited"),
            Err(e) => tracing::error!("[monitor] warm pool reconciler panicked: {e}"),
        }
    });

    // ─── CORS ─────────────────────────────────────────────────────────────────

    let cors = CorsLayer::new()
        .allow_origin(
            cfg.frontend_origin
                .parse::<axum::http::HeaderValue>()
                .expect("Invalid FRONTEND_ORIGIN"),
        )
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE])
        .allow_credentials(true);

    // ─── SPA static files ─────────────────────────────────────────────────────
    //
    // `ServeDir` serves actual static files (/assets/*). For SPA routes like
    // `/terminals` or `/network`, `ServeDir::not_found_service` serves
    // index.html but tower-http 0.6 returns 404 status, which generates
    // browser console errors. We wrap the SPA service in a layer that rewrites
    // 404 HTML responses to 200.

    let index_path = format!("{}/index.html", cfg.web_dir);
    let spa_service = ServeDir::new(&cfg.web_dir).not_found_service(ServeFile::new(&index_path));

    // ─── Auth-protected API routes ────────────────────────────────────────────

    // Streaming routes (WebSocket) — no timeout, no body limit.
    let api_streaming = Router::new().route(
        "/terminals/{container}/pty",
        get(handlers_terminal::handle_terminal_pty),
    );

    // REST routes — 60 s timeout to prevent hung handlers.
    let api_rest = Router::new()
        // Auth
        .route("/auth/logout", post(auth::handle_logout))
        .route("/me", get(auth::handle_me))
        // Misc
        .route("/claw-types", get(handlers_misc::handle_claw_types))
        .merge(claw_store_routes::admin_routes())
        .route("/version", get(handlers_misc::handle_version))
        .route("/logs", get(handlers_misc::handle_logs))
        // Network
        .route(
            "/network/status",
            get(handlers_network::handle_network_status),
        )
        .route("/network/expose", post(handlers_network::handle_expose))
        // Jobs
        .route("/jobs", get(handlers_jobs::handle_list_jobs))
        .route("/jobs/{id}", get(handlers_jobs::handle_get_job))
        // Instances
        .route("/instances", get(handlers_instances::handle_list_instances))
        .route(
            "/instances",
            post(handlers_instances::handle_create_instance_body),
        )
        .route(
            "/instances/{id}",
            get(handlers_instances::handle_get_instance),
        )
        .route(
            "/instances/{id}/status",
            get(handlers_instances::handle_instance_status),
        )
        .route(
            "/instances/{id}/public-sites",
            get(public_sites::handle_list_public_sites)
                .post(public_sites::handle_upsert_public_sites),
        )
        .route(
            "/instances/{id}/public-sites/{domain}",
            delete(public_sites::handle_delete_public_site),
        )
        .route(
            "/instances/{id}/stop",
            post(handlers_instances::handle_stop_instance),
        )
        .route(
            "/instances/{id}/restart",
            post(handlers_instances::handle_restart_instance),
        )
        .route(
            "/instances/{id}/rebuild",
            post(handlers_instances::handle_rebuild_instance),
        )
        .route(
            "/instances/{id}",
            delete(handlers_instances::handle_delete_instance),
        )
        .route(
            "/instances/{id}/autoupdate",
            post(handlers_instances::handle_instance_autoupdate),
        )
        .route(
            "/instances/{id}",
            patch(handlers_instances::handle_assign_owner),
        )
        // Admin operations — warm pool
        .route(
            "/admin/warm-pool-status",
            get(handlers_admin::handle_warm_pool_status),
        )
        .route(
            "/admin/warm-pool-refill",
            post(handlers_admin::handle_warm_pool_refill),
        )
        .route(
            "/admin/warm-pool-init",
            post(handlers_admin::handle_warm_pool_init),
        )
        .route(
            "/admin/drain-warm-pool",
            post(handlers_admin::handle_drain_warm_pool),
        )
        // Admin operations — host resource metrics
        .route("/admin/resources", get(handlers_admin::handle_resources))
        // Admin operations — simulator token (long-lived mobile session)
        .route(
            "/admin/simulator-token",
            post(handlers_mobile::handle_simulator_token),
        )
        // Admin operations — maintenance mode
        .route(
            "/admin/maintenance",
            get(handlers_admin::handle_maintenance_status),
        )
        // Admin operations — Cloudflare tunnel (UI-driven setup, replaces SSH+nix)
        .route(
            "/admin/cloudflare/status",
            get(cloudflare_admin::handle_status),
        )
        .route(
            "/admin/cloudflare/zones",
            post(cloudflare_admin::handle_list_zones),
        )
        .route(
            "/admin/cloudflare/setup",
            post(cloudflare_admin::handle_setup).delete(cloudflare_admin::handle_disconnect),
        )
        // LLM proxy — reverse-proxied to the host-side daemon after admin
        // auth. See handlers_llm.rs for the rationale (split user identity
        // between server-rs and llm-proxy-rs).
        .route("/llm/catalog", get(server_rs::handlers_llm::handle_catalog))
        .route(
            "/llm/active",
            get(server_rs::handlers_llm::handle_get_active)
                .put(server_rs::handlers_llm::handle_put_active),
        )
        .route(
            "/llm/active/{claw_type}",
            put(server_rs::handlers_llm::handle_put_active_claw)
                .delete(server_rs::handlers_llm::handle_delete_active_claw),
        )
        .route(
            "/llm/providers",
            get(server_rs::handlers_llm::handle_list_providers)
                .post(server_rs::handlers_llm::handle_upsert_provider),
        )
        .route(
            "/llm/providers/{id}",
            delete(server_rs::handlers_llm::handle_delete_provider),
        )
        .route(
            "/llm/providers/{id}/test",
            post(server_rs::handlers_llm::handle_test_provider),
        )
        .route("/llm/audit", get(server_rs::handlers_llm::handle_get_audit))
        // Terminals (non-streaming)
        .route(
            "/terminals/containers",
            get(handlers_terminal::handle_containers),
        )
        .route(
            "/terminals/{container}/reconnect",
            post(handlers_terminal::handle_terminal_reconnect),
        )
        .route(
            "/terminals/{container}/workspace",
            post(handlers_terminal::handle_terminal_workspace),
        )
        // Conversations management (v2: formerly "workspaces"). Paths kept
        // under /workspaces for iOS contract compatibility until the app ships
        // the renamed paths.
        .route(
            "/terminals/{container}/workspaces",
            get(handlers_terminal::handle_list_conversations)
                .post(handlers_terminal::handle_create_conversation),
        )
        .route(
            "/terminals/{container}/workspaces/{id}",
            patch(handlers_terminal::handle_rename_conversation)
                .delete(handlers_terminal::handle_delete_conversation),
        )
        // File browser (VM filesystem — read-only)
        .route(
            "/terminals/{container}/files",
            get(handlers_terminal::handle_files_list),
        )
        .route(
            "/terminals/{container}/files/read",
            get(handlers_terminal::handle_files_read),
        )
        .route(
            "/terminals/{container}/files/download",
            get(handlers_terminal::handle_files_download),
        )
        // Invites (admin-authed)
        .route(
            "/invites",
            get(handlers_invites::handle_list_invites).post(handlers_invites::handle_create_invite),
        )
        .route(
            "/invites/{id}",
            delete(handlers_invites::handle_delete_invite),
        )
        // Mobile — QR token generation (admin-authed)
        .route(
            "/instances/{id}/qr-token",
            post(handlers_mobile::handle_generate_qr_token),
        )
        // Product A mobile Claw VPN Mesh-C owner/admin actions. These mutate
        // only the persisted Mesh-C model; they do not mint usable offers,
        // open relay sessions, or touch host networking.
        .route(
            "/mobile/claw-vpn/owner/enroll-device",
            post(handlers_mobile::handle_admin_mobile_claw_vpn_enroll_device),
        )
        .route(
            "/mobile/claw-vpn/owner/claw-availability",
            post(handlers_mobile::handle_admin_mobile_claw_vpn_set_claw_availability),
        )
        .route(
            "/mobile/claw-vpn/owner/grant",
            post(handlers_mobile::handle_admin_mobile_claw_vpn_grant),
        )
        .route(
            "/mobile/claw-vpn/owner/revoke-grant",
            post(handlers_mobile::handle_admin_mobile_claw_vpn_revoke_grant),
        )
        // Mobile — Continue on iPhone (any authed user, for own workspaces)
        .route(
            "/mobile/continue-qr",
            post(handlers_mobile::handle_generate_continue_qr),
        )
        .route(
            "/mobile/qr-status/{token}",
            get(handlers_mobile::handle_continue_qr_status),
        )
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(60),
        ));

    // Upload routes — larger body limit (100 MB) and longer timeout (10 min).
    let api_uploads = Router::new()
        .route(
            "/terminals/{container}/attachments",
            post(handlers_terminal_attachments::handle_upload_attachment),
        )
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(600),
        ));

    let api = api_rest
        .merge(api_streaming)
        .merge(api_uploads)
        // Apply auth middleware to all routes
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ))
        .with_state(Arc::clone(&state));

    // ─── Full router ─────────────────────────────────────────────────────────

    // ─── Mobile API routes (own auth via Bearer token) ──────────────────────
    // Nested at /api/v1/mobile — routes here omit the /mobile/ prefix.
    let mobile_api = Router::new()
        .route("/auth", post(handlers_mobile::handle_mobile_auth))
        .route("/pair", post(handlers_mobile::handle_pair))
        .route("/status", get(handlers_mobile::handle_mobile_status))
        .route(
            "/instances",
            get(handlers_mobile::handle_mobile_instances)
                .post(handlers_mobile::handle_mobile_create_instance),
        )
        .route(
            "/instances/{id}/status",
            get(handlers_mobile::handle_mobile_instance_status),
        )
        .route("/logout", post(handlers_mobile::handle_mobile_logout))
        .route("/users", get(handlers_mobile::handle_mobile_users))
        .route(
            "/server-info",
            get(handlers_mobile::handle_mobile_server_info),
        )
        .route(
            "/resource-options",
            get(handlers_mobile::handle_resource_options),
        )
        .route(
            "/claw-vpn/status",
            get(handlers_mobile::handle_mobile_claw_vpn_status),
        )
        .merge(claw_store_routes::mobile_nested_routes())
        .with_state(Arc::clone(&state));

    let app = Router::new()
        .route(
            "/health",
            get(health::handle_health).with_state(Arc::clone(&state)),
        )
        .route(
            "/healthz",
            get(health::handle_health).with_state(Arc::clone(&state)),
        )
        .route(
            "/readyz",
            get(health::handle_ready).with_state(Arc::clone(&state)),
        )
        .route("/debugz", get(health::handle_debug))
        .route("/privacy", get(handle_privacy))
        .route(
            "/qr/{image_id}",
            get(handlers_mobile::handle_pair_qr_image).with_state(Arc::clone(&state)),
        )
        .route(
            "/api/v1/auth/login",
            post(auth::handle_login).with_state(Arc::clone(&state)),
        )
        .route(
            "/api/v1/invites/redeem",
            post(handlers_invites::handle_redeem_invite).with_state(Arc::clone(&state)),
        )
        // Server pairing — generates a server-level QR token (admin-authed, uses AdminUser extractor)
        .route(
            "/api/v1/mobile/pair-token",
            post(handlers_mobile::handle_pair_token).with_state(Arc::clone(&state)),
        )
        // Mobile claw install/uninstall/availability — registered directly to
        // avoid axum nest routing conflict with parameterized paths under
        // /api/v1/mobile.
        .merge(claw_store_routes::mobile_direct_routes(Arc::clone(&state)))
        .nest("/api/v1/mobile", mobile_api)
        .nest("/api/v1", api)
        .fallback_service(spa_service)
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB global body limit
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            public_sites::public_site_gateway,
        ))
        .layer(middleware::from_fn(rewrite_spa_404_to_200))
        .layer(middleware::from_fn(set_cache_control))
        .layer(CompressionLayer::new())
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(cfg.addr)
        .await
        .expect("Failed to bind listener");

    info!("Listening on {}", cfg.addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(server_rs::shutdown::shutdown_signal())
        .await
        .expect("Server error");

    server_rs::bonjour_publisher::shutdown_household_bonjour().await;

    // Drain warm-pool VMs before exiting so they don't survive as orphans.
    // Use the Executor's IPC connection to drain the REAL warm pool inside
    // the vmrunner_ipc subprocess (state.vm_runner has an empty pool).
    match state.executor.lock() {
        Ok(exec) => match exec.warm_pool_drain() {
            Ok(v) => {
                let drained = v["drained"].as_u64().unwrap_or(0);
                if drained > 0 {
                    info!("Drained {drained} warm-pool VM(s) before exit");
                }
            }
            Err(e) => tracing::warn!("warm pool drain failed on shutdown: {e}"),
        },
        Err(e) => tracing::warn!("executor lock poisoned on shutdown: {e}"),
    }

    info!("Server shut down gracefully");
}

/// Build `FlowConfig` from environment variables.
/// Resolve the directory where conversation log files live. Env override via
/// `THEYOS_CONVERSATIONS_DIR`; defaults (all user-writable, no root required):
/// - Linux: `$THEYOS_HOME/theyos/.run/conversations` → `$HOME/theyos/.run/conversations` → `/tmp/theyos-conversations`
/// - macOS: `$HOME/Library/Application Support/theyos/conversations` → `/tmp/theyos-conversations`
fn resolve_conv_dir() -> PathBuf {
    if let Ok(v) = std::env::var("THEYOS_CONVERSATIONS_DIR") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return PathBuf::from(home)
                    .join("Library/Application Support/theyos/conversations");
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Prefer the per-user runtime dir used by the systemd service today:
        // $THEYOS_HOME/theyos/.run/… (matches sessions/jobs/ratelimit DB layout).
        if let Ok(theyos_home) = std::env::var("THEYOS_HOME") {
            if !theyos_home.is_empty() {
                return PathBuf::from(theyos_home).join("theyos/.run/conversations");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return PathBuf::from(home).join("theyos/.run/conversations");
            }
        }
    }
    PathBuf::from("/tmp/theyos-conversations")
}

fn flow_config_from_env(sqlite_db: &str) -> FlowConfig {
    use core_rs::env::env_string;

    FlowConfig {
        vmrunner_bin: env_string("THEYOS_VMRUNNER_RS_BIN"),
        store_bin: env_string("THEYOS_STORE_RS_BIN"),
        terminal_bin: env_string("THEYOS_TERMINAL_RS_BIN"),
        firecracker_state_dir: env_string("FIRECRACKER_STATE_DIR"),
        firecracker_bin: env_string("FIRECRACKER_BIN"),
        kernel_image: env_string("FIRECRACKER_KERNEL_IMAGE"),
        base_rootfs: env_string("FIRECRACKER_BASE_ROOTFS"),
        ssh_key: env_string("FIRECRACKER_SSH_KEY"),
        ssh_pubkey: env_string("FIRECRACKER_SSH_PUBKEY"),
        ssh_wait_tries: std::env::var("FIRECRACKER_SSH_WAIT_TRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
        store_db_path: sqlite_db.to_string(),
    }
}

fn mobile_claw_vpn_offer_ttl_secs_from_env() -> u64 {
    std::env::var(MOBILE_CLAW_VPN_OFFER_TTL_SECS_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_MOBILE_CLAW_VPN_OFFER_TTL_SECS)
}
