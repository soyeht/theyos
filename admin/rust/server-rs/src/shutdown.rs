//! Process-lifecycle signal handlers: graceful shutdown (SIGINT/SIGTERM) and
//! configuration hot-reload (SIGHUP).
//!
//! On macOS this lets `launchctl kill HUP <service>` trigger a config reread
//! without restarting the daemon.

use crate::config;
use tracing::info;

/// Resolves when SIGINT or SIGTERM arrives. Pass to the Axum server's
/// graceful-shutdown hook to drain in-flight requests.
///
/// # Panics
///
/// Panics if the SIGINT or SIGTERM handler cannot be installed at the
/// kernel level (e.g. running outside any signal-handling context).
/// Both are unrecoverable for a daemon and reflect a misconfigured
/// runtime, not a normal failure mode.
pub async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl-C");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c    => info!("Received SIGINT, shutting down"),
        () = terminate => info!("Received SIGTERM, shutting down"),
    }
}

/// Spawn a background task that listens for SIGHUP and triggers config
/// hot-reload. Unix-only; a no-op on other platforms.
#[cfg(unix)]
pub fn spawn_sighup_handler() {
    use tokio::signal::unix;

    tokio::spawn(async {
        loop {
            match unix::signal(unix::SignalKind::hangup()) {
                Ok(mut stream) => {
                    info!("SIGHUP handler installed, configuration reload enabled");
                    while stream.recv().await.is_some() {
                        info!("Received SIGHUP, reloading configuration...");
                        reload_config();
                        info!("Configuration reloaded successfully");
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to install SIGHUP handler: {}", e);
                    break;
                }
            }
        }
    });
}

#[cfg(not(unix))]
pub fn spawn_sighup_handler() {
    // No-op on non-Unix platforms.
}

/// Re-read configuration from environment variables. Most config is loaded
/// once at startup, so this currently logs the refreshed values for audit
/// without mutating any running state.
fn reload_config() {
    let cfg = config::Config::from_env();
    info!(
        "Configuration reloaded: addr={}, web_dir={:?}",
        cfg.addr, cfg.web_dir
    );
}
