//! Background version-cache refresher.
//!
//! Mirrors the Go `startVersionRefresher`: reads the `VERSION` file and checks
//! `git rev-parse HEAD` vs `git rev-parse origin/main` to detect updates.
//! Runs once immediately on startup, then every `interval`.

use crate::state::{SharedState, VersionCache};
use std::time::Duration;
use tokio::process::Command;

/// Spawn a background task that keeps `AppState::ver_cache` up to date.
pub fn start_version_refresher(state: SharedState, interval: Duration) {
    tokio::spawn(async move {
        refresh(&state).await;
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // first tick fires immediately — skip it
        loop {
            ticker.tick().await;
            refresh(&state).await;
        }
    });
}

async fn refresh(state: &SharedState) {
    let version = read_version_file().await;
    let update_available = check_update_available().await;

    let Ok(mut cache) = state.ver_cache.write().map_err(|e| {
        tracing::error!("[version] ver_cache write lock poisoned: {e}");
    }) else {
        return;
    };
    *cache = VersionCache {
        version,
        update_available,
    };
}

async fn read_version_file() -> String {
    tokio::fs::read_to_string("VERSION")
        .await
        .map_or_else(|_| "unknown".to_string(), |s| s.trim().to_string())
}

/// Run `git fetch origin` then compare HEAD vs origin/main.
/// Returns `true` if they differ (update available), `false` on any error.
async fn check_update_available() -> bool {
    let fetch = Command::new("git")
        .args(["fetch", "--quiet", "origin"])
        .output()
        .await;

    if fetch.is_ok_and(|o| o.status.success()) {
        let local = git_rev_parse("HEAD").await;
        let remote = git_rev_parse("origin/main").await;
        matches!((local, remote), (Some(l), Some(r)) if l != r)
    } else {
        false
    }
}

async fn git_rev_parse(rev: &str) -> Option<String> {
    Command::new("git")
        .args(["rev-parse", rev])
        .output()
        .await
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
