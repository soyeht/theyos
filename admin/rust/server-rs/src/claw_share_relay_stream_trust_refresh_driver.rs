//! Trust refresh driver for Product A `relay_stream` (default-off building block).
//!
//! C5a. A `RelayStreamTrustContextRuntime` (C4b) stops serving once its cached
//! context ages past `max_stale` or refresh has failed past the policy limit.
//! This driver keeps the runtime fresh by calling `refresh_now` on a periodic
//! tick AND on an explicit trigger, so a future consumer's admission gate keeps
//! serving while the household/mesh-log stay reachable.
//!
//! It is a building block: nothing spawns it yet (a future C6 caller will). It
//! never replaces the context nor makes the runtime permissive - it only calls
//! `refresh_now`. The health policy stays entirely in the runtime: a failed
//! refresh keeps the last-good context, and `ensure_healthy`/the failure counter
//! still decide when to stop serving.
//!
//! Out of scope: bootstrap/app-state/env wiring, claim-ack, iOS, guest path,
//! offer store/provider, and any `DirectoryDeviceRemoved` production emitter
//! (the driver only READS the projection through `refresh_now`).

use std::sync::Arc;
use std::time::Duration;

use household_rs::household_mesh_log::MeshLogStore;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::claw_share_relay_stream_trust_context_health::RelayStreamTrustContextRuntime;
use crate::household_state::HouseholdState;

/// How often the driver refreshes the runtime on its own, independent of any
/// trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStreamTrustRefreshConfig {
    pub tick: Duration,
}

impl RelayStreamTrustRefreshConfig {
    #[must_use]
    pub fn new(tick: Duration) -> Self {
        Self { tick }
    }
}

/// Abortable handle over the driver task.
///
/// `shutdown` asks the loop to break at its next select point; `Drop` aborts the
/// task outright. Either way no further refresh runs.
#[derive(Debug)]
pub struct RelayStreamTrustRefreshDriverHandle {
    cancel: Arc<Notify>,
    task: JoinHandle<()>,
}

impl RelayStreamTrustRefreshDriverHandle {
    /// Signal the loop to stop at its next select point. Idempotent.
    pub fn shutdown(&self) {
        self.cancel.notify_one();
    }

    /// Abort the driver task immediately.
    pub fn abort(&self) {
        self.task.abort();
    }
}

impl Drop for RelayStreamTrustRefreshDriverHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Spawn the refresh driver.
///
/// `config.tick` must be strictly shorter than the runtime's `max_stale`, else
/// the context could age out between ticks and the serving gate would flap; that
/// is a stable config error, decided up front, not a runtime decision. The
/// driver borrows the same `HouseholdState` and `MeshLogStore` the runtime was
/// loaded from, so a record/members change and a mesh-log change both fold in
/// through `refresh_now`.
pub fn spawn_relay_stream_trust_refresh_driver(
    runtime: Arc<RelayStreamTrustContextRuntime>,
    household: HouseholdState,
    mesh_log: Arc<MeshLogStore>,
    config: RelayStreamTrustRefreshConfig,
    trigger: Arc<Notify>,
    now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
) -> Result<RelayStreamTrustRefreshDriverHandle, RelayStreamTrustRefreshConfigError> {
    if config.tick.is_zero() {
        return Err(RelayStreamTrustRefreshConfigError::TickZero);
    }
    if config.tick >= runtime.max_stale() {
        return Err(RelayStreamTrustRefreshConfigError::TickNotBelowMaxStale {
            tick_secs: config.tick.as_secs(),
            max_stale_secs: runtime.max_stale().as_secs(),
        });
    }

    let cancel = Arc::new(Notify::new());
    let task = tokio::spawn(refresh_loop(
        runtime,
        household,
        mesh_log,
        config.tick,
        trigger,
        Arc::clone(&cancel),
        now_unix,
    ));
    Ok(RelayStreamTrustRefreshDriverHandle { cancel, task })
}

async fn refresh_loop(
    runtime: Arc<RelayStreamTrustContextRuntime>,
    household: HouseholdState,
    mesh_log: Arc<MeshLogStore>,
    tick: Duration,
    trigger: Arc<Notify>,
    cancel: Arc<Notify>,
    now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
) {
    loop {
        tokio::select! {
            // Cancellation is checked first so a pending tick/trigger cannot
            // sneak in one more refresh after shutdown was requested.
            biased;

            () = cancel.notified() => break,
            () = sleep(tick) => {}
            () = trigger.notified() => {}
        }

        // A clock failure must make the context unhealthy IMMEDIATELY. Merely
        // skipping the refresh would leave the last-good context serving until
        // `max_stale`, i.e. it would look handled while still admitting.
        let Some(now) = now_unix() else {
            runtime.mark_clock_unusable();
            continue;
        };
        // Recovery needs BOTH a plausible reading and a green refresh. Clearing
        // the flag here — before the refresh — would let a failing refresh serve
        // the last-good context again as soon as the clock came back, which is
        // the fail-open this flag exists to prevent.
        match runtime
            .refresh_now(&household, mesh_log.as_ref(), now)
            .await
        {
            Ok(()) => runtime.clear_clock_unusable(),
            Err(error) => {
                // A failed refresh keeps the last-good context; the runtime's health
                // policy alone decides when to stop serving. Never permissive, never
                // fatal to the driver: log a debug-safe reason and keep running.
                tracing::debug!(
                    stage = "claw_share.relay_stream.trust_refresh.failed",
                    error = %error,
                );
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamTrustRefreshConfigError {
    #[error("relay stream trust refresh tick must be non-zero")]
    TickZero,

    #[error(
        "relay stream trust refresh tick {tick_secs}s must be below max_stale {max_stale_secs}s"
    )]
    TickNotBelowMaxStale { tick_secs: u64, max_stale_secs: u64 },
}

#[cfg(test)]
mod tests;
