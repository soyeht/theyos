//! Testable reverse-connect pool for Product A `relay_stream`.
//!
//! C4e building block. This module keeps reverse-connect attempts parked for a
//! caller-injected set of offers. It is not product-wired: no offer discovery,
//! bootstrap, claim ack, iOS, public listener, or app-state refresh loop.
//!
//! Critical invariant: every spawn builds a fresh binding from a fresh admission
//! (`admit -> bind -> dial -> serve`). The pool never reuses a
//! `RelayStreamReverseConnectBinding` across attempts, so the per-admission
//! trust-health gate from C4c remains effective.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use household_rs::claw_share_data_tunnel::ClawTargetRouter;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::claw_share_relay_stream_contract::RelayStreamOfferContract;
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;
use crate::claw_share_relay_stream_offer_store::{RelayStreamOfferStore, RelayStreamOfferStoreKey};
use crate::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
use crate::claw_share_relay_stream_responder_reverse_connect::{
    RelayStreamResponderReverseConnectConfig, RelayStreamResponderReverseConnectError,
    serve_relay_stream_responder_reverse_connect_binding,
};
use crate::claw_share_relay_stream_reverse_connect_binding::RelayStreamReverseConnectBinding;
use crate::claw_share_relay_stream_target_router::{
    RelayStreamIpTunnelUnavailableRouter, RelayStreamOfferTargetRouter,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStreamReverseConnectBackoffPolicy {
    pub min: Duration,
    pub max: Duration,
}

impl RelayStreamReverseConnectBackoffPolicy {
    pub fn new(min: Duration, max: Duration) -> Result<Self, RelayStreamReverseConnectPoolError> {
        if min.is_zero() {
            return Err(RelayStreamReverseConnectPoolError::InvalidBackoff);
        }
        if max < min {
            return Err(RelayStreamReverseConnectPoolError::InvalidBackoff);
        }
        Ok(Self { min, max })
    }

    fn next_after_failure(self, current: Duration) -> Duration {
        let doubled = current.saturating_mul(2);
        doubled.min(self.max).max(self.min)
    }
}

impl Default for RelayStreamReverseConnectBackoffPolicy {
    fn default() -> Self {
        Self {
            min: Duration::from_millis(100),
            max: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStreamReverseConnectPoolConfig {
    pub per_offer_parked: usize,
    pub max_total_connections: usize,
    pub backoff: RelayStreamReverseConnectBackoffPolicy,
}

impl RelayStreamReverseConnectPoolConfig {
    pub fn validate(self) -> Result<Self, RelayStreamReverseConnectPoolError> {
        if self.per_offer_parked == 0 {
            return Err(RelayStreamReverseConnectPoolError::InvalidPerOfferParked);
        }
        if self.max_total_connections == 0 {
            return Err(RelayStreamReverseConnectPoolError::InvalidMaxTotalConnections);
        }
        RelayStreamReverseConnectBackoffPolicy::new(self.backoff.min, self.backoff.max)?;
        Ok(self)
    }
}

impl Default for RelayStreamReverseConnectPoolConfig {
    fn default() -> Self {
        Self {
            per_offer_parked: 1,
            max_total_connections: 16,
            backoff: RelayStreamReverseConnectBackoffPolicy::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamReverseConnectPoolError {
    #[error("relay stream reverse-connect pool per-offer parked must be greater than zero")]
    InvalidPerOfferParked,

    #[error("relay stream reverse-connect pool max total connections must be greater than zero")]
    InvalidMaxTotalConnections,

    #[error("relay stream reverse-connect pool backoff is invalid")]
    InvalidBackoff,
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamReverseConnectBindingBuildError {
    #[error("relay stream reverse-connect offer expired")]
    Expired,

    #[error("relay stream reverse-connect trust unhealthy: {0}")]
    Unhealthy(String),
}

pub type RelayStreamReverseConnectBindingFactory<P, S, I = RelayStreamIpTunnelUnavailableRouter> =
    dyn Fn(
            Arc<RelayStreamOfferContract>,
            u64,
        ) -> Result<
            RelayStreamReverseConnectBinding<P, S, I>,
            RelayStreamReverseConnectBindingBuildError,
        > + Send
        + Sync;

pub struct RelayStreamReverseConnectPoolHandle {
    cancelled: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

impl RelayStreamReverseConnectPoolHandle {
    pub fn shutdown(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        for task in &self.tasks {
            task.abort();
        }
    }

    #[must_use]
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

impl fmt::Debug for RelayStreamReverseConnectPoolHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamReverseConnectPoolHandle")
            .field("task_count", &self.tasks.len())
            .field("cancelled", &self.cancelled.load(Ordering::SeqCst))
            .finish()
    }
}

impl Drop for RelayStreamReverseConnectPoolHandle {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
        for task in &self.tasks {
            task.abort();
        }
    }
}

// Takes the shared `Arc` handles by value: callers hand the pool ownership of
// one `params`/`binding_factory`/`now_unix` handle, which is then `Arc::clone`d
// per parked worker. The owned `now_unix` parameter also lets a concrete
// `Arc<fn()>` unsize-coerce to `Arc<dyn Fn>` at the call site, which an `&Arc`
// parameter could not.
#[allow(clippy::needless_pass_by_value)]
pub fn spawn_relay_stream_reverse_connect_pool<P, S, I>(
    config: RelayStreamReverseConnectPoolConfig,
    reverse_config: RelayStreamResponderReverseConnectConfig,
    params: Arc<RelayStreamResponderParams>,
    offers: Vec<Arc<RelayStreamOfferContract>>,
    binding_factory: Arc<RelayStreamReverseConnectBindingFactory<P, S, I>>,
    now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> Result<RelayStreamReverseConnectPoolHandle, RelayStreamReverseConnectPoolError>
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    let config = config.validate()?;
    let semaphore = Arc::new(Semaphore::new(config.max_total_connections));
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();

    for offer in offers {
        for _ in 0..config.per_offer_parked {
            let offer = Arc::clone(&offer);
            let params = Arc::clone(&params);
            let binding_factory = Arc::clone(&binding_factory);
            let now_unix = Arc::clone(&now_unix);
            let semaphore = Arc::clone(&semaphore);
            let cancelled = Arc::clone(&cancelled);
            let task = tokio::spawn(async move {
                run_offer_worker(
                    config,
                    reverse_config,
                    params,
                    offer,
                    binding_factory,
                    now_unix,
                    semaphore,
                    cancelled,
                )
                .await;
            });
            tasks.push(task);
        }
    }

    Ok(RelayStreamReverseConnectPoolHandle { cancelled, tasks })
}

// Internal per-offer worker: each `Arc` is moved into the spawned task and owned
// for the worker's lifetime, so the parameters are genuinely consumed rather than
// bundled into a context struct.
#[allow(clippy::too_many_arguments)]
async fn run_offer_worker<P, S, I>(
    config: RelayStreamReverseConnectPoolConfig,
    reverse_config: RelayStreamResponderReverseConnectConfig,
    params: Arc<RelayStreamResponderParams>,
    offer: Arc<RelayStreamOfferContract>,
    binding_factory: Arc<RelayStreamReverseConnectBindingFactory<P, S, I>>,
    now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
    semaphore: Arc<Semaphore>,
    cancelled: Arc<AtomicBool>,
) where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    let mut failure_backoff = config.backoff.min;
    loop {
        if cancelled.load(Ordering::SeqCst) {
            break;
        }

        let now = now_unix();
        if offer.payload.not_after <= now {
            break;
        }

        let binding = match binding_factory(Arc::clone(&offer), now) {
            Ok(binding) => binding,
            Err(RelayStreamReverseConnectBindingBuildError::Expired) => break,
            Err(RelayStreamReverseConnectBindingBuildError::Unhealthy(_)) => {
                sleep_backoff(failure_backoff, &cancelled).await;
                failure_backoff = config.backoff.next_after_failure(failure_backoff);
                continue;
            }
        };

        let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
            break;
        };
        if cancelled.load(Ordering::SeqCst) {
            drop(permit);
            break;
        }

        let result = serve_relay_stream_responder_reverse_connect_binding(
            reverse_config,
            &binding,
            &params,
            now,
        )
        .await;
        drop(permit);

        match result {
            Ok(()) => failure_backoff = config.backoff.min,
            Err(RelayStreamResponderReverseConnectError::Responder(
                crate::claw_share_relay_stream_responder::RelayStreamResponderError::HandshakeTimeout,
            )) => {
                failure_backoff = config.backoff.min;
            }
            Err(_) => {
                sleep_backoff(failure_backoff, &cancelled).await;
                failure_backoff = config.backoff.next_after_failure(failure_backoff);
            }
        }
    }
}

async fn sleep_backoff(duration: Duration, cancelled: &AtomicBool) {
    if duration.is_zero() || cancelled.load(Ordering::SeqCst) {
        return;
    }
    tokio::time::sleep(duration).await;
}

// ─── Dynamic offer re-sync ────────────────────────────────────────────────────
//
// The static `spawn_relay_stream_reverse_connect_pool` parks workers for a fixed
// injected offer set. A live engine, however, provisions offers into the store
// at claim time AFTER assembly; the re-sync driver re-reads the store on a tick
// and reconciles workers so those offers are served without a restart.
//
// Reconcile is keyed by `(slot_id, resource)` AND offer content: a vanished or
// expired/revoked key drains its workers; a key whose offer content changed
// (re-mint -> new rendezvous token / not_after / static key) drains the stale
// workers and respawns fresh ones, so no worker stays parked with a stale token.
// All workers share ONE global semaphore, so the connection cap holds across
// churn. Workers reuse `run_offer_worker`; per-key teardown aborts that key's
// handles (the held permit is released on drop).

struct OfferWorkerEntry {
    offer: Arc<RelayStreamOfferContract>,
    handles: Vec<JoinHandle<()>>,
}

#[derive(Default)]
struct OfferWorkerRegistry {
    entries: HashMap<RelayStreamOfferStoreKey, OfferWorkerEntry>,
}

fn offer_store_key(offer: &RelayStreamOfferContract) -> RelayStreamOfferStoreKey {
    RelayStreamOfferStoreKey::new(offer.payload.slot_id.clone(), offer.payload.resource)
}

/// Everything a resync needs to (re)spawn workers, shared by the initial sync
/// resync and the tick loop. Cheaply `Arc`-cloned.
struct ResyncContext<P, S, I> {
    state_dir: PathBuf,
    trust: RelayStreamIssuerTrust,
    config: RelayStreamReverseConnectPoolConfig,
    reverse_config: RelayStreamResponderReverseConnectConfig,
    params: Arc<RelayStreamResponderParams>,
    binding_factory: Arc<RelayStreamReverseConnectBindingFactory<P, S, I>>,
    now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
    semaphore: Arc<Semaphore>,
    worker_cancelled: Arc<AtomicBool>,
    registry: Arc<Mutex<OfferWorkerRegistry>>,
    trigger: Arc<Notify>,
}

fn spawn_offer_worker<P, S, I>(
    ctx: &ResyncContext<P, S, I>,
    offer: Arc<RelayStreamOfferContract>,
) -> JoinHandle<()>
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    let config = ctx.config;
    let reverse_config = ctx.reverse_config;
    let params = Arc::clone(&ctx.params);
    let binding_factory = Arc::clone(&ctx.binding_factory);
    let now_unix = Arc::clone(&ctx.now_unix);
    let semaphore = Arc::clone(&ctx.semaphore);
    let cancelled = Arc::clone(&ctx.worker_cancelled);
    tokio::spawn(async move {
        run_offer_worker(
            config,
            reverse_config,
            params,
            offer,
            binding_factory,
            now_unix,
            semaphore,
            cancelled,
        )
        .await;
    })
}

/// Re-read the store and reconcile the worker registry. Synchronous: it loads,
/// verifies/prunes via `list_active`, then spawns/aborts tasks (all sync). The
/// registry mutex is never held across an await.
fn resync_offers<P, S, I>(ctx: &ResyncContext<P, S, I>)
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    let now = (ctx.now_unix)();
    // CRITICAL: re-load from disk every tick. The claim path opens its own store,
    // `put_minted` persists and drops it; a load-once in-memory store would never
    // see the claim's write.
    let mut store = match RelayStreamOfferStore::load(&ctx.state_dir, &ctx.trust, now) {
        Ok(store) => store,
        Err(error) => {
            tracing::warn!(
                stage = "claw_share.relay_stream.resync.store_load_failed",
                error = %error,
            );
            return;
        }
    };
    let active = match store.list_active(&ctx.trust, now) {
        Ok(active) => active,
        Err(error) => {
            tracing::warn!(
                stage = "claw_share.relay_stream.resync.list_active_failed",
                error = %error,
            );
            return;
        }
    };
    let active: HashMap<RelayStreamOfferStoreKey, Arc<RelayStreamOfferContract>> = active
        .into_iter()
        .map(|offer| (offer_store_key(&offer), Arc::new(offer)))
        .collect();

    let mut registry = match ctx.registry.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };

    // Drain workers for keys that are no longer active (gone / expired / revoked).
    registry.entries.retain(|key, entry| {
        if active.contains_key(key) {
            true
        } else {
            for handle in &entry.handles {
                handle.abort();
            }
            false
        }
    });

    for (key, offer) in active {
        match registry.entries.get_mut(&key) {
            Some(entry) if entry.offer.as_ref() == offer.as_ref() => {
                // Same key + same content: reap finished workers and top back up
                // to `per_offer_parked` (a worker only exits on expiry/cancel).
                entry.handles.retain(|handle| !handle.is_finished());
                while entry.handles.len() < ctx.config.per_offer_parked {
                    entry
                        .handles
                        .push(spawn_offer_worker(ctx, Arc::clone(&offer)));
                }
            }
            Some(entry) => {
                // Same key, different offer: a re-mint/upsert produced a new
                // token/not_after/static key. Drain the stale workers and respawn
                // so none stays parked with a stale rendezvous token.
                for handle in &entry.handles {
                    handle.abort();
                }
                entry.offer = Arc::clone(&offer);
                entry.handles = (0..ctx.config.per_offer_parked)
                    .map(|_| spawn_offer_worker(ctx, Arc::clone(&offer)))
                    .collect();
            }
            None => {
                let handles = (0..ctx.config.per_offer_parked)
                    .map(|_| spawn_offer_worker(ctx, Arc::clone(&offer)))
                    .collect();
                registry.entries.insert(
                    key,
                    OfferWorkerEntry {
                        offer: Arc::clone(&offer),
                        handles,
                    },
                );
            }
        }
    }
}

async fn resync_loop<P, S, I>(
    ctx: ResyncContext<P, S, I>,
    tick: Duration,
    driver_cancel: Arc<Notify>,
) where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    let trigger = Arc::clone(&ctx.resync_trigger());
    loop {
        tokio::select! {
            // Cancellation wins so no extra resync runs after shutdown.
            biased;
            () = driver_cancel.notified() => break,
            () = sleep(tick) => {}
            () = trigger.notified() => {}
        }
        resync_offers(&ctx);
    }
    // Graceful stop: cancel + abort every worker so none outlives the driver.
    ctx.worker_cancelled.store(true, Ordering::SeqCst);
    if let Ok(registry) = ctx.registry.lock() {
        for entry in registry.entries.values() {
            for handle in &entry.handles {
                handle.abort();
            }
        }
    }
}

impl<P, S, I> ResyncContext<P, S, I> {
    fn resync_trigger(&self) -> Arc<Notify> {
        Arc::clone(&self.trigger)
    }
}

/// Abortable handle over the offer re-sync driver and the workers it manages.
///
/// `shutdown` (and `Drop`) cancel the loop and abort every live worker, so no
/// task outlives the handle. `offer_count`/`task_count` report the live registry.
pub struct RelayStreamOfferResyncDriverHandle {
    worker_cancelled: Arc<AtomicBool>,
    registry: Arc<Mutex<OfferWorkerRegistry>>,
    driver_cancel: Arc<Notify>,
    trigger: Arc<Notify>,
    task: JoinHandle<()>,
}

impl RelayStreamOfferResyncDriverHandle {
    fn stop(&self) {
        self.worker_cancelled.store(true, Ordering::SeqCst);
        self.driver_cancel.notify_one();
        if let Ok(registry) = self.registry.lock() {
            for entry in registry.entries.values() {
                for handle in &entry.handles {
                    handle.abort();
                }
            }
        }
        self.task.abort();
    }

    pub fn shutdown(&self) {
        self.stop();
    }

    /// Pulse an immediate resync (e.g. a future claim-time hook); the next tick
    /// would pick the change up regardless.
    pub fn trigger_resync(&self) {
        self.trigger.notify_one();
    }

    #[must_use]
    pub fn offer_count(&self) -> usize {
        self.registry
            .lock()
            .map_or(0, |registry| registry.entries.len())
    }

    #[must_use]
    pub fn task_count(&self) -> usize {
        self.registry.lock().map_or(0, |registry| {
            registry
                .entries
                .values()
                .map(|entry| entry.handles.iter().filter(|h| !h.is_finished()).count())
                .sum()
        })
    }
}

impl fmt::Debug for RelayStreamOfferResyncDriverHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Summarized view: the registry, notifiers, and join handle are internal
        // sync primitives that are not meaningfully printable, so they are
        // intentionally omitted in favor of the live counts.
        f.debug_struct("RelayStreamOfferResyncDriverHandle")
            .field("offer_count", &self.offer_count())
            .field("task_count", &self.task_count())
            .field("cancelled", &self.worker_cancelled.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Drop for RelayStreamOfferResyncDriverHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn the dynamic offer re-sync driver. Performs an initial SYNCHRONOUS
/// resync (so the handle's counts are immediately populated), then re-reads the
/// store and reconciles workers every `tick`. All workers share one global
/// connection semaphore (`max_total_connections`). Replaces the static pool in
/// the live path: it both seeds the initial offers and tracks later ones.
#[allow(clippy::too_many_arguments)]
pub fn spawn_relay_stream_offer_resync_driver<P, S, I>(
    state_dir: PathBuf,
    trust: RelayStreamIssuerTrust,
    tick: Duration,
    config: RelayStreamReverseConnectPoolConfig,
    reverse_config: RelayStreamResponderReverseConnectConfig,
    params: Arc<RelayStreamResponderParams>,
    binding_factory: Arc<RelayStreamReverseConnectBindingFactory<P, S, I>>,
    now_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> Result<RelayStreamOfferResyncDriverHandle, RelayStreamReverseConnectPoolError>
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    let config = config.validate()?;
    let worker_cancelled = Arc::new(AtomicBool::new(false));
    let registry = Arc::new(Mutex::new(OfferWorkerRegistry::default()));
    let driver_cancel = Arc::new(Notify::new());
    let trigger = Arc::new(Notify::new());

    let ctx = ResyncContext {
        state_dir,
        trust,
        config,
        reverse_config,
        params,
        binding_factory,
        now_unix,
        semaphore: Arc::new(Semaphore::new(config.max_total_connections)),
        worker_cancelled: Arc::clone(&worker_cancelled),
        registry: Arc::clone(&registry),
        trigger: Arc::clone(&trigger),
    };

    // Initial synchronous resync: seed workers for the offers already on disk.
    resync_offers(&ctx);

    let task = tokio::spawn(resync_loop(ctx, tick, Arc::clone(&driver_cancel)));

    Ok(RelayStreamOfferResyncDriverHandle {
        worker_cancelled,
        registry,
        driver_cancel,
        trigger,
        task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use household_rs::cbor;
    use household_rs::claw_share::{ClawShareSlotStore, SlotRecord, SlotState};
    use household_rs::claw_share_data_tunnel::{
        HEALTH_PROBE, ReplayGuard, SessionAuthToken, TcpStreamRouter, TunnelAck, TunnelFrame,
        client_authenticate, client_health, client_open_stream, recv_frame, send_frame,
    };
    use household_rs::household_mesh_log::MeshLogStore;
    use household_rs::ids::derive_household_id;
    use household_rs::keys::IdentityKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::{Duration, timeout};

    use crate::claw_share_relay_stream_admission::RelayStreamAdmission;
    use crate::claw_share_relay_stream_contract::{
        RelayStreamClawStaticPublicKey, RelayStreamExpectedPath, RelayStreamOfferPayload,
        RelayStreamResource,
    };
    use crate::claw_share_relay_stream_noise::{
        RelayStreamNoiseFramed, generate_relay_stream_noise_static_keypair,
    };
    use crate::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
    use crate::claw_share_relay_stream_responder_reverse_connect::{
        RelayStreamResponderReverseConnectConfig,
        serve_relay_stream_responder_reverse_connect_binding,
    };
    use crate::claw_share_relay_stream_reverse_connect_binding::bind_relay_stream_reverse_connect;
    use crate::claw_share_relay_stream_test_support::{
        DATA_TUNNEL_CLAW_ID, DATA_TUNNEL_SLOT, data_tunnel_credential,
        data_tunnel_token as support_data_tunnel_token, guest_pub, guest_signer, now_unix,
        owner_pub, owner_signer, relay_stream_admission, relay_stream_household_state,
        rendezvous_token, spawn_ack_target,
    };
    use crate::claw_share_relay_stream_trust_context_health::{
        RelayStreamTrustContextRefreshPolicy, RelayStreamTrustContextRuntime,
    };
    use crate::claw_share_rendezvous_stream_relay::{
        RendezvousHello, RendezvousRole, RendezvousToken,
    };
    use crate::claw_share_rendezvous_stream_relay_listener::{
        RendezvousStreamRelayListenerConfig, serve_rendezvous_stream_relay,
    };

    const TOKEN_AUDIENCE: &str = "relay-stream-pool-test";

    fn pool_config(
        per_offer_parked: usize,
        max_total_connections: usize,
    ) -> RelayStreamReverseConnectPoolConfig {
        RelayStreamReverseConnectPoolConfig {
            per_offer_parked,
            max_total_connections,
            backoff: RelayStreamReverseConnectBackoffPolicy::new(
                Duration::from_millis(25),
                Duration::from_millis(100),
            )
            .unwrap(),
        }
    }

    fn reverse_config(
        relay_addr: std::net::SocketAddr,
    ) -> RelayStreamResponderReverseConnectConfig {
        RelayStreamResponderReverseConnectConfig {
            relay_addr,
            connect_timeout: Duration::from_millis(200),
            hello_timeout: Duration::from_millis(200),
            allow_non_loopback_relay_addr: false,
        }
    }

    fn consumed_slots() -> Arc<ClawShareSlotStore> {
        let store = ClawShareSlotStore::new();
        store
            .insert(SlotRecord {
                slot_id: DATA_TUNNEL_SLOT,
                claw_id: DATA_TUNNEL_CLAW_ID.to_string(),
                expires_at: now_unix() + 86_400,
                state: SlotState::Open,
            })
            .unwrap();
        store
            .consume_atomic(
                &DATA_TUNNEL_SLOT,
                DATA_TUNNEL_CLAW_ID,
                guest_signer().public(),
                now_unix(),
            )
            .unwrap();
        Arc::new(store)
    }

    fn offer_for_resource(
        token_label: u8,
        resource: RelayStreamResource,
        static_pub: RelayStreamClawStaticPublicKey,
        not_after: u64,
    ) -> Arc<RelayStreamOfferContract> {
        let payload = RelayStreamOfferPayload::new(
            rendezvous_token(token_label),
            DATA_TUNNEL_CLAW_ID.to_string(),
            DATA_TUNNEL_SLOT,
            guest_pub(),
            resource,
            RelayStreamExpectedPath::RelayStream,
            "relay-stream://127.0.0.1:49152".to_string(),
            static_pub,
            not_after,
        );
        Arc::new(RelayStreamOfferContract::sign(payload, &owner_signer()).unwrap())
    }

    async fn params_for(
        keypair: crate::claw_share_relay_stream_noise::RelayStreamNoiseStaticKeypair,
        auth_deadline: Duration,
        admission: RelayStreamAdmission,
    ) -> RelayStreamResponderParams {
        RelayStreamResponderParams {
            bind_addr: "127.0.0.1:49152".parse().unwrap(),
            auth_deadline,
            idle_timeout: Duration::from_secs(60),
            admission,
            noise_keypair: keypair,
        }
    }

    fn data_tunnel_token(credential_cbor: &[u8], nonce: &[u8]) -> SessionAuthToken {
        support_data_tunnel_token(TOKEN_AUDIENCE, credential_cbor, nonce)
    }

    async fn spawn_pairing_relay() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RendezvousStreamRelayListenerConfig {
            hello_timeout: Duration::from_secs(1),
            token_ttl: Duration::from_secs(2),
            max_pending: 16,
            max_active_connections: 16,
            reaper_interval: Duration::from_millis(50),
            splice_idle_timeout: Duration::from_secs(5),
            splice_max_lifetime: Duration::from_secs(60),
            abuse: crate::claw_share_relay_stream_abuse::RelayAbuseConfig::default(),
        };
        let handle = serve_rendezvous_stream_relay(listener, config);
        (addr, handle)
    }

    async fn connect_guest_with_hello(
        relay_addr: std::net::SocketAddr,
        token: RendezvousToken,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(relay_addr).await.unwrap();
        stream
            .write_all(&RendezvousHello::new(RendezvousRole::Guest, token).encode())
            .await
            .unwrap();
        stream.flush().await.unwrap();
        stream
    }

    async fn spawn_counting_relay() -> (
        std::net::SocketAddr,
        mpsc::Receiver<RendezvousHello>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel(64);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut header = [0u8; 4];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let token_len = u16::from_be_bytes([header[2], header[3]]) as usize;
                    let mut token = vec![0u8; token_len];
                    if stream.read_exact(&mut token).await.is_err() {
                        return;
                    }
                    let mut bytes = header.to_vec();
                    bytes.extend_from_slice(&token);
                    if let Ok(hello) = RendezvousHello::decode(&bytes) {
                        let _ = tx.send(hello).await;
                    }
                    let mut hold = [0u8; 1];
                    let _ = stream.read(&mut hold).await;
                });
            }
        });
        (addr, rx, handle)
    }

    fn binding_factory(
        admission: RelayStreamAdmission,
        slots: Arc<ClawShareSlotStore>,
        pty_addr: String,
        site_addr: String,
        attempts: Arc<AtomicUsize>,
    ) -> Arc<RelayStreamReverseConnectBindingFactory<TcpStreamRouter, TcpStreamRouter>> {
        Arc::new(move |offer, now| {
            attempts.fetch_add(1, Ordering::SeqCst);
            if offer.payload.not_after <= now {
                return Err(RelayStreamReverseConnectBindingBuildError::Expired);
            }
            let trust = admission.admit(now).map_err(|error| {
                RelayStreamReverseConnectBindingBuildError::Unhealthy(error.to_string())
            })?;
            Ok(bind_relay_stream_reverse_connect(
                offer,
                trust,
                derive_household_id(&owner_pub()),
                Arc::clone(&slots),
                Arc::new(ReplayGuard::new()),
                TcpStreamRouter::new(pty_addr.clone()),
                TcpStreamRouter::new(site_addr.clone()),
                now_unix,
            ))
        })
    }

    #[tokio::test]
    async fn reverse_connect_binding_serves_end_to_end_composition() {
        timeout(Duration::from_secs(5), async {
            let (relay_addr, relay_handle) = spawn_pairing_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB1,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix() + 60,
            );
            let params = params_for(
                keypair,
                Duration::from_secs(2),
                relay_stream_admission().await,
            )
            .await;
            let pty_addr = spawn_ack_target().await;
            let site_addr = "127.0.0.1:1".to_string();
            let trust = params.admission.admit(now_unix()).unwrap();
            let binding = bind_relay_stream_reverse_connect(
                Arc::clone(&offer),
                trust,
                derive_household_id(&owner_pub()),
                consumed_slots(),
                Arc::new(ReplayGuard::new()),
                TcpStreamRouter::new(pty_addr),
                TcpStreamRouter::new(site_addr),
                now_unix,
            );
            let claw = tokio::spawn(async move {
                serve_relay_stream_responder_reverse_connect_binding(
                    reverse_config(relay_addr),
                    &binding,
                    &params,
                    now_unix(),
                )
                .await
            });

            let guest =
                connect_guest_with_hello(relay_addr, offer.payload.rendezvous_token.clone()).await;
            let mut stream = RelayStreamNoiseFramed::initiator_handshake(
                guest,
                &offer,
                &owner_pub(),
                &guest_pub(),
                now_unix(),
            )
            .await
            .unwrap()
            .into_async_stream();
            let cbor = cbor::to_canonical_vec(&data_tunnel_credential()).unwrap();
            assert!(matches!(
                client_authenticate(&mut stream, &cbor, data_tunnel_token(&cbor, b"pool-e2e"))
                    .await
                    .unwrap(),
                TunnelAck::Ok { .. }
            ));
            assert_eq!(
                client_health(&mut stream, HEALTH_PROBE).await.unwrap(),
                HEALTH_PROBE
            );
            client_open_stream(&mut stream).await.unwrap();
            send_frame(&mut stream, &TunnelFrame::Data(b"via-binding".to_vec()))
                .await
                .unwrap();
            assert_eq!(
                recv_frame(&mut stream).await.unwrap(),
                TunnelFrame::Data(b"ACK:via-binding".to_vec())
            );
            send_frame(&mut stream, &TunnelFrame::Close).await.unwrap();
            claw.await.unwrap().unwrap();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pool_parks_k_per_offer_bounded_by_global_cap() {
        timeout(Duration::from_secs(3), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB2,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix() + 60,
            );
            let params = Arc::new(
                params_for(
                    keypair,
                    Duration::from_secs(5),
                    relay_stream_admission().await,
                )
                .await,
            );
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                Arc::clone(&attempts),
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(3, 2),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(now_unix),
            )
            .unwrap();

            let mut count = 0usize;
            while count < 2 {
                let hello = timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(hello.role, RendezvousRole::Claw);
                count += 1;
            }
            assert!(
                timeout(Duration::from_millis(150), rx.recv())
                    .await
                    .is_err()
            );
            assert_eq!(handle.task_count(), 3);
            handle.shutdown();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pool_skips_expired_offer_without_dialing() {
        timeout(Duration::from_secs(2), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB3,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix().saturating_sub(1),
            );
            let params = Arc::new(
                params_for(
                    keypair,
                    Duration::from_millis(100),
                    relay_stream_admission().await,
                )
                .await,
            );
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                attempts,
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(1, 1),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(now_unix),
            )
            .unwrap();

            assert!(
                timeout(Duration::from_millis(150), rx.recv())
                    .await
                    .is_err()
            );
            handle.shutdown();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pool_unhealthy_admission_does_not_dial_and_retries() {
        timeout(Duration::from_secs(2), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB4,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix() + 60,
            );
            let policy =
                RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(1), 1).unwrap();
            let runtime = RelayStreamTrustContextRuntime::load(
                &relay_stream_household_state(),
                &MeshLogStore::new(),
                now_unix().saturating_sub(10_000),
                policy,
            )
            .await
            .unwrap();
            let admission = RelayStreamAdmission::new(Arc::new(runtime));
            let params = Arc::new(params_for(keypair, Duration::from_millis(100), admission).await);
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                Arc::clone(&attempts),
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(1, 1),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(now_unix),
            )
            .unwrap();

            tokio::time::sleep(Duration::from_millis(160)).await;
            assert!(attempts.load(Ordering::SeqCst) >= 1);
            assert!(timeout(Duration::from_millis(50), rx.recv()).await.is_err());
            handle.shutdown();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pool_respawns_after_handshake_timeout() {
        timeout(Duration::from_secs(3), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB5,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix() + 60,
            );
            let params = Arc::new(
                params_for(
                    keypair,
                    Duration::from_millis(75),
                    relay_stream_admission().await,
                )
                .await,
            );
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                attempts,
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(1, 1),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(now_unix),
            )
            .unwrap();

            let first = timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first.role, RendezvousRole::Claw);
            let second = timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(second.role, RendezvousRole::Claw);
            handle.shutdown();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pool_shutdown_stops_new_dials_and_debug_redacts() {
        timeout(Duration::from_secs(2), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB6,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix() + 60,
            );
            let params = Arc::new(
                params_for(
                    keypair,
                    Duration::from_secs(5),
                    relay_stream_admission().await,
                )
                .await,
            );
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                attempts,
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(1, 1),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(now_unix),
            )
            .unwrap();
            let debug = format!("{handle:?}");
            assert!(!debug.contains("private"));
            assert!(!debug.contains("secret"));
            assert!(!debug.contains("token"));
            let _ = timeout(Duration::from_secs(1), rx.recv()).await.unwrap();
            handle.shutdown();
            assert!(
                timeout(Duration::from_millis(200), rx.recv())
                    .await
                    .is_err()
            );
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    mod resync {
        use super::*;

        use std::net::SocketAddr;
        use std::path::Path;

        use crate::claw_share_relay_stream_contract::RelayStreamOfferMintInput;
        use crate::claw_share_relay_stream_offer_store::RelayStreamOfferStore;
        use crate::claw_share_relay_stream_test_support::relay_stream_issuer_trust;

        // Mint + persist an offer for `(DATA_TUNNEL_SLOT, resource)` with a known
        // rendezvous token, like the claim provisioning path does.
        fn seed_offer(
            state_dir: &Path,
            token: RendezvousToken,
            resource: RelayStreamResource,
            not_after: u64,
        ) {
            let trust = relay_stream_issuer_trust();
            let credential = data_tunnel_credential();
            let mut store = RelayStreamOfferStore::load(state_dir, &trust, now_unix()).unwrap();
            store
                .put_minted(
                    RelayStreamOfferMintInput {
                        rendezvous_token: token,
                        credential: &credential,
                        resource,
                        expected_path: RelayStreamExpectedPath::RelayStream,
                        relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
                        claw_static_pub: RelayStreamClawStaticPublicKey::try_new([0x77; 32])
                            .unwrap(),
                        not_after,
                        now_unix: now_unix(),
                    },
                    &owner_signer(),
                    &trust,
                )
                .unwrap();
        }

        fn remove_offer(state_dir: &Path, resource: RelayStreamResource) {
            let trust = relay_stream_issuer_trust();
            let mut store = RelayStreamOfferStore::load(state_dir, &trust, now_unix()).unwrap();
            store.remove(&DATA_TUNNEL_SLOT, resource).unwrap();
        }

        async fn wait_until<F: Fn() -> bool>(predicate: F) {
            for _ in 0..200 {
                if predicate() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("condition not met in time");
        }

        // Drain the relay's Claw hellos until one carries `token`.
        async fn wait_for_hello_token(
            rx: &mut mpsc::Receiver<RendezvousHello>,
            token: &RendezvousToken,
        ) {
            timeout(Duration::from_secs(3), async {
                loop {
                    let hello = rx.recv().await.expect("relay closed");
                    if &hello.token == token {
                        return;
                    }
                }
            })
            .await
            .expect("expected a Claw hello carrying the token");
        }

        async fn start_driver(
            state_dir: &Path,
            relay_addr: SocketAddr,
            tick: Duration,
            config: RelayStreamReverseConnectPoolConfig,
        ) -> RelayStreamOfferResyncDriverHandle {
            let admission = relay_stream_admission().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let params =
                Arc::new(params_for(keypair, Duration::from_millis(200), admission.clone()).await);
            let slots = consumed_slots();
            let pty = spawn_ack_target().await;
            let site = spawn_ack_target().await;
            let factory =
                binding_factory(admission, slots, pty, site, Arc::new(AtomicUsize::new(0)));
            spawn_relay_stream_offer_resync_driver(
                state_dir.to_path_buf(),
                relay_stream_issuer_trust(),
                tick,
                config,
                reverse_config(relay_addr),
                params,
                factory,
                Arc::new(now_unix),
            )
            .unwrap()
        }

        // Counts peak concurrent accepted connections, to assert the global cap.
        async fn spawn_concurrency_relay() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let peak = Arc::new(AtomicUsize::new(0));
            let active = Arc::new(AtomicUsize::new(0));
            let peak_for_loop = Arc::clone(&peak);
            let handle = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    let active = Arc::clone(&active);
                    let peak = Arc::clone(&peak_for_loop);
                    tokio::spawn(async move {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        let mut buf = [0u8; 64];
                        let _ = stream.read(&mut buf).await;
                        let mut hold = [0u8; 1];
                        let _ = stream.read(&mut hold).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            });
            (addr, peak, handle)
        }

        #[tokio::test]
        async fn resync_spawns_worker_for_offer_added_after_start() {
            timeout(Duration::from_secs(5), async {
                let dir = tempfile::tempdir().unwrap();
                let (relay_addr, mut rx, relay) = spawn_counting_relay().await;
                let handle = start_driver(
                    dir.path(),
                    relay_addr,
                    Duration::from_millis(50),
                    pool_config(1, 4),
                )
                .await;
                assert_eq!(handle.offer_count(), 0);

                let token = rendezvous_token(0x42);
                seed_offer(
                    dir.path(),
                    token.clone(),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );

                wait_for_hello_token(&mut rx, &token).await;
                assert_eq!(handle.offer_count(), 1);
                handle.shutdown();
                relay.abort();
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn resync_drains_worker_when_offer_removed() {
            timeout(Duration::from_secs(5), async {
                let dir = tempfile::tempdir().unwrap();
                let (relay_addr, mut rx, relay) = spawn_counting_relay().await;
                seed_offer(
                    dir.path(),
                    rendezvous_token(0x43),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );
                let handle = start_driver(
                    dir.path(),
                    relay_addr,
                    Duration::from_millis(50),
                    pool_config(1, 4),
                )
                .await;
                wait_for_hello_token(&mut rx, &rendezvous_token(0x43)).await;
                assert_eq!(handle.offer_count(), 1);

                remove_offer(dir.path(), RelayStreamResource::Pty);
                wait_until(|| handle.offer_count() == 0).await;
                handle.shutdown();
                relay.abort();
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn resync_respawns_workers_on_offer_content_change() {
            timeout(Duration::from_secs(6), async {
                let dir = tempfile::tempdir().unwrap();
                let (relay_addr, mut rx, relay) = spawn_counting_relay().await;
                seed_offer(
                    dir.path(),
                    rendezvous_token(0x44),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );
                let handle = start_driver(
                    dir.path(),
                    relay_addr,
                    Duration::from_millis(50),
                    pool_config(1, 4),
                )
                .await;
                wait_for_hello_token(&mut rx, &rendezvous_token(0x44)).await;

                // Re-mint the SAME key with a NEW token: the stale worker is drained
                // and a fresh one parks with the new token.
                let new_token = rendezvous_token(0x55);
                seed_offer(
                    dir.path(),
                    new_token.clone(),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );
                wait_for_hello_token(&mut rx, &new_token).await;
                assert_eq!(handle.offer_count(), 1);
                handle.shutdown();
                relay.abort();
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn resync_respects_global_cap_during_churn() {
            timeout(Duration::from_secs(5), async {
                let dir = tempfile::tempdir().unwrap();
                let (relay_addr, peak, relay) = spawn_concurrency_relay().await;
                // Two distinct keys (same slot, Pty + ClawSite), global cap of 1.
                seed_offer(
                    dir.path(),
                    rendezvous_token(0x46),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );
                seed_offer(
                    dir.path(),
                    rendezvous_token(0x47),
                    RelayStreamResource::ClawSite,
                    now_unix() + 600,
                );
                let handle = start_driver(
                    dir.path(),
                    relay_addr,
                    Duration::from_millis(50),
                    pool_config(1, 1),
                )
                .await;

                wait_until(|| handle.offer_count() == 2).await;
                // Let the workers churn (dial / handshake-timeout / retry) for a
                // while; the shared semaphore must keep concurrent dials <= cap.
                tokio::time::sleep(Duration::from_millis(800)).await;
                assert!(
                    peak.load(Ordering::SeqCst) <= 1,
                    "peak concurrent connections {} exceeded cap 1",
                    peak.load(Ordering::SeqCst)
                );
                handle.shutdown();
                relay.abort();
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn resync_shutdown_stops_driver_and_workers() {
            timeout(Duration::from_secs(5), async {
                let dir = tempfile::tempdir().unwrap();
                let (relay_addr, mut rx, relay) = spawn_counting_relay().await;
                seed_offer(
                    dir.path(),
                    rendezvous_token(0x48),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );
                let handle = start_driver(
                    dir.path(),
                    relay_addr,
                    Duration::from_millis(50),
                    pool_config(1, 4),
                )
                .await;
                wait_for_hello_token(&mut rx, &rendezvous_token(0x48)).await;

                handle.shutdown();
                // All workers were aborted: live worker count drops to zero.
                wait_until(|| handle.task_count() == 0).await;
                relay.abort();
            })
            .await
            .unwrap();
        }
    }
}
