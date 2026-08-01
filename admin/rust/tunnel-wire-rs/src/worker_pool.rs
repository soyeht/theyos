//! Parked-worker pool over an opaque work item.
//!
//! S0: neutral. Parking, the global connection cap, the backoff policy, the
//! cancellation flag, `Drop`-based teardown and the reconcile algorithm are
//! mechanics — they schedule work and decide nothing about who may do what.
//!
//! # What the boundary forced, and why the seam is one callback
//!
//! Thirteen product symbols crossed out of this module. Two of them —
//! `RelayStreamReverseConnectBinding` and the serve function — mean the pool
//! cannot build a binding and then serve it: it can name neither. So the
//! product's `binding_factory` + `serve` collapse into ONE **attempt callback**,
//! and the router generics `P`/`S`/`I`, which existed only to name the product's
//! binding type, disappear from this signature entirely.
//!
//! # This module reads no clock
//!
//! `AdmissionInstant` samples its monotonic anchor BEFORE the wall seam, and its
//! own docs call reading the wall first "the late-anchor bug" — the shape a
//! `#[cfg(test)]`-only constructor exists to keep out of production. If this
//! module took a `now_unix()` seam of its own, the product's callback would then
//! anchor AFTER that wall read, putting a production path onto exactly that
//! anti-pattern. So the callback captures the admission itself, in the order the
//! pre-extraction worker used, and the resync source reports an unusable clock
//! as `None` rather than handing a time value across.
//!
//! # The item's expiry is not read here
//!
//! The pre-extraction worker checked `not_after <= now` before building. That
//! check moves INTO the callback with the clock, so this module holds no
//! deadline and the item trait needs no accessor for one. The check itself is
//! unchanged and still runs before the attempt.

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::sleep;

/// One unit of parked work, opaque to this module.
///
/// Exactly two members, and the enumeration is why: over the pre-extraction
/// pool's production region the item was read in exactly three places — a
/// hashable key for the reconcile registry, whole-content equality to detect a
/// re-mint at the same key, and a deadline. The deadline moved product-side with
/// the clock, leaving two. `key` cannot yield content equality and content
/// equality cannot yield `key`, so neither is redundant.
///
/// `Key` is opaque: this module uses it only as a `HashMap` key — no field
/// access, no ordering, no serialization, no decision. It cannot name the
/// concrete type, so it cannot reach anything inside it.
pub trait PoolWorkItem: Send + Sync + PartialEq + 'static {
    /// The reconcile identity. Two items with the same key are the same slot of
    /// work; a key that vanishes drains its workers.
    type Key: Eq + Hash + Clone + Send + Sync + 'static;
    fn key(&self) -> Self::Key;
}

/// What one attempt did, as the pool's only view of it.
///
/// Three variants, read off the ten exits of the pre-extraction worker. The
/// three that end the worker — an unusable clock, an expired item, and a factory
/// reporting expiry — are operationally identical (`drop(permit)` then `break`),
/// so they collapse into `Stop` without losing a distinction the loop ever made.
pub enum AttemptOutcome {
    /// The worker is done: stop parking this item.
    Stop,
    /// The attempt ran to a clean finish; reset the failure backoff.
    ResetBackoff,
    /// The attempt failed in a retryable way; sleep the current backoff and grow it.
    Backoff,
}

/// What the product's source can say about the current set of work.
///
/// THREE states, not two. The design for this seam originally specified
/// `Option<Vec<Arc<W>>>` with `None` meaning "drain" — which collapsed two
/// genuinely different pre-extraction behaviours into one. Measured on the
/// pre-extraction driver: an unusable wall clock DRAINED every worker, while a
/// failure to read or verify the product's store logged and returned early,
/// deliberately LEAVING the existing workers running on the last good view.
/// Adopting the two-state seam would have turned a transient read failure into a
/// full drain — a behaviour change inside an extraction whose bar is behaviour
/// identity.
pub enum ResyncView<W> {
    /// The product's current authoritative set. Reconcile against it.
    Items(Vec<Arc<W>>),
    /// A transient failure to read. Change nothing; the existing workers keep
    /// running against the last view they were given.
    Unchanged,
    /// The product cannot judge validity at all. Drain every worker rather than
    /// let them keep dialing on a view nothing can vouch for.
    Drain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    pub min: Duration,
    pub max: Duration,
}

impl BackoffPolicy {
    pub fn new(min: Duration, max: Duration) -> Result<Self, WorkerPoolError> {
        if min.is_zero() {
            return Err(WorkerPoolError::InvalidBackoff);
        }
        if max < min {
            return Err(WorkerPoolError::InvalidBackoff);
        }
        Ok(Self { min, max })
    }

    fn next_after_failure(self, current: Duration) -> Duration {
        let doubled = current.saturating_mul(2);
        doubled.min(self.max).max(self.min)
    }
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            min: Duration::from_millis(100),
            max: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerPoolConfig {
    pub per_item_parked: usize,
    pub max_total_connections: usize,
    pub backoff: BackoffPolicy,
}

impl WorkerPoolConfig {
    pub fn validate(self) -> Result<Self, WorkerPoolError> {
        if self.per_item_parked == 0 {
            return Err(WorkerPoolError::InvalidPerItemParked);
        }
        if self.max_total_connections == 0 {
            return Err(WorkerPoolError::InvalidMaxTotalConnections);
        }
        BackoffPolicy::new(self.backoff.min, self.backoff.max)?;
        Ok(self)
    }
}

impl Default for WorkerPoolConfig {
    fn default() -> Self {
        Self {
            per_item_parked: 1,
            max_total_connections: 16,
            backoff: BackoffPolicy::default(),
        }
    }
}

/// Sizing/validation failures. The variant names and messages are neutral on
/// purpose: an error string is as much a part of the surface as a type name, and
/// "relay stream reverse-connect" / "per-offer" would have carried the product's
/// vocabulary into shared code. Caught by re-reading the moved text rather than
/// by any check — the rename pass covered identifiers, not prose.
#[derive(Debug, thiserror::Error)]
pub enum WorkerPoolError {
    #[error("worker pool per-item parked must be greater than zero")]
    InvalidPerItemParked,

    #[error("worker pool max total connections must be greater than zero")]
    InvalidMaxTotalConnections,

    #[error("worker pool backoff is invalid")]
    InvalidBackoff,
}

/// One parked attempt for one item, supplied by the product.
///
/// Replaces the pre-extraction `binding_factory` **and** the serve call. The
/// product captures its own admission clock, applies its own expiry check, builds
/// whatever it needs and serves it; this module learns only which of three things
/// happened. It is boxed rather than a type parameter so the pool's signature
/// carries no product-shaped generics at all.
pub type ItemAttempt<W> = dyn Fn(Arc<W>) -> AttemptFuture + Send + Sync;

/// The future an [`ItemAttempt`] returns. Boxed for the same reason.
pub type AttemptFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = AttemptOutcome> + Send>>;

pub struct WorkerPoolHandle {
    cancelled: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

impl WorkerPoolHandle {
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

impl fmt::Debug for WorkerPoolHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerPoolHandle")
            .field("task_count", &self.tasks.len())
            .field("cancelled", &self.cancelled.load(Ordering::SeqCst))
            .finish()
    }
}

impl Drop for WorkerPoolHandle {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
        for task in &self.tasks {
            task.abort();
        }
    }
}

// Takes the shared `Arc` handles by value: callers hand the pool ownership of
// one `attempt` handle, which is then `Arc::clone`d per parked worker. The owned
// parameter also lets a concrete `Arc<fn()>` unsize-coerce to `Arc<dyn Fn>` at
// the call site, which an `&Arc` parameter could not.
#[allow(clippy::needless_pass_by_value)]
pub fn spawn_worker_pool<W: PoolWorkItem>(
    config: WorkerPoolConfig,
    items: Vec<Arc<W>>,
    attempt: Arc<ItemAttempt<W>>,
) -> Result<WorkerPoolHandle, WorkerPoolError> {
    let config = config.validate()?;
    let semaphore = Arc::new(Semaphore::new(config.max_total_connections));
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();

    for item in items {
        for _ in 0..config.per_item_parked {
            let item = Arc::clone(&item);
            let attempt = Arc::clone(&attempt);
            let semaphore = Arc::clone(&semaphore);
            let cancelled = Arc::clone(&cancelled);
            let task = tokio::spawn(async move {
                run_item_worker(config, item, attempt, semaphore, cancelled).await;
            });
            tasks.push(task);
        }
    }

    Ok(WorkerPoolHandle { cancelled, tasks })
}

// Internal per-item worker: each `Arc` is moved into the spawned task and owned
// for the worker's lifetime, so the parameters are genuinely consumed rather than
// bundled into a context struct.
async fn run_item_worker<W: PoolWorkItem>(
    config: WorkerPoolConfig,
    item: Arc<W>,
    attempt: Arc<ItemAttempt<W>>,
    semaphore: Arc<Semaphore>,
    cancelled: Arc<AtomicBool>,
) {
    let mut failure_backoff = config.backoff.min;
    loop {
        if cancelled.load(Ordering::SeqCst) {
            break;
        }

        // Acquire the permit FIRST: this await can be long, and anything we
        // read before it could be stale by the time we dial.
        let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
            break;
        };
        if cancelled.load(Ordering::SeqCst) {
            drop(permit);
            break;
        }

        // Everything the pre-extraction worker did between here and the serve
        // call — sample the clock anchor-before-wall, stop on an unusable clock,
        // revalidate expiry against that fresh reading, build, dial, serve —
        // happens inside `attempt`. It has to: this module can name neither the
        // admission clock nor the binding, and giving it a clock seam of its own
        // would push the product's anchor after the wall read.
        let outcome = attempt(Arc::clone(&item)).await;
        // The permit is dropped on every path before any sleep, exactly as each
        // of the pre-extraction worker's exits did.
        drop(permit);

        match outcome {
            AttemptOutcome::Stop => break,
            AttemptOutcome::ResetBackoff => failure_backoff = config.backoff.min,
            AttemptOutcome::Backoff => {
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

// ─── Dynamic item re-sync ─────────────────────────────────────────────────────
//
// The static `spawn_worker_pool` parks workers for a fixed injected item set. A
// live product, however, provisions work AFTER assembly; the re-sync driver
// re-reads the product's source on a tick and reconciles workers so the new work
// is served without a restart.
//
// Reconcile is keyed by the item's own key AND its content: a vanished key
// drains its workers; a key whose CONTENT changed drains the stale workers and
// respawns fresh ones, so no worker stays parked against a superseded item. That
// is why the trait requires `PartialEq` on the whole item rather than a
// product-supplied revision counter — a counter that never changed would leave
// stale workers parked and this module could not detect it.
// All workers share ONE global semaphore, so the connection cap holds across
// churn. Workers reuse `run_item_worker`; per-key teardown aborts that key's
// handles (the held permit is released on drop).

struct WorkerEntry<W> {
    item: Arc<W>,
    handles: Vec<JoinHandle<()>>,
}

struct WorkerRegistry<W: PoolWorkItem> {
    entries: HashMap<W::Key, WorkerEntry<W>>,
}

impl<W: PoolWorkItem> Default for WorkerRegistry<W> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

/// Everything a resync needs to (re)spawn workers, shared by the initial sync
/// resync and the tick loop. Cheaply `Arc`-cloned.
///
/// No `state_dir`, no trust seam and no clock: reading the product's store,
/// verifying its items and judging the wall clock all stay product-side, behind
/// `source`. A `None` from it means the clock is unusable, which drains.
struct ResyncContext<W: PoolWorkItem> {
    config: WorkerPoolConfig,
    source: Arc<dyn Fn() -> ResyncView<W> + Send + Sync>,
    attempt: Arc<ItemAttempt<W>>,
    semaphore: Arc<Semaphore>,
    worker_cancelled: Arc<AtomicBool>,
    registry: Arc<Mutex<WorkerRegistry<W>>>,
    trigger: Arc<Notify>,
}

fn spawn_item_worker<W: PoolWorkItem>(ctx: &ResyncContext<W>, item: Arc<W>) -> JoinHandle<()> {
    let config = ctx.config;
    let attempt = Arc::clone(&ctx.attempt);
    let semaphore = Arc::clone(&ctx.semaphore);
    let cancelled = Arc::clone(&ctx.worker_cancelled);
    tokio::spawn(async move {
        run_item_worker(config, item, attempt, semaphore, cancelled).await;
    })
}

/// Re-read the product's source and reconcile the worker registry. Synchronous:
/// it reads, then spawns/aborts tasks (all sync). The registry mutex is never
/// held across an await.
fn resync_items<W: PoolWorkItem>(ctx: &ResyncContext<W>) {
    // Clock gate for the whole tick, reported by the source rather than judged
    // here. `None` means the product could not establish a usable clock, and
    // without one expiry cannot be enforced — so we must not merely return:
    // existing workers would keep dialing on a stale view. DRAIN them, then let
    // a later tick repopulate the registry.
    //
    // Re-reading through the source every tick is CRITICAL and is the product's
    // contract to honour: work provisioned after assembly is invisible to a
    // source that caches.
    let active = match (ctx.source)() {
        ResyncView::Items(items) => items,
        // Transient: leave the registry exactly as it is. The product already
        // logged whatever failed; workers keep running on their last view.
        ResyncView::Unchanged => return,
        ResyncView::Drain => {
            if let Ok(mut registry) = ctx.registry.lock() {
                for entry in registry.entries.values() {
                    for handle in &entry.handles {
                        handle.abort();
                    }
                }
                registry.entries.clear();
            }
            tracing::warn!(
                stage = "worker_pool.resync.drain",
                "item source cannot vouch for any view; drained workers and skipped resync",
            );
            return;
        }
    };
    let active: HashMap<W::Key, Arc<W>> =
        active.into_iter().map(|item| (item.key(), item)).collect();

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

    for (key, item) in active {
        match registry.entries.get_mut(&key) {
            Some(entry) if entry.item.as_ref() == item.as_ref() => {
                // Same key + same content: reap finished workers and top back up
                // to `per_item_parked` (a worker only exits on expiry/cancel).
                entry.handles.retain(|handle| !handle.is_finished());
                while entry.handles.len() < ctx.config.per_item_parked {
                    entry
                        .handles
                        .push(spawn_item_worker(ctx, Arc::clone(&item)));
                }
            }
            Some(entry) => {
                // Same key, different content: the product superseded this item.
                // Drain the stale workers and respawn so none stays parked
                // against the old one.
                for handle in &entry.handles {
                    handle.abort();
                }
                entry.item = Arc::clone(&item);
                entry.handles = (0..ctx.config.per_item_parked)
                    .map(|_| spawn_item_worker(ctx, Arc::clone(&item)))
                    .collect();
            }
            None => {
                let handles = (0..ctx.config.per_item_parked)
                    .map(|_| spawn_item_worker(ctx, Arc::clone(&item)))
                    .collect();
                registry.entries.insert(
                    key,
                    WorkerEntry {
                        item: Arc::clone(&item),
                        handles,
                    },
                );
            }
        }
    }
}

async fn resync_loop<W: PoolWorkItem>(
    ctx: ResyncContext<W>,
    tick: Duration,
    driver_cancel: Arc<Notify>,
) {
    let trigger = Arc::clone(&ctx.resync_trigger());
    loop {
        tokio::select! {
            // Cancellation wins so no extra resync runs after shutdown.
            biased;
            () = driver_cancel.notified() => break,
            () = sleep(tick) => {}
            () = trigger.notified() => {}
        }
        resync_items(&ctx);
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

impl<W: PoolWorkItem> ResyncContext<W> {
    fn resync_trigger(&self) -> Arc<Notify> {
        Arc::clone(&self.trigger)
    }
}

/// Abortable handle over the item re-sync driver and the workers it manages.
///
/// `shutdown` (and `Drop`) cancel the loop and abort every live worker, so no
/// task outlives the handle. `item_count`/`task_count` report the live registry.
pub struct ItemResyncDriverHandle<W: PoolWorkItem> {
    worker_cancelled: Arc<AtomicBool>,
    registry: Arc<Mutex<WorkerRegistry<W>>>,
    driver_cancel: Arc<Notify>,
    trigger: Arc<Notify>,
    task: JoinHandle<()>,
}

impl<W: PoolWorkItem> ItemResyncDriverHandle<W> {
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
    pub fn item_count(&self) -> usize {
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

impl<W: PoolWorkItem> fmt::Debug for ItemResyncDriverHandle<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Summarized view: the registry, notifiers, and join handle are internal
        // sync primitives that are not meaningfully printable, so they are
        // intentionally omitted in favor of the live counts.
        f.debug_struct("ItemResyncDriverHandle")
            .field("item_count", &self.item_count())
            .field("task_count", &self.task_count())
            .field("cancelled", &self.worker_cancelled.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl<W: PoolWorkItem> Drop for ItemResyncDriverHandle<W> {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn the dynamic item re-sync driver. Performs an initial SYNCHRONOUS resync
/// (so the handle's counts are immediately populated), then re-reads `source` and
/// reconciles workers every `tick`. All workers share one global connection
/// semaphore (`max_total_connections`). Replaces the static pool in a live path:
/// it both seeds the initial items and tracks later ones.
///
/// `source` is the product's: it owns the store, the trust seam and the clock.
/// See [`ResyncView`] for the three answers it can give and why two were not
/// enough.
pub fn spawn_item_resync_driver<W: PoolWorkItem>(
    tick: Duration,
    config: WorkerPoolConfig,
    source: Arc<dyn Fn() -> ResyncView<W> + Send + Sync>,
    attempt: Arc<ItemAttempt<W>>,
) -> Result<ItemResyncDriverHandle<W>, WorkerPoolError> {
    let config = config.validate()?;
    let worker_cancelled = Arc::new(AtomicBool::new(false));
    let registry = Arc::new(Mutex::new(WorkerRegistry::default()));
    let driver_cancel = Arc::new(Notify::new());
    let trigger = Arc::new(Notify::new());

    let ctx = ResyncContext {
        config,
        source,
        attempt,
        semaphore: Arc::new(Semaphore::new(config.max_total_connections)),
        worker_cancelled: Arc::clone(&worker_cancelled),
        registry: Arc::clone(&registry),
        trigger: Arc::clone(&trigger),
    };

    // Initial synchronous resync: seed workers for whatever the source already has.
    resync_items(&ctx);

    let task = tokio::spawn(resync_loop(ctx, tick, Arc::clone(&driver_cancel)));

    Ok(ItemResyncDriverHandle {
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
    use std::sync::atomic::AtomicUsize;

    /// A non-product work item. Its existence is the point: the pool's
    /// mechanics are reusable by something that is not an offer, which was not
    /// true before the extraction.
    #[derive(Debug, PartialEq)]
    struct FixtureItem {
        key: u32,
        revision: u32,
    }

    impl PoolWorkItem for FixtureItem {
        type Key = u32;
        fn key(&self) -> u32 {
            self.key
        }
    }

    fn tiny_config(per_item: usize) -> WorkerPoolConfig {
        WorkerPoolConfig {
            max_total_connections: 4,
            per_item_parked: per_item,
            // A zero `min` is rejected by the validator, so the fixture uses the
            // smallest legal backoff rather than none. The Stop path never
            // sleeps anyway.
            backoff: BackoffPolicy {
                min: Duration::from_nanos(1),
                max: Duration::from_nanos(1),
            },
        }
    }

    /// `Stop` ends the worker: the attempt runs once per parked worker and the
    /// loop does not spin. A counter, not a timer — a passing assertion with a
    /// sleep in it proves much less.
    #[tokio::test]
    async fn stop_ends_the_worker_after_exactly_one_attempt() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let attempt: Arc<ItemAttempt<FixtureItem>> = Arc::new(move |_item| {
            let seen = Arc::clone(&seen);
            Box::pin(async move {
                seen.fetch_add(1, Ordering::SeqCst);
                AttemptOutcome::Stop
            })
        });

        let handle = spawn_worker_pool(
            tiny_config(2),
            vec![Arc::new(FixtureItem {
                key: 1,
                revision: 0,
            })],
            attempt,
        )
        .expect("valid config");
        assert_eq!(handle.task_count(), 2, "one worker per parked slot");
        for _ in 0..50 {
            if calls.load(Ordering::SeqCst) == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "each parked worker attempts once, then Stop ends it"
        );
    }

    /// The config validator rejects what it must. Positive control first so the
    /// negatives cannot pass by rejecting everything.
    #[test]
    fn config_validation_rejects_zero_sizing() {
        assert!(tiny_config(1).validate().is_ok(), "positive control");
        assert!(tiny_config(0).validate().is_err());
        let mut zero_conns = tiny_config(1);
        zero_conns.max_total_connections = 0;
        assert!(zero_conns.validate().is_err());
    }

    /// Content equality, not just key equality, decides a respawn. This is the
    /// property that stops a worker staying parked against a superseded item,
    /// and it is why the trait requires `PartialEq` on the whole item rather
    /// than trusting a product-supplied revision number.
    #[test]
    fn same_key_different_content_is_not_equal() {
        let a = FixtureItem {
            key: 7,
            revision: 1,
        };
        let b = FixtureItem {
            key: 7,
            revision: 2,
        };
        assert_eq!(a.key(), b.key(), "same reconcile key");
        assert_ne!(a, b, "different content must compare unequal");
    }
}
