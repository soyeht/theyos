//! Product side of the `relay_stream` reverse-connect pool.
//!
//! S0 cutover: parking, the global connection cap, the backoff policy, the
//! cancellation flag, `Drop`-based teardown and the reconcile algorithm now live
//! in [`tunnel_wire_rs::worker_pool`]. What remains here is everything that was
//! ever product-specific — the offer store, the trust seam, the admission clock,
//! the expiry check, the binding and the serve call — behind one attempt
//! callback.
//!
//! Critical invariant, unchanged: every attempt builds a fresh binding from a
//! fresh admission (`admit -> bind -> dial -> serve`). No
//! `RelayStreamReverseConnectBinding` is reused across attempts, so the
//! per-admission trust-health gate from C4c remains effective.
//!
//! # Why the callback, and not a factory plus a serve call
//!
//! The neutral pool can name neither `RelayStreamReverseConnectBinding` nor
//! `serve_relay_stream_responder_reverse_connect_binding`, so it cannot build a
//! binding and then serve it. The two collapse into one callback here — which
//! also means the router generics `P`/`S`/`I` never cross the boundary, since
//! they only ever existed to name the binding type.
//!
//! # The admission clock stays on this side, and that is load-bearing
//!
//! [`AdmissionInstant::capture_with`] samples its monotonic anchor BEFORE
//! running the wall seam; its own docs call the reverse "the late-anchor bug",
//! kept out of production by a `#[cfg(test)]`-only constructor. If the neutral
//! pool held a `now_unix()` seam and passed a time value down, this callback
//! would anchor AFTER that wall read — a production path on the test-only
//! anti-pattern. So the capture happens here, first thing, and the pool never
//! sees a clock.
//!
//! The order inside the callback is the pre-extraction worker's, unchanged:
//! capture the admission, revalidate `not_after` against that fresh reading,
//! build the binding, serve it.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use household_rs::claw_share::data_tunnel::ClawTargetRouter;
use tunnel_wire_rs::worker_pool::{
    AttemptOutcome, ItemAttempt, PoolWorkItem, ResyncView, WorkerPoolConfig, WorkerPoolError,
    spawn_item_resync_driver, spawn_worker_pool,
};

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
use crate::claw_share_session_clock::AdmissionInstant;

// Neutral names, re-exported under the spellings this crate already uses. These
// are claw-named paths to neutral symbols, which is the case the S0 guard's
// positive control blesses: the property is reachability, not spelling.
pub use tunnel_wire_rs::worker_pool::{
    BackoffPolicy as RelayStreamReverseConnectBackoffPolicy,
    WorkerPoolConfig as RelayStreamReverseConnectPoolConfig,
    WorkerPoolError as RelayStreamReverseConnectPoolError,
    WorkerPoolHandle as RelayStreamReverseConnectPoolHandle,
};

/// One offer, as a unit of parked work.
///
/// A newtype rather than an impl on `RelayStreamOfferContract` directly: the
/// contract lives in `household-rs` and the trait in `tunnel-wire-rs`, so an
/// impl here would be an orphan. The wrapper is the local type that makes it
/// legal, and it carries no behaviour of its own.
#[derive(PartialEq)]
pub struct RelayStreamOfferItem(pub RelayStreamOfferContract);

impl PoolWorkItem for RelayStreamOfferItem {
    type Key = RelayStreamOfferStoreKey;

    fn key(&self) -> Self::Key {
        RelayStreamOfferStoreKey::new(self.0.payload.slot_id.clone(), self.0.payload.resource)
    }
}

/// The driver handle with its work-item bound. An alias rather than a bare
/// re-export so consumers keep naming one type with no generic argument, exactly
/// as before the extraction.
pub type RelayStreamOfferResyncDriverHandle =
    tunnel_wire_rs::worker_pool::ItemResyncDriverHandle<RelayStreamOfferItem>;

/// The product's name for the neutral handle's item count.
///
/// An extension trait rather than a rename at the call sites: `offer_count`
/// appears inside existing ASSERTIONS, and those are the oracle for behaviour
/// identity across this move. Preserving the spelling keeps them untouched, and
/// it is the honest name here anyway — every work item in this pool is an offer.
pub trait RelayStreamOfferResyncDriverHandleExt {
    fn offer_count(&self) -> usize;
}

impl RelayStreamOfferResyncDriverHandleExt for RelayStreamOfferResyncDriverHandle {
    fn offer_count(&self) -> usize {
        self.item_count()
    }
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

/// Build the attempt callback the neutral pool parks.
///
/// Everything the pre-extraction worker did between acquiring the permit and
/// returning happens in here, in the same order, and reports back as one of
/// three neutral outcomes.
fn offer_attempt<P, S, I>(
    reverse_config: RelayStreamResponderReverseConnectConfig,
    params: Arc<RelayStreamResponderParams>,
    binding_factory: Arc<RelayStreamReverseConnectBindingFactory<P, S, I>>,
    now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
) -> Arc<ItemAttempt<RelayStreamOfferItem>>
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    Arc::new(move |item: Arc<RelayStreamOfferItem>| {
        let reverse_config = reverse_config;
        let params = Arc::clone(&params);
        let binding_factory = Arc::clone(&binding_factory);
        let now_unix = Arc::clone(&now_unix);
        Box::pin(async move {
            // Sample the clock, anchor-before-wall by construction. `None` means
            // the wall clock is unusable, and with a broken clock expiry cannot
            // be enforced — stop rather than dialing fail-open.
            let Some(admission) = AdmissionInstant::capture_with(&*now_unix) else {
                return AttemptOutcome::Stop;
            };
            let now = admission.wall();
            // Revalidate the offer against that fresh reading.
            //
            // BOUND BY `pool_expiry_precheck_runs_before_the_binding_factory`,
            // which asserts the factory is never invoked for an expired offer.
            // That is the property this line carries: expiry is caught BEFORE
            // we build, so a product whose factory forgets expiry still stops.
            //
            // An earlier revision of this comment said nothing in the suite
            // could bite its removal. That was an assertion of an ABSENCE, and
            // it was wrong — the discriminator was already in the harness, since
            // `binding_factory` counts attempts before its own expiry check.
            let offer = Arc::new(item.0.clone());
            if offer.payload.not_after <= now {
                return AttemptOutcome::Stop;
            }

            let binding = match binding_factory(Arc::clone(&offer), now) {
                Ok(binding) => binding,
                Err(RelayStreamReverseConnectBindingBuildError::Expired) => {
                    return AttemptOutcome::Stop;
                }
                Err(RelayStreamReverseConnectBindingBuildError::Unhealthy(_)) => {
                    return AttemptOutcome::Backoff;
                }
            };

            let result = serve_relay_stream_responder_reverse_connect_binding(
                reverse_config,
                &binding,
                &params,
                admission,
            )
            .await;

            match result {
                // A clean finish and a handshake timeout both reset the backoff.
                // Two arms in the pre-extraction worker, merged here because
                // they now share one expression body rather than two assignment
                // statements — the effect is identical and both reasons stay
                // visible.
                Ok(())
                | Err(RelayStreamResponderReverseConnectError::Responder(
                    crate::claw_share_relay_stream_responder::RelayStreamResponderError::HandshakeTimeout,
                )) => AttemptOutcome::ResetBackoff,
                Err(_) => AttemptOutcome::Backoff,
            }
        }) as tunnel_wire_rs::worker_pool::AttemptFuture
    })
}

// Takes the shared `Arc` handles by value: callers hand the pool ownership of
// one `params`/`binding_factory`/`now_unix` handle. The owned `now_unix`
// parameter also lets a concrete `Arc<fn()>` unsize-coerce to `Arc<dyn Fn>` at
// the call site, which an `&Arc` parameter could not.
#[allow(clippy::needless_pass_by_value)]
pub fn spawn_relay_stream_reverse_connect_pool<P, S, I>(
    config: WorkerPoolConfig,
    reverse_config: RelayStreamResponderReverseConnectConfig,
    params: Arc<RelayStreamResponderParams>,
    offers: Vec<Arc<RelayStreamOfferContract>>,
    binding_factory: Arc<RelayStreamReverseConnectBindingFactory<P, S, I>>,
    now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
) -> Result<RelayStreamReverseConnectPoolHandle, WorkerPoolError>
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    let attempt = offer_attempt(reverse_config, params, binding_factory, now_unix);
    let items = offers
        .into_iter()
        .map(|offer| Arc::new(RelayStreamOfferItem((*offer).clone())))
        .collect();
    spawn_worker_pool(config, items, attempt)
}

/// Spawn the dynamic offer re-sync driver.
///
/// The store, the trust seam and the clock stay here: the source closure re-reads
/// from disk every tick and hands the neutral reconcile an opaque item list.
/// `None` means the wall clock is unusable, which drains rather than coasts —
/// the same fail-closed shape the pre-extraction driver had.
///
/// CRITICAL: re-load from disk every tick. The claim path opens its own store,
/// `put_minted` persists and drops it; a load-once in-memory store would never
/// see the claim's write.
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn spawn_relay_stream_offer_resync_driver<P, S, I>(
    state_dir: PathBuf,
    trust: RelayStreamIssuerTrust,
    tick: Duration,
    config: WorkerPoolConfig,
    reverse_config: RelayStreamResponderReverseConnectConfig,
    params: Arc<RelayStreamResponderParams>,
    binding_factory: Arc<RelayStreamReverseConnectBindingFactory<P, S, I>>,
    now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
) -> Result<RelayStreamOfferResyncDriverHandle, WorkerPoolError>
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    let attempt = offer_attempt(
        reverse_config,
        params,
        binding_factory,
        Arc::clone(&now_unix),
    );
    let source: Arc<dyn Fn() -> ResyncView<RelayStreamOfferItem> + Send + Sync> =
        Arc::new(move || {
            // Clock gate: an unusable wall clock cannot judge `not_after`, so
            // existing workers must not keep dialing on a view nothing can
            // vouch for. DRAIN — the one case that does.
            //
            // The stage is logged HERE, product-side, because the extraction
            // moved the drain decision's *effect* to the neutral pool but the
            // product still owns the reason. It was dropped in the first cut
            // while both sibling stages survived, which is what made it a slip
            // rather than a decision: observable telemetry is behaviour, and
            // this slice's bar is behaviour identity. Stage and message are the
            // pre-extraction ones verbatim.
            let Some(now) = (now_unix)() else {
                tracing::warn!(
                    stage = "claw_share.relay_stream.resync.clock_unusable",
                    "wall clock unusable; drained offer workers and skipped resync",
                );
                return ResyncView::Drain;
            };
            let mut store = match RelayStreamOfferStore::load(&state_dir, &trust, now) {
                Ok(store) => store,
                Err(error) => {
                    tracing::warn!(
                        stage = "claw_share.relay_stream.resync.store_load_failed",
                        error = %error,
                    );
                    // NOT a drain. The pre-extraction driver logged and returned
                    // early, leaving workers running on the last good view; a
                    // transient disk error is not a reason to tear down live
                    // connections.
                    return ResyncView::Unchanged;
                }
            };
            let active = match store.list_active(&trust, now) {
                Ok(active) => active,
                Err(error) => {
                    tracing::warn!(
                        stage = "claw_share.relay_stream.resync.list_active_failed",
                        error = %error,
                    );
                    return ResyncView::Unchanged;
                }
            };
            ResyncView::Items(
                active
                    .into_iter()
                    .map(|offer| Arc::new(RelayStreamOfferItem(offer)))
                    .collect(),
            )
        });

    spawn_item_resync_driver(tick, config, source, attempt)
}
#[cfg(test)]
mod tests;
