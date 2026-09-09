//! Per-connection M2 binding for Product A `relay_stream` reverse connect.
//!
//! C4d. [`bind_relay_stream_reverse_connect`] is the single-source constructor
//! that ties one offer to one target router and one slot store, closing the M2
//! confused-deputy gap:
//!   * the same offer drives the Noise handshake (`binding.offer`) and the
//!     `RelayStreamOfferTargetRouter` inside `binding.deps`;
//!   * the router and the data-tunnel deps share the same
//!     `Arc<ClawShareSlotStore>`, so revocation observed by one is observed by
//!     the other;
//!   * the router carries the same pre-admitted `trust` seam the handshake uses.
//!
//! There is no API that accepts a separate handshake-offer and router-offer.
//! This is NOT the pool: no multiplicity, sizing, eviction, or backoff (C4e),
//! and no live wiring.

use std::fmt;
use std::sync::Arc;

use household_rs::claw_share::ClawShareSlotStore;
use household_rs::claw_share::data_tunnel::{ClawTargetRouter, ReplayGuard};
use household_rs::ids::HouseholdId;

use crate::claw_share_relay_stream_contract::RelayStreamOfferContract;
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;
use crate::claw_share_relay_stream_reopen_limiter::ReopenStreamLimiter;
use crate::claw_share_relay_stream_responder::ResponderDataTunnelDeps;
#[cfg(any(test, feature = "dev_t1_datapath"))]
use crate::claw_share_relay_stream_target_router::RelayStreamIpTunnelRouter;
use crate::claw_share_relay_stream_target_router::{
    RelayStreamIpTunnelUnavailableRouter, RelayStreamOfferTargetRouter,
};

/// One offer bound to its target router and data-tunnel deps for a single
/// reverse-connect attempt.
///
/// `offer` is the source of truth: the handshake uses `offer`, and the router
/// inside `deps` was built from the same offer + the same `trust` seam + the
/// same slot store, so the two cannot diverge.
pub struct RelayStreamReverseConnectBinding<P, S, I = RelayStreamIpTunnelUnavailableRouter> {
    pub offer: Arc<RelayStreamOfferContract>,
    pub trust: RelayStreamIssuerTrust,
    pub deps: ResponderDataTunnelDeps<RelayStreamOfferTargetRouter<P, S, I>>,
}

impl<P, S, I> fmt::Debug for RelayStreamReverseConnectBinding<P, S, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamReverseConnectBinding")
            .field("offer", &"redacted")
            .field("trust", &self.trust)
            .field("deps", &self.deps)
            .finish()
    }
}

/// Bind one offer to a fresh target router + data-tunnel deps.
///
/// Takes the offer and the slot store ONCE so the handshake offer, the router's
/// offer, and the router/deps slot store cannot diverge. The router is built
/// from `(*offer).clone()` and `trust.clone()`, and both the router and the
/// deps hold `Arc::clone(&slots)` — the same store.
// `slots` is taken by value on purpose: the constructor's contract is to own the
// single slot-store handle once (see doc above) and fan it out internally, so it
// is not reduced to `&Arc` here.
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn bind_relay_stream_reverse_connect<P, S>(
    offer: Arc<RelayStreamOfferContract>,
    trust: RelayStreamIssuerTrust,
    household_id: HouseholdId,
    slots: Arc<ClawShareSlotStore>,
    replay: Arc<ReplayGuard>,
    pty_router: P,
    clawsite_router: S,
    reopen_limiter: Arc<ReopenStreamLimiter>,
    now_unix: impl Fn() -> Option<u64> + Send + Sync + 'static,
) -> RelayStreamReverseConnectBinding<P, S>
where
    P: ClawTargetRouter,
    S: ClawTargetRouter,
{
    let router = RelayStreamOfferTargetRouter::new(
        (*offer).clone(),
        trust.clone(),
        Arc::clone(&slots),
        pty_router,
        clawsite_router,
        now_unix,
    );
    let deps = ResponderDataTunnelDeps::new(
        household_id,
        Arc::clone(&slots),
        replay,
        router,
        reopen_limiter,
    );
    RelayStreamReverseConnectBinding { offer, trust, deps }
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn bind_relay_stream_reverse_connect_with_ip_tunnel_router<P, S, I>(
    offer: Arc<RelayStreamOfferContract>,
    trust: RelayStreamIssuerTrust,
    household_id: HouseholdId,
    slots: Arc<ClawShareSlotStore>,
    replay: Arc<ReplayGuard>,
    pty_router: P,
    clawsite_router: S,
    ip_tunnel_router: I,
    reopen_limiter: Arc<ReopenStreamLimiter>,
    now_unix: impl Fn() -> Option<u64> + Send + Sync + 'static,
) -> RelayStreamReverseConnectBinding<P, S, I>
where
    P: ClawTargetRouter,
    S: ClawTargetRouter,
    I: RelayStreamIpTunnelRouter,
{
    let router = RelayStreamOfferTargetRouter::new_with_ip_tunnel_router(
        (*offer).clone(),
        trust.clone(),
        Arc::clone(&slots),
        pty_router,
        clawsite_router,
        ip_tunnel_router,
        now_unix,
    );
    let deps = ResponderDataTunnelDeps::new(
        household_id,
        Arc::clone(&slots),
        replay,
        router,
        reopen_limiter,
    );
    RelayStreamReverseConnectBinding { offer, trust, deps }
}

#[cfg(test)]
mod tests;
