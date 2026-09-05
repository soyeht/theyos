//! "Somebody is standing at this Mac with the Add iPhone sheet open."
//!
//! # The half of situation 2 that was missing
//!
//! The owner's rule is that the home is discoverable on the local network in
//! exactly two situations: while the household has not been set up yet, and
//! while an "Add iPhone" window is open (see the module docs on
//! [`crate::household_listener`]). The engine half of the second situation
//! already existed -- `HouseholdExposurePolicy` re-admits
//! `InterfaceClass::Lan` post-onboarding while
//! `household_listener::PairingWindow` is `Open`, and the listener reconciles
//! on the window's broadcast and on a 500 ms tick.
//!
//! MEASURED against the Dev engine on 2026-09-05, and the reason this module
//! exists: on a household that is already set up, the Mac's "Add iPhone" sheet
//! never opened that window. The sheet asks
//! `MacPairingAdvertisement.shared.currentOffer()` -- an offer the MAC mints --
//! and falls back to `GET /bootstrap/pair-device-uri`, which is the FIRST-OWNER
//! route: it answered `404` with `device_count=1`. Nothing engine-side moved,
//! the exposure policy saw `Closed`, and the LAN was never bound. A phone with
//! no Tailscale had no address to dial.
//!
//! # Why this is not a call to `/bootstrap/pair-device/reissue`
//!
//! Because that route MINTS. It creates a new `PairToken`
//! (`handlers_bootstrap::post_pair_device_reissue`) and rejects with `409
//! window_still_open` when one is already open. The Mac has already minted the
//! offer whose six words are on the owner's screen; minting a second one makes
//! the words on the Mac and the words the phone expects disagree. This codebase
//! has lived through that defect once already -- see the "one offer per Mac"
//! comment at `PreferencesDevicesViewController.swift`.
//!
//! So this module separates the two facts that were conflated:
//!
//! - "here is the token" -- minted by whoever owns the ceremony, unchanged.
//! - "I am willing to be seen on the local network right now" -- this module.
//!   It touches no token, no nonce, no household identity and no bootstrap
//!   state. It records one fact with a deadline, and the exposure policy
//!   decides what that fact means.
//!
//! # Contract
//!
//! - `POST /bootstrap/local-network-visibility/open` -- be visible on the LAN
//!   now. Idempotent: opening while open REPLACES the deadline (extends it)
//!   rather than stacking a second grant; there is one slot, so two opens and
//!   one open leave the engine in the same state. Returns the deadline.
//! - `POST /bootstrap/local-network-visibility/close` -- stop being visible.
//!   Explicit, because the sheet closing is a real event: waiting out the TTL
//!   would leave the LAN bound for minutes after the person is done.
//!
//! Both are LOOPBACK-ONLY, the same ACL shape (and the same bare-404 hiding
//! contract) as `POST /bootstrap/pair-machine/local/stage` and `POST
//! /bootstrap/pair-device/reissue`: only a process on this Mac may say the Mac
//! is showing a sheet. A non-loopback peer gets the response a missing route
//! would give, so the endpoint's existence is not advertised across the LAN.
//!
//! # The TTL, and why it is the pair-device TTL
//!
//! [`visibility_ttl`] reads
//! `household_bootstrap::pair_window_ttl_secs_from_env("THEYOS_PAIR_DEVICE_TTL_SECS")`
//! -- default 5 minutes, clamped to 60..=3600. It is deliberately the SAME knob
//! the pair-device window uses, because the two are timing the same human
//! moment: the sheet is showing an offer whose own token expires on that TTL.
//!
//! - Longer than the offer would leave the LAN bound after the thing a phone
//!   could dial for has already expired -- exposure with nothing to gain.
//! - Shorter than the offer would blind the phone mid-ceremony: the words on
//!   screen are still valid, and the address they need stops answering.
//!
//! The caller does not get to choose it. The route ignores its request body,
//! so a Mac cannot ask to be visible for an hour.
//!
//! # How the listener learns
//!
//! - OPEN and explicit CLOSE broadcast on [`LocalNetworkVisibility::subscribe`],
//!   which `household_listener::refresh_loop` selects on, so the bind (or the
//!   withdrawal) is the delay, not a timer.
//! - EXPIRY broadcasts NOTHING. There is no TTL task here on purpose:
//!   [`LocalNetworkVisibility::is_open`] compares the deadline on every read, so
//!   the listener's 500 ms reconciliation tick observes an expired grant as
//!   closed and withdraws the LAN listener. The stated bound for expiry is
//!   therefore one tick, 500 ms -- the same backstop the pair-device window
//!   already relies on for a token whose TTL task lives in another process.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Router, http::StatusCode};
use serde::Serialize;
use tokio::sync::{RwLock, broadcast};
use tracing::{info, warn};

/// Broadcast depth. The payload carries no work, only "something moved", and
/// the listener re-reads the live grant under its own lock afterwards, so a
/// lagged subscriber loses nothing a tick will not recover.
const VISIBILITY_EVENT_CAPACITY: usize = 16;

/// What a [`LocalNetworkVisibility`] broadcast says. Deliberately a
/// notification and not a decision: the position that decides exposure is the
/// one read back through [`LocalNetworkVisibility::is_open`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalNetworkVisibilityState {
    /// The Mac says it is showing an "Add iPhone" sheet.
    Open,
    /// The Mac said the sheet closed.
    Closed,
}

/// One grant. There is at most one, which is what makes opening idempotent.
#[derive(Clone, Copy, Debug)]
struct VisibilityGrant {
    /// Monotonic deadline. `Instant` rather than a unix timestamp so that a
    /// clock step -- NTP, a user changing the date, waking from sleep with a
    /// bad RTC -- cannot extend LAN exposure.
    deadline: Instant,
    /// The same deadline in unix seconds, for the response body only. Never
    /// consulted by [`Self::is_open`].
    expires_at_unix: u64,
}

/// The Mac's "I am showing an Add iPhone sheet" fact, with a deadline.
///
/// Shared as an `Arc` between the two routes below and
/// `household_listener::refresh_loop`. It holds no token and no identity: the
/// whole of its state is one optional deadline.
pub struct LocalNetworkVisibility {
    grant: RwLock<Option<VisibilityGrant>>,
    events: broadcast::Sender<LocalNetworkVisibilityState>,
}

impl Default for LocalNetworkVisibility {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalNetworkVisibility {
    #[must_use]
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(VISIBILITY_EVENT_CAPACITY);
        Self {
            grant: RwLock::new(None),
            events,
        }
    }

    /// Subscribe to open/close notifications, so the listener does not wait
    /// for its next tick.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<LocalNetworkVisibilityState> {
        self.events.subscribe()
    }

    /// Record that the Mac is showing an "Add iPhone" sheet, for `ttl`.
    ///
    /// Idempotent by construction: there is one slot, and this REPLACES what
    /// is in it with `now + ttl`. Two opens and one open leave the same single
    /// deadline, and since `ttl` is a constant the replacement is always the
    /// later of the two -- opening while open extends.
    ///
    /// Returns the deadline in unix seconds for the response body.
    pub async fn open(&self, ttl: Duration) -> u64 {
        let expires_at_unix = crate::time_util::unix_now_secs_checked("local_network_visibility")
            .unwrap_or(0)
            .saturating_add(ttl.as_secs());
        {
            let mut grant = self.grant.write().await;
            *grant = Some(VisibilityGrant {
                deadline: Instant::now() + ttl,
                expires_at_unix,
            });
        }
        // Send after the lock is dropped: the subscriber wakes and immediately
        // reads the grant back, and holding the write lock across the send
        // would make it wait for us.
        let _ = self.events.send(LocalNetworkVisibilityState::Open);
        expires_at_unix
    }

    /// Record that the sheet closed. Idempotent; closing a closed visibility
    /// still notifies, and a redundant reconciliation pass is a no-op.
    pub async fn close(&self) {
        {
            let mut grant = self.grant.write().await;
            *grant = None;
        }
        let _ = self.events.send(LocalNetworkVisibilityState::Closed);
    }

    /// Is the Mac showing a sheet right now?
    ///
    /// Expiry-aware on every read, which is what lets the listener's 500 ms
    /// tick withdraw the LAN listener with no TTL task anywhere. An expired
    /// grant is left in the slot rather than cleared -- this takes a read lock,
    /// and clearing would need a write one for no observable gain, since every
    /// reader compares the deadline.
    pub async fn is_open(&self) -> bool {
        let grant = self.grant.read().await;
        matches!(grant.as_ref(), Some(grant) if Instant::now() < grant.deadline)
    }

    /// The current deadline in unix seconds, or `None` when shut or expired.
    /// Reporting only.
    pub async fn expires_at_unix(&self) -> Option<u64> {
        let grant = self.grant.read().await;
        grant
            .as_ref()
            .filter(|grant| Instant::now() < grant.deadline)
            .map(|grant| grant.expires_at_unix)
    }
}

/// How long one "Add iPhone" sheet buys.
///
/// The pair-device knob, not a knob of its own: the sheet and the offer it
/// shows are timing the same human moment, and two TTLs would let the LAN stay
/// bound after the offer died (or die while the offer is still on screen).
/// Clamped to 60..=3600 by `pair_window_ttl_secs_from_env`, defaulting to
/// 5 minutes.
#[must_use]
pub fn visibility_ttl() -> Duration {
    Duration::from_secs(crate::household_bootstrap::pair_window_ttl_secs_from_env(
        "THEYOS_PAIR_DEVICE_TTL_SECS",
    ))
}

/// Response body of both routes. `expires_at_unix` is absent on close.
#[derive(Serialize)]
struct VisibilityResponse {
    #[serde(rename = "v")]
    version: u8,
    open: bool,
    expires_at_unix: Option<u64>,
}

/// Loopback-only ACL, matching `post_pair_machine_local_stage` and
/// `post_pair_device_reissue`: a non-loopback peer gets the bare `404` a
/// missing route would produce, so the endpoint's shape is not advertised
/// across the LAN.
///
/// Read those two handlers rather than assumed: both compare
/// `peer.ip().is_loopback()` and return `StatusCode::NOT_FOUND.into_response()`
/// with a `warn!` naming the stage. This is the same check, and it is the
/// ONLY gate -- there is deliberately no bootstrap-state gate here, because
/// this route records a fact about the Mac's screen, and
/// `HouseholdExposurePolicy` is the single place that decides what that fact
/// means in each state.
fn loopback_only(peer: SocketAddr, stage: &'static str) -> Option<Response> {
    if peer.ip().is_loopback() {
        return None;
    }
    warn!(stage, peer = %peer, "non-loopback peer rejected");
    Some(StatusCode::NOT_FOUND.into_response())
}

/// `POST /bootstrap/local-network-visibility/open`
///
/// The request body is ignored on purpose: the TTL is engine policy, not a
/// caller's choice.
async fn post_open(
    State(visibility): State<Arc<LocalNetworkVisibility>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    if let Some(rejection) =
        loopback_only(peer, "local_network_visibility.open.non_loopback_rejected")
    {
        return rejection;
    }
    let ttl = visibility_ttl();
    let expires_at_unix = visibility.open(ttl).await;
    info!(
        stage = "local_network_visibility.opened",
        ttl_secs = ttl.as_secs(),
        expires_at_unix,
    );
    crate::handlers_bootstrap::cbor_ok(VisibilityResponse {
        version: 1,
        open: true,
        expires_at_unix: Some(expires_at_unix),
    })
}

/// `POST /bootstrap/local-network-visibility/close`
async fn post_close(
    State(visibility): State<Arc<LocalNetworkVisibility>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    if let Some(rejection) =
        loopback_only(peer, "local_network_visibility.close.non_loopback_rejected")
    {
        return rejection;
    }
    visibility.close().await;
    info!(stage = "local_network_visibility.closed");
    crate::handlers_bootstrap::cbor_ok(VisibilityResponse {
        version: 1,
        open: false,
        expires_at_unix: None,
    })
}

/// The two routes, over the shared visibility handle the listener reads.
///
/// Its own router rather than a pair of routes on `bootstrap_router`: the
/// state this needs is one deadline, and putting it in `BootstrapHandlerState`
/// -- which carries the household identity, the pairing windows and the state
/// dir -- would put "willing to be seen" back next to "here is the token",
/// which is the conflation this module exists to undo.
pub fn local_network_visibility_router(visibility: Arc<LocalNetworkVisibility>) -> Router {
    Router::new()
        .route("/bootstrap/local-network-visibility/open", post(post_open))
        .route(
            "/bootstrap/local-network-visibility/close",
            post(post_close),
        )
        .with_state(visibility)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn request(path: &str, peer: SocketAddr) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .extension(ConnectInfo::<SocketAddr>(peer))
            .body(Body::empty())
            .unwrap()
    }

    fn loopback() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 51234))
    }

    #[derive(serde::Deserialize, Debug)]
    struct VisibilityResponseForTest {
        #[serde(rename = "v")]
        version: u8,
        open: bool,
        expires_at_unix: Option<u64>,
    }

    async fn decode(response: Response) -> VisibilityResponseForTest {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        household_rs::cbor::from_canonical_slice(&bytes).expect("CBOR decode")
    }

    #[tokio::test]
    async fn a_fresh_visibility_is_shut() {
        let visibility = LocalNetworkVisibility::new();
        assert!(!visibility.is_open().await);
        assert_eq!(visibility.expires_at_unix().await, None);
    }

    #[tokio::test]
    async fn open_then_close_moves_the_fact_in_both_directions() {
        let visibility = LocalNetworkVisibility::new();
        visibility.open(Duration::from_secs(300)).await;
        assert!(visibility.is_open().await);
        visibility.close().await;
        assert!(!visibility.is_open().await);
        assert_eq!(visibility.expires_at_unix().await, None);
    }

    /// An expired grant reads shut with nothing having notified anyone -- no
    /// TTL task ran in this test. That is the property the listener's 500 ms
    /// tick stands on.
    #[tokio::test]
    async fn an_expired_grant_reads_shut_without_any_task_running() {
        let visibility = LocalNetworkVisibility::new();
        // Zero TTL: `deadline == Instant::now()` at open, and `is_open` is
        // `now < deadline`.
        visibility.open(Duration::ZERO).await;
        assert!(
            !visibility.is_open().await,
            "a grant whose deadline has passed must not read as open"
        );
        assert_eq!(visibility.expires_at_unix().await, None);
    }

    /// Opening twice extends one deadline instead of stacking two grants, and
    /// -- the half that matters -- ONE close shuts it. A stacking design would
    /// need as many closes as opens, so the sheet closing once would leave the
    /// LAN bound.
    #[tokio::test]
    async fn opening_twice_extends_one_grant_and_one_close_shuts_it() {
        let visibility = LocalNetworkVisibility::new();
        visibility.open(Duration::from_secs(60)).await;
        let first = visibility.expires_at_unix().await.expect("open");
        visibility.open(Duration::from_secs(3600)).await;
        let second = visibility.expires_at_unix().await.expect("still open");
        assert!(
            second >= first,
            "opening while open must extend the deadline, not shorten it"
        );

        visibility.close().await;
        assert!(
            !visibility.is_open().await,
            "one close must shut it however many times it was opened"
        );
    }

    #[tokio::test]
    async fn opening_broadcasts_so_the_listener_does_not_wait_for_a_tick() {
        let visibility = LocalNetworkVisibility::new();
        let mut events = visibility.subscribe();
        visibility.open(Duration::from_secs(300)).await;
        assert_eq!(
            events.recv().await.expect("open event"),
            LocalNetworkVisibilityState::Open
        );
        visibility.close().await;
        assert_eq!(
            events.recv().await.expect("close event"),
            LocalNetworkVisibilityState::Closed
        );
    }

    #[tokio::test]
    async fn the_open_route_is_loopback_only() {
        for peer in [
            SocketAddr::from(([192, 168, 15, 99], 50000)),
            SocketAddr::from(([100, 64, 0, 10], 50000)),
        ] {
            let visibility = Arc::new(LocalNetworkVisibility::new());
            let app = local_network_visibility_router(Arc::clone(&visibility));
            let response = app
                .oneshot(request("/bootstrap/local-network-visibility/open", peer))
                .await
                .unwrap();
            // Bare 404 — the same answer a missing route gives.
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(
                !visibility.is_open().await,
                "a refused peer must not have moved the fact"
            );
        }
    }

    #[tokio::test]
    async fn the_close_route_is_loopback_only() {
        let visibility = Arc::new(LocalNetworkVisibility::new());
        visibility.open(Duration::from_secs(300)).await;
        let app = local_network_visibility_router(Arc::clone(&visibility));
        let response = app
            .oneshot(request(
                "/bootstrap/local-network-visibility/close",
                SocketAddr::from(([192, 168, 15, 99], 50000)),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            visibility.is_open().await,
            "a LAN peer must not be able to shut the owner's window either"
        );
    }

    #[tokio::test]
    async fn loopback_ipv6_is_admitted_too() {
        let visibility = Arc::new(LocalNetworkVisibility::new());
        let app = local_network_visibility_router(Arc::clone(&visibility));
        let response = app
            .oneshot(request(
                "/bootstrap/local-network-visibility/open",
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 51234)),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(visibility.is_open().await);
    }

    #[tokio::test]
    async fn the_routes_open_and_close_the_shared_fact() {
        let visibility = Arc::new(LocalNetworkVisibility::new());

        let app = local_network_visibility_router(Arc::clone(&visibility));
        let opened = app
            .oneshot(request(
                "/bootstrap/local-network-visibility/open",
                loopback(),
            ))
            .await
            .unwrap();
        assert_eq!(opened.status(), StatusCode::OK);
        let body = decode(opened).await;
        assert_eq!(body.version, 1);
        assert!(body.open);
        assert!(body.expires_at_unix.is_some());
        assert!(visibility.is_open().await);

        let app = local_network_visibility_router(Arc::clone(&visibility));
        let closed = app
            .oneshot(request(
                "/bootstrap/local-network-visibility/close",
                loopback(),
            ))
            .await
            .unwrap();
        assert_eq!(closed.status(), StatusCode::OK);
        let body = decode(closed).await;
        assert!(!body.open);
        assert_eq!(body.expires_at_unix, None);
        assert!(!visibility.is_open().await);
    }

    /// The route mints nothing. Stated as a test because it is the whole
    /// reason this module is not a call to `/bootstrap/pair-device/reissue`:
    /// the six words on the Mac's screen belong to an offer the Mac already
    /// minted, and a second mint would make them disagree.
    #[tokio::test]
    async fn opening_visibility_does_not_touch_the_pair_device_window() {
        let window = household_rs::pair_device::PairDeviceWindow::new();
        let token = window
            .mint_token(Duration::from_secs(300), None)
            .await
            .expect("mint the offer the Mac is already showing");

        let visibility = Arc::new(LocalNetworkVisibility::new());
        let app = local_network_visibility_router(Arc::clone(&visibility));
        let response = app
            .oneshot(request(
                "/bootstrap/local-network-visibility/open",
                loopback(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let after = window.current_token().await.expect("window still open");
        assert_eq!(
            after.nonce.0, token.nonce.0,
            "the visibility route must not re-mint the offer on screen"
        );
        assert_eq!(after.expires_at_unix, token.expires_at_unix);
    }

    /// The TTL is the pair-device TTL, and it is not the caller's to pick.
    #[tokio::test]
    async fn the_ttl_is_the_pair_device_window_ttl() {
        assert_eq!(
            visibility_ttl().as_secs(),
            crate::household_bootstrap::pair_window_ttl_secs_from_env(
                "THEYOS_PAIR_DEVICE_TTL_SECS"
            ),
            "one knob times both the sheet and the offer it is showing"
        );
    }
}
