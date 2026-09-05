//! The whole chain, from the Mac's HTTP request to the bind set.
//!
//! The unit tests inside `local_network_visibility` cover the route's ACL and
//! the fact's own semantics, and the ones inside `household_listener` cover the
//! exposure table. Neither of them proves the two are wired together: a route
//! that opened a DIFFERENT `LocalNetworkVisibility` from the one the listener
//! reads would pass both suites and still leave a Ready household invisible,
//! which is exactly the class of bug this branch exists to fix (the Mac's
//! "Add iPhone" sheet was talking to a route that answered 404).
//!
//! So this drives the real router over a real request and then asks the real
//! policy what a Ready household would bind. There is no socket: binding a LAN
//! address in CI would need the host's interfaces, and what is under test is
//! the decision, not `TcpListener`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use household_rs::bootstrap_state::BootstrapState;
use household_rs::pair_device::PairDeviceWindow;
use server_rs::household_listener::{HouseholdExposurePolicy, InterfaceClass, PairingWindow};
use server_rs::local_network_visibility::{
    LocalNetworkVisibility, local_network_visibility_router,
};
use tower::ServiceExt;

const OPEN: &str = "/bootstrap/local-network-visibility/open";
const CLOSE: &str = "/bootstrap/local-network-visibility/close";

fn request(path: &str, peer: SocketAddr) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .extension(ConnectInfo::<SocketAddr>(peer))
        .body(Body::empty())
        .unwrap()
}

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 52001))
}

fn lan_peer() -> SocketAddr {
    SocketAddr::from(([192, 168, 15, 99], 52002))
}

/// One host with one address of every class, so the two positions are compared
/// on identical input.
fn one_target_per_class() -> Vec<(IpAddr, InterfaceClass)> {
    vec![
        (IpAddr::V4(Ipv4Addr::LOCALHOST), InterfaceClass::Loopback),
        ("192.0.2.10".parse().unwrap(), InterfaceClass::Lan),
        ("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale),
        ("10.77.0.10".parse().unwrap(), InterfaceClass::Mesh),
    ]
}

async fn post(
    visibility: &Arc<LocalNetworkVisibility>,
    path: &str,
    peer: SocketAddr,
) -> StatusCode {
    local_network_visibility_router(Arc::clone(visibility))
        .oneshot(request(path, peer))
        .await
        .unwrap()
        .status()
}

/// What a household in `state` would bind right now, asked the same way the
/// listener asks it.
async fn bind_set(
    state: BootstrapState,
    window: &PairDeviceWindow,
    visibility: &LocalNetworkVisibility,
) -> Vec<(IpAddr, InterfaceClass)> {
    let position = PairingWindow::observe(window, visibility).await;
    HouseholdExposurePolicy::allowed_targets_with(state, one_target_per_class(), position)
}

fn binds_lan(targets: &[(IpAddr, InterfaceClass)]) -> bool {
    targets
        .iter()
        .any(|(_, class)| *class == InterfaceClass::Lan)
}

/// The measured gap, end to end: a Ready household with no pair-device token
/// binds no LAN address until the Mac says it is showing an "Add iPhone"
/// sheet, and stops the moment the sheet closes.
#[tokio::test]
async fn the_route_puts_a_ready_household_on_the_wifi_and_takes_it_off_again() {
    let window = PairDeviceWindow::new();
    let visibility = Arc::new(LocalNetworkVisibility::new());

    for state in [
        BootstrapState::Ready,
        BootstrapState::NamedAwaitingPair,
        BootstrapState::Recovering,
    ] {
        assert!(
            !binds_lan(&bind_set(state, &window, &visibility).await),
            "{state:?} must be invisible on the local network before anyone taps Add iPhone"
        );

        assert_eq!(post(&visibility, OPEN, loopback()).await, StatusCode::OK);
        assert!(
            binds_lan(&bind_set(state, &window, &visibility).await),
            "{state:?} must bind the LAN address while the sheet is open"
        );
        assert!(
            window.current_token().await.is_none(),
            "the route must not have minted a pairing token"
        );

        assert_eq!(post(&visibility, CLOSE, loopback()).await, StatusCode::OK);
        assert!(
            !binds_lan(&bind_set(state, &window, &visibility).await),
            "{state:?} must leave the local network when the sheet closes"
        );
    }
}

/// Opening twice does not stack: one close still takes the home off the Wi-Fi.
///
/// A design that counted opens would need as many closes, so a sheet opened
/// twice (re-render, a second window) and closed once would leave a Ready
/// household on the local network with nobody watching.
#[tokio::test]
async fn opening_twice_still_needs_only_one_close() {
    let window = PairDeviceWindow::new();
    let visibility = Arc::new(LocalNetworkVisibility::new());

    assert_eq!(post(&visibility, OPEN, loopback()).await, StatusCode::OK);
    assert_eq!(post(&visibility, OPEN, loopback()).await, StatusCode::OK);
    assert!(binds_lan(
        &bind_set(BootstrapState::Ready, &window, &visibility).await
    ));

    assert_eq!(post(&visibility, CLOSE, loopback()).await, StatusCode::OK);
    assert!(
        !binds_lan(&bind_set(BootstrapState::Ready, &window, &visibility).await),
        "two opens and one close must leave the home invisible"
    );
}

/// Only a process on this Mac may say the Mac is showing a sheet.
///
/// Both directions: a LAN peer cannot put the household on the Wi-Fi, and --
/// the half that is easy to forget -- cannot take it off either, which would
/// be a denial of the owner's own pairing.
#[tokio::test]
async fn a_lan_peer_can_neither_open_nor_close_the_window() {
    let window = PairDeviceWindow::new();
    let visibility = Arc::new(LocalNetworkVisibility::new());

    // Bare 404 — the answer a missing route gives, so the endpoint's shape is
    // not advertised across the LAN.
    assert_eq!(
        post(&visibility, OPEN, lan_peer()).await,
        StatusCode::NOT_FOUND
    );
    assert!(
        !binds_lan(&bind_set(BootstrapState::Ready, &window, &visibility).await),
        "a refused peer must not have widened the bind set"
    );

    assert_eq!(post(&visibility, OPEN, loopback()).await, StatusCode::OK);
    assert_eq!(
        post(&visibility, CLOSE, lan_peer()).await,
        StatusCode::NOT_FOUND
    );
    assert!(
        binds_lan(&bind_set(BootstrapState::Ready, &window, &visibility).await),
        "a LAN peer must not be able to shut the owner's Add iPhone window"
    );
}

/// The install states do not move with this route, in either direction.
///
/// Situation 1 grants LAN on its own, so the sheet cannot widen an install --
/// and, the failure that would actually hurt, it cannot NARROW one either. An
/// interrupted install stays on loopback + Tailnet whatever the route says.
#[tokio::test]
async fn the_install_states_are_unaffected_by_the_route() {
    let window = PairDeviceWindow::new();
    let visibility = Arc::new(LocalNetworkVisibility::new());

    for state in [
        BootstrapState::Uninitialized,
        BootstrapState::ReadyForNaming,
        BootstrapState::PairMachineInstallRestartRequired,
    ] {
        let before = bind_set(state, &window, &visibility).await;
        assert_eq!(post(&visibility, OPEN, loopback()).await, StatusCode::OK);
        let during = bind_set(state, &window, &visibility).await;
        assert_eq!(post(&visibility, CLOSE, loopback()).await, StatusCode::OK);
        let after = bind_set(state, &window, &visibility).await;

        assert_eq!(
            before, during,
            "{state:?} must not move when the sheet opens"
        );
        assert_eq!(
            during, after,
            "{state:?} must not move when the sheet closes"
        );
    }

    // Controls, so the equalities above are not "nothing is ever exposed":
    // the two onboarding states bind LAN throughout, and the interrupted
    // install never does.
    for state in [
        BootstrapState::Uninitialized,
        BootstrapState::ReadyForNaming,
    ] {
        assert!(binds_lan(&bind_set(state, &window, &visibility).await));
    }
    assert!(!binds_lan(
        &bind_set(
            BootstrapState::PairMachineInstallRestartRequired,
            &window,
            &visibility
        )
        .await
    ));
}
