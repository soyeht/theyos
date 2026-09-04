//! S1-A transport exposure guard.
//!
//! These source-level checks pin the architectural boundary: bind/listener
//! reconciliation and Bonjour publishing must consume `HouseholdExposurePolicy`
//! instead of re-creating listener-vs-advertisement rules locally.

use std::fs;
use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn src_dir() -> PathBuf {
    crate_dir().join("src")
}

/// Every `.rs` file under `src/`, recursively. The exposure claims are about
/// the crate, not about whichever files a change happened to open.
fn rust_sources_under_src() -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => panic!("read_dir {}: {e}", dir.display()),
        };
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&src_dir(), &mut out);
    out.sort();
    assert!(out.len() > 20, "src/ walk found only {} files", out.len());
    out
}

fn read_src(file: &str) -> String {
    fs::read_to_string(src_dir().join(file)).unwrap_or_else(|e| panic!("read src/{file}: {e}"))
}

fn slice_between<'a>(source: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let start = source
        .find(start_marker)
        .unwrap_or_else(|| panic!("start marker `{start_marker}` not found"));
    let rest = &source[start..];
    let end = rest
        .find(end_marker)
        .map_or(source.len(), |offset| start + offset);
    &source[start..end]
}

#[test]
fn household_listener_filters_binds_through_exposure_policy() {
    let source = read_src("household_listener.rs");
    let sync_body = slice_between(
        &source,
        "async fn sync_interface_targets",
        "\nasync fn sync_exposure_policy",
    );
    assert!(
        sync_body.contains("HouseholdExposurePolicy::allowed_targets_with"),
        "listener target sync must filter enumerate_bind_targets() through HouseholdExposurePolicy"
    );
    assert!(
        sync_body.contains("pairing_window,"),
        "listener target sync must pass the pair-device window position it was given, \
         not re-derive one: the policy is pure and the window is the caller's fact"
    );

    let spawn_body = slice_between(
        &source,
        "pub async fn spawn_household_listeners",
        "\n/// Periodic refresh task",
    );
    assert!(
        spawn_body.contains("sync_interface_targets"),
        "initial listener bind must route through the policy-aware sync helper"
    );
}

#[test]
fn bonjour_publishers_filter_targets_through_exposure_policy() {
    let household_source = read_src("bonjour_publisher.rs");
    let household_publish_body = slice_between(
        &household_source,
        "pub async fn publish_household_bonjour",
        "\n    // Spawn a task",
    );
    assert!(
        household_publish_body.contains("HouseholdExposurePolicy::bonjour_targets_with"),
        "household Bonjour publisher must filter targets through the Bonjour exposure policy"
    );
    assert!(
        household_publish_body.contains("PairingWindow::observe(pair_device_window.as_ref())"),
        "the household beacon must advertise at the same window position the listener \
         bound at, or a Ready household binds a LAN address it never announces"
    );

    let candidate_publish_body = slice_between(
        &household_source,
        "pub async fn publish_candidate_joiner_bonjour",
        "\nimpl HouseholdBonjour",
    );
    assert!(
        candidate_publish_body.contains("is_bonjour_advertisable"),
        "candidate Bonjour publisher must omit non-advertisable interface classes"
    );

    let setup_source = read_src("setup_beacon.rs");
    let setup_publish_body = slice_between(
        &setup_source,
        "fn publish_targets",
        "\nfn unregister_fullnames",
    );
    assert!(
        setup_publish_body.contains("HouseholdExposurePolicy::bonjour_targets_with"),
        "setup beacon publisher must filter targets through the Bonjour exposure policy"
    );
    let setup_refresh_body = slice_between(
        &setup_source,
        "async fn sync_bound_targets",
        "\n/// Publish `_soyeht-setup._tcp.`",
    );
    assert!(
        setup_refresh_body.contains("HouseholdExposurePolicy::bonjour_targets_with"),
        "setup beacon refresh must keep non-advertisable classes withdrawn"
    );
}

#[test]
fn post_trust_household_peer_gate_is_shared_by_terminal_and_owner_site_routes() {
    let claws_source = read_src("handlers_household_claws.rs");
    assert!(
        claws_source.contains("crate::household_listener::post_trust_household_peer_gate"),
        "peer-sensitive household routes must share the opt-in mesh peer gate"
    );
    for route_gate in [
        "terminal_attach_peer_rejection(peer_addr(peer), \"mint_attach_token\").await",
        "terminal_attach_peer_rejection(peer_addr(peer), \"terminal_pty\").await",
        "owner_site_pre_effect_peer_rejection(peer_addr(peer)).await",
        "owner_site_ake_peer_rejection(peer_addr(peer)).await",
    ] {
        assert!(
            claws_source.contains(route_gate),
            "each mesh-sensitive household route must use the shared peer gate: {route_gate}"
        );
    }

    let mint_handler = slice_between(
        &claws_source,
        "pub async fn handle_household_mint_attach_token",
        "\n/// Upgrades a household terminal WebSocket",
    );
    assert!(
        mint_handler
            .find("terminal_attach_peer_rejection")
            .expect("mint handler must call the shared peer gate")
            < mint_handler
                .find("let authorized")
                .expect("mint handler must retain its PoP authorization"),
        "mint must reject the peer before PoP authorization or attach-token effects"
    );

    let pty_handler = slice_between(
        &claws_source,
        "pub async fn handle_household_terminal_pty",
        "\n/// `PoP`-gates stopping a household-scoped instance",
    );
    assert!(
        pty_handler
            .find("terminal_attach_peer_rejection")
            .expect("PTY handler must call the shared peer gate")
            < pty_handler
                .rfind("household_terminal_pty")
                .expect("PTY handler must retain attach-token redemption"),
        "PTY must reject the peer before attach-token redemption"
    );

    let owner_site_handler = slice_between(
        &claws_source,
        "pub(crate) async fn handle_household_owner_site_preflight",
        "\n/// Upgrades the one-WebSocket owner-site A2 M1/M2/M3 handshake and S2/C3 record confirmation.",
    );
    assert!(
        owner_site_handler
            .find("owner_site_pre_effect_peer_rejection")
            .expect("owner-site pre-effect route must call the shared peer gate")
            < owner_site_handler
                .find("let Some(Extension(store))")
                .expect("owner-site pre-effect route must retain fail-closed provider extraction"),
        "owner-site pre-effect route must reject a peer before provider/admission work"
    );

    let owner_site_ake_handler = slice_between(
        &claws_source,
        "pub(crate) async fn handle_household_owner_site_ake",
        "\n/// `PoP`-gates listing instances",
    );
    assert!(
        owner_site_ake_handler
            .find("owner_site_ake_peer_rejection")
            .expect("owner-site A2 route must call the shared peer gate")
            < owner_site_ake_handler
                .find("let Some(Extension(provider))")
                .expect("owner-site A2 route must retain fail-closed provider extraction"),
        "owner-site A2 route must reject a peer before provider work"
    );
    assert!(
        owner_site_ake_handler
            .find("provider.admits_resource(&resource)")
            .expect("A2 typed provider admission must exist")
            < owner_site_ake_handler
                .find(".on_upgrade")
                .expect("A2 must use one WebSocket upgrade"),
        "owner-site A2 must check the typed provider before upgrading the socket"
    );

    let listener = read_src("household_listener.rs");
    let production_gate = slice_between(
        &listener,
        "pub(crate) async fn is_post_trust_household_peer_allowed",
        "\n/// Apply the shared Ready-state source policy",
    );
    for required in [
        "crate::household_bootstrap::global_bootstrap_state()",
        "bootstrap.read().await",
        "BootstrapState::Uninitialized",
    ] {
        assert!(
            production_gate.contains(required),
            "production terminal peer gate must consume the live exposure state: {required}"
        );
    }
    let classified_peer_gate = slice_between(
        &listener,
        "fn is_post_trust_household_peer_allowed_with_context",
        "\nfn is_lan",
    );
    assert!(
        classified_peer_gate.contains("HouseholdExposurePolicy::allows_terminal_attach_peer"),
        "the live terminal peer state must be evaluated by the shared exposure policy"
    );
    assert!(
        listener.contains("InterfaceClass::Mesh => state == BootstrapState::Ready"),
        "the shared policy must require Ready before a verified Mesh peer can pass"
    );
    assert!(
        classified_peer_gate.contains("context.mesh.allows_remote_mesh_peer(ip)"),
        "the shared policy must require the typed local VerifiedMesh decision before Mesh admission"
    );
}

#[test]
fn mesh_exposure_requires_typed_configuration_verified_ownership_and_prebind_trace() {
    let listener = read_src("household_listener.rs");
    for term in [
        "enum MeshExposureConfig",
        "enum LocalAddressOwnership",
        "VerifiedMesh",
        "struct HouseholdListenerContext",
        "trait BindAttemptObserver: Send",
        "fn plan_listener_reconciliation",
        "observer.before_bind(*attempt)",
        "MeshExposureInput::from_env()",
        "quarantined_subnet",
        "run_post_trust_household_peer_gate",
    ] {
        assert!(
            listener.contains(term),
            "mesh exposure hardening must retain `{term}`"
        );
    }
    for forbidden in [
        "configured_mesh_subnet",
        "classify_with_mesh_subnet",
        "is_mesh_ip_with_subnet",
        "ipv4_cidr_contains",
    ] {
        assert!(
            !listener.contains(forbidden),
            "raw CIDR helper `{forbidden}` must not regain release authority"
        );
    }
}

#[test]
fn plain_http_listener_contract_is_pinned_in_code() {
    let listener = read_src("household_listener.rs");
    let spawn_body = slice_between(
        &listener,
        "fn spawn_listener_task",
        "\nasync fn bind_allowed_target",
    );
    assert!(
        spawn_body.contains("TcpListener")
            && spawn_body.contains("phase0_axum_serve!")
            && spawn_body.contains("connect_info = SocketAddr"),
        "household listener must keep plaintext TCP behind the Phase 0 HTTP serve choke-point, or update the tests with the transport migration"
    );

    let bootstrap = read_src("handlers_bootstrap.rs");
    let router_body = slice_between(&bootstrap, "pub fn bootstrap_router", "\n}\n\n//");
    assert!(
        router_body.contains(".route(\"/bootstrap/status\", get(get_bootstrap_status))"),
        "bootstrap status route must stay explicit in bootstrap_router"
    );
    assert!(
        router_body.contains("REACHABILITY_ECHO_PATH")
            && router_body.contains("post(post_reachability_echo)")
            && router_body.contains("DefaultBodyLimit::max(REACHABILITY_ECHO_BYTES)"),
        "diagnostic echo must remain explicit, fixed-size, and independently routed"
    );
    let household = read_src("handlers_household.rs");
    for (file, source) in [
        ("handlers_bootstrap.rs", bootstrap.as_str()),
        ("handlers_household.rs", household.as_str()),
    ] {
        assert!(
            source.contains("core_rs::phase0_axum_serve!") && !source.contains("axum::serve("),
            "{file} test listeners must not bypass the Phase 0 HTTP serve choke-point"
        );
    }
    let echo_contract = slice_between(
        &bootstrap,
        "/// `POST /api/v1/household/reachability/echo`",
        "pub async fn post_reachability_echo",
    );
    for required in [
        "proves only that bytes made a round trip",
        "never evidence of machine identity",
        "MUST NOT create a",
        "`LocalAddressOwnership::VerifiedMesh` fact",
    ] {
        assert!(
            echo_contract.contains(required),
            "diagnostic echo contract must retain `{required}`"
        );
    }
    let status_contract = slice_between(
        &bootstrap,
        "/// `GET /bootstrap/status`",
        "pub async fn get_bootstrap_status",
    );
    assert!(
        status_contract.contains("No auth required"),
        "bootstrap/status no-auth posture must stay documented in handlers_bootstrap.rs"
    );
}

/// The pair-device window reaches the setup browser's network filter, and
/// nothing else about when that browser runs.
///
/// MEASURED by reading both consumers of the cache the browser fills:
/// `POST /bootstrap/claim-setup-invitation` returns 409 `already_initialized`
/// unless the engine is `Uninitialized`, and `POST /bootstrap/accept-household`
/// returns 409 unless it is `Uninitialized` or `ReadyForNaming`
/// (`handlers_bootstrap.rs`). So spawning the browser in any other state feeds
/// a cache no route can read -- an earlier revision of this change did exactly
/// that and called it a second gate. The spawn therefore stays keyed to the
/// two onboarding states.
///
/// The half that is real: `BrowserConfig::default()` hard-codes
/// `include_local_network = false`, which drops a LAN-only iPhone beacon as
/// `setup_browser.suppressed reason=non_tailnet`. That flag, and only that
/// flag, follows the exposure rule -- and it follows it by ASKING THE POLICY,
/// `allows_with(state, Lan, window)`, rather than by a second copy of the rule
/// written at the spawn site. Source-level because spawning a real mDNS
/// browser in a test would need the host's multicast, which CI does not have.
#[test]
fn setup_invitation_browser_ties_only_its_network_filter_to_the_exposure_policy() {
    let source = read_src("household_bootstrap.rs");
    let spawn_body = slice_between(
        &source,
        "let pairing_window =\n        household_listener::PairingWindow::observe(pair_device_window.as_ref()).await;",
        "let bootstrap_rt =",
    );

    assert!(
        spawn_body.contains(
            "if matches!(\n        initial_bootstrap_state,\n        \
             BootstrapState::Uninitialized | BootstrapState::ReadyForNaming\n    )"
        ),
        "the spawn must stay keyed to the states whose routes can consume the \
         cache; widening it spawns a browser that feeds nothing"
    );
    assert!(
        spawn_body.contains("household_listener::HouseholdExposurePolicy::allows_with(")
            && spawn_body.contains("household_listener::InterfaceClass::Lan,")
            && spawn_body.contains("include_local_network,"),
        "the browser's network filter must be derived from the one exposure policy, \
         so \"visible on the local network in exactly two situations\" has exactly one \
         implementation"
    );
    assert!(
        !spawn_body.contains("BrowserConfig::default()"),
        "the config must be derived from the policy, not from the default that \
         hard-codes include_local_network = false"
    );
}

/// The environment switch is gone, and did not leave a second way in.
///
/// `THEYOS_HOUSEHOLD_LAN_PAIRING` briefly existed on this branch as an owner
/// opt-in. It was REPLACED by the pair-device window, not kept alongside it:
/// two ways to put a Ready household on the Wi-Fi means the answer to "is it
/// visible right now" depends on which one you read.
///
/// `SOYEHT_SETUP_INVITATION_ALLOW_LAN` is the older ghost -- exported by some
/// Mac launchd plists and read NOWHERE in this repo, so an operator who set it
/// got silence. Neither name may become an environment read again.
#[test]
fn local_network_exposure_has_no_environment_switch() {
    // Every file under src/, not a list of the seven that happened to be
    // touched: the claim is that no environment variable decides local-network
    // exposure anywhere, and a list can only ever prove it about itself.
    for path in rust_sources_under_src() {
        let file = path
            .strip_prefix(src_dir())
            .unwrap_or(&path)
            .display()
            .to_string();
        let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {file}: {e}"));
        assert!(
            !body.contains("THEYOS_HOUSEHOLD_LAN_PAIRING"),
            "src/{file} must not reintroduce the deleted LAN-pairing switch"
        );
        for read in [
            r#"var_os("SOYEHT_SETUP_INVITATION_ALLOW_LAN")"#,
            r#"var("SOYEHT_SETUP_INVITATION_ALLOW_LAN")"#,
        ] {
            assert!(
                !body.contains(read),
                "src/{file} must not revive the dead LaunchAgent variable as a switch"
            );
        }
    }

    // The policy stays pure: no clock, no store, no environment inside the
    // decision. `PairingWindow::observe` is the ONE reader of the live window,
    // and it lives outside `HouseholdExposurePolicy`.
    let listener = read_src("household_listener.rs");
    let policy = slice_between(
        &listener,
        "impl HouseholdExposurePolicy {",
        "\n/// The one Product A IPv4 allocation",
    );
    for forbidden in ["std::env::", "Instant::now", "SystemTime", ".await"] {
        assert!(
            !policy.contains(forbidden),
            "HouseholdExposurePolicy must stay a pure function of \
             (state, class, window); `{forbidden}` makes it answerable only from a \
             running process"
        );
    }
}
