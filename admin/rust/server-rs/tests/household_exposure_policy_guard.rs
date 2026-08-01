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

fn repo_dir() -> PathBuf {
    crate_dir().join("../../..")
}

fn src_dir() -> PathBuf {
    crate_dir().join("src")
}

fn read_src(file: &str) -> String {
    fs::read_to_string(src_dir().join(file)).unwrap_or_else(|e| panic!("read src/{file}: {e}"))
}

fn read_repo(file: &str) -> String {
    fs::read_to_string(repo_dir().join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"))
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
        sync_body.contains("HouseholdExposurePolicy::allowed_targets"),
        "listener target sync must filter enumerate_bind_targets() through HouseholdExposurePolicy"
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
        household_publish_body.contains("HouseholdExposurePolicy::bonjour_targets"),
        "household Bonjour publisher must filter targets through the Bonjour exposure policy"
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
        setup_publish_body.contains("HouseholdExposurePolicy::bonjour_targets"),
        "setup beacon publisher must filter targets through the Bonjour exposure policy"
    );
    let setup_refresh_body = slice_between(
        &setup_source,
        "async fn sync_bound_targets",
        "\n/// Publish `_soyeht-setup._tcp.`",
    );
    assert!(
        setup_refresh_body.contains("HouseholdExposurePolicy::bonjour_targets"),
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
fn ready_posture_doc_matches_plain_http_listener_contract() {
    let doc = read_repo("docs/household-bind-posture.md");
    for term in [
        "HTTP plaintext",
        "no TLS/rustls",
        "Ready invariant is loopback + Tailnet + verified Mesh",
        "`THEYOS_MESH_SUBNET` is only a validated input",
        "verified Mesh-interface ownership fact",
        "must not advertise Mesh addresses through LAN mDNS",
        "literal `ready`",
        "before PoP, minting, or token consumption",
        "LAN is only",
        "for onboarding and pre-household discovery",
        "Wildcard binds remain prohibited",
        "operator-network boundary",
        "`GET /bootstrap/status`, `GET /health`, `GET /healthz`",
        "`POST /api/v1/household/reachability/echo`",
        "proves byte reachability only",
        "No auth by contract",
        "Soyeht-PoP plus the declared `Operation::Claws*` caveat",
        "single-use header token",
    ] {
        assert!(
            doc.contains(term),
            "household bind posture doc must describe `{term}`"
        );
    }

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
        "household listener must keep plaintext TCP behind the Phase 0 HTTP serve choke-point, or update docs/tests with the transport migration"
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
