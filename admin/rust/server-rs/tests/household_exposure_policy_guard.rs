//! S1-A transport exposure guard.
//!
//! These source-level checks pin the architectural boundary: bind/listener
//! reconciliation and Bonjour publishing must consume `HouseholdExposurePolicy`
//! instead of re-creating LAN-vs-Tailnet rules locally.

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
        household_publish_body.contains("HouseholdExposurePolicy::allowed_targets"),
        "household Bonjour publisher must filter targets through HouseholdExposurePolicy"
    );

    let setup_source = read_src("setup_beacon.rs");
    let setup_publish_body = slice_between(
        &setup_source,
        "fn publish_targets",
        "\nfn unregister_fullnames",
    );
    assert!(
        setup_publish_body.contains("HouseholdExposurePolicy::allowed_targets"),
        "setup beacon publisher must filter targets through HouseholdExposurePolicy"
    );
}

#[test]
fn ready_posture_doc_matches_plain_http_listener_contract() {
    let doc = read_repo("docs/household-bind-posture.md");
    for term in [
        "HTTP plaintext",
        "no TLS/rustls",
        "Ready invariant is loopback + Tailnet only",
        "LAN is only",
        "for onboarding and pre-household discovery",
        "Wildcard binds remain prohibited",
        "operator-network boundary",
        "`GET /bootstrap/status`, `GET /health`, `GET /healthz`",
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
        spawn_body.contains("TcpListener") && spawn_body.contains("axum::serve"),
        "household listener must keep the documented plaintext TcpListener + axum::serve contract, or update docs/tests with the transport migration"
    );

    let bootstrap = read_src("handlers_bootstrap.rs");
    let router_body = slice_between(&bootstrap, "pub fn bootstrap_router", "\n}\n\n//");
    assert!(
        router_body.contains(".route(\"/bootstrap/status\", get(get_bootstrap_status))"),
        "bootstrap status route must stay explicit in bootstrap_router"
    );
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
