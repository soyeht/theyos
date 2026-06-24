//! S1-A transport exposure guard.
//!
//! These source-level checks pin the architectural boundary: bind/listener
//! reconciliation and Bonjour publishing must consume `HouseholdExposurePolicy`
//! instead of re-creating LAN-vs-Tailnet rules locally.

use std::fs;
use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(file: &str) -> String {
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
    let source = read("household_listener.rs");
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
    let household_source = read("bonjour_publisher.rs");
    let household_publish_body = slice_between(
        &household_source,
        "pub async fn publish_household_bonjour",
        "\n    // Spawn a task",
    );
    assert!(
        household_publish_body.contains("HouseholdExposurePolicy::allowed_targets"),
        "household Bonjour publisher must filter targets through HouseholdExposurePolicy"
    );

    let setup_source = read("setup_beacon.rs");
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
