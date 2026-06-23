//! Cross-language fixture parity guard for `GuestImageFailureCode`.
//!
//! Pins that `tests/fixtures/guest_image_failure_codes.json` — the cross-repo
//! contract vendored into soyeht-ios — stays in lockstep with the Rust enum:
//! every code's `wire` + `default_scope` agree with the enum, and the set is
//! exhaustive (no code added/removed without updating the fixture). The
//! `recovery_action` / `cta` columns are the iOS surface's to validate (PR-B);
//! here they are only sanity-checked for presence + a well-formed `cta`.

use core_rs::guest_image_failure::{FailureScope, GuestImageFailureCode};
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/guest_image_failure_codes.json");

/// Every variant of `GuestImageFailureCode`. Kept honest by `_exhaustive` below,
/// which fails to compile if a variant is added without updating this list.
fn all_codes() -> Vec<GuestImageFailureCode> {
    use GuestImageFailureCode::{
        EntitlementMissing, HelperMissing, HostVmLimitReached, InsufficientDisk,
        IpswDownloadFailed, IpswIncompatible, Unknown, VirtualizationUnavailable,
    };
    vec![
        HostVmLimitReached,
        HelperMissing,
        InsufficientDisk,
        EntitlementMissing,
        IpswDownloadFailed,
        IpswIncompatible,
        VirtualizationUnavailable,
        Unknown,
    ]
}

#[allow(dead_code)]
fn _exhaustive(c: GuestImageFailureCode) {
    // Adding a variant breaks compilation here → update all_codes() AND the fixture.
    match c {
        GuestImageFailureCode::HostVmLimitReached
        | GuestImageFailureCode::HelperMissing
        | GuestImageFailureCode::InsufficientDisk
        | GuestImageFailureCode::EntitlementMissing
        | GuestImageFailureCode::IpswDownloadFailed
        | GuestImageFailureCode::IpswIncompatible
        | GuestImageFailureCode::VirtualizationUnavailable
        | GuestImageFailureCode::Unknown => {}
    }
}

#[test]
fn fixture_matches_rust_failure_code_set() {
    let parsed: Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");
    let rows = parsed["codes"].as_array().expect("`codes` is an array");

    // 1) Count parity: exactly one fixture row per Rust variant.
    assert_eq!(
        rows.len(),
        all_codes().len(),
        "fixture row count != GuestImageFailureCode variant count (a code was added/removed \
         without updating the fixture)"
    );

    // 2) Every Rust code has a row whose wire + default_scope agree with the enum.
    for code in all_codes() {
        let wire = code.as_str();
        let row = rows
            .iter()
            .find(|r| r["wire"].as_str() == Some(wire))
            .unwrap_or_else(|| panic!("fixture is missing a row for `{wire}`"));
        assert_eq!(
            row["default_scope"].as_str(),
            Some(code.default_scope().as_str()),
            "fixture default_scope for `{wire}` disagrees with the Rust default_scope"
        );
        assert_eq!(
            GuestImageFailureCode::from_wire(wire),
            code,
            "from_wire(`{wire}`) did not round-trip to the expected code"
        );
    }

    // 3) Every fixture row is a known code/scope, and the iOS-owned columns are
    //    present + well-formed (PR-B validates the exact action↔cta policy).
    for row in rows {
        let wire = row["wire"].as_str().expect("row has a `wire`");
        assert!(
            all_codes().iter().any(|c| c.as_str() == wire),
            "fixture row `{wire}` is not a known GuestImageFailureCode"
        );
        let scope = row["default_scope"]
            .as_str()
            .expect("row has a `default_scope`");
        assert_ne!(
            FailureScope::from_wire(scope),
            FailureScope::Unknown,
            "fixture default_scope `{scope}` for `{wire}` is not a known FailureScope"
        );
        assert!(
            row["recovery_action"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "fixture row `{wire}` is missing `recovery_action`"
        );
        assert!(
            matches!(
                row["cta"].as_str(),
                Some("prepare" | "check_again" | "none")
            ),
            "fixture row `{wire}` has an unknown `cta`"
        );
    }
}

#[test]
fn virtualization_unavailable_is_terminal_with_no_cta() {
    // The whole point of this PR: virtualization_unavailable must be a persistent
    // (blocking) failure whose iOS recovery is "no mutating CTA" (action+cta none)
    // so the iPhone never offers an infinite prepare retry on an unsupportable Mac.
    assert_eq!(
        GuestImageFailureCode::VirtualizationUnavailable.default_scope(),
        FailureScope::Persistent
    );
    let parsed: Value = serde_json::from_str(FIXTURE).unwrap();
    let row = parsed["codes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["wire"].as_str() == Some("virtualization_unavailable"))
        .expect("virtualization_unavailable row exists");
    assert_eq!(row["recovery_action"].as_str(), Some("none"));
    assert_eq!(row["cta"].as_str(), Some("none"));
}
