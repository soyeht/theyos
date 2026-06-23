//! Cross-language contract guard for the instance lifecycle status wire string.
//!
//! `store_rs::InstanceStatus` is the source of truth. This pins that it EMITS
//! exactly the wire set in `tests/fixtures/instance_status_codes.json` (the
//! contract soyeht-ios vendors verbatim), and documents the legacy receive-only
//! `error` alias separately so it never leaks into the emitted contract.

use serde_json::Value;
use std::str::FromStr;
use store_rs::InstanceStatus;

const FIXTURE: &str = include_str!("fixtures/instance_status_codes.json");

/// Every concrete `InstanceStatus` variant. The match in `_exhaustive` fails to
/// compile if a variant is added without updating this list (and the fixture).
fn all() -> Vec<InstanceStatus> {
    vec![
        InstanceStatus::Provisioning,
        InstanceStatus::Active,
        InstanceStatus::Stopped,
        InstanceStatus::Failed,
    ]
}

#[allow(dead_code)]
fn _exhaustive(s: InstanceStatus) {
    // Adding a variant breaks compilation here → update all() AND the fixture.
    match s {
        InstanceStatus::Provisioning
        | InstanceStatus::Active
        | InstanceStatus::Stopped
        | InstanceStatus::Failed => {}
    }
}

#[test]
fn fixture_matches_emitted_wire_set() {
    let parsed: Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");
    let rows = parsed["statuses"]
        .as_array()
        .expect("`statuses` is an array");

    // Count parity: one fixture row per emitted variant.
    assert_eq!(
        rows.len(),
        all().len(),
        "fixture row count != InstanceStatus variant count"
    );

    let wires: Vec<&str> = rows
        .iter()
        .map(|r| r["wire"].as_str().expect("row has a string `wire`"))
        .collect();

    // Every emitted variant is in the fixture and round-trips via as_str / FromStr /
    // serde (rename_all = "lowercase").
    for s in all() {
        assert!(
            wires.contains(&s.as_str()),
            "emitted status `{}` is missing from the fixture",
            s.as_str()
        );
        assert_eq!(
            InstanceStatus::from_str(s.as_str()).unwrap(),
            s,
            "FromStr round-trip failed for {s:?}"
        );
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            format!("\"{}\"", s.as_str()),
            "serde wire string diverges from as_str for {s:?}"
        );
    }

    // Bidirectional: every fixture wire is an emitted variant.
    for wire in &wires {
        assert!(
            all().iter().any(|s| s.as_str() == *wire),
            "fixture wire `{wire}` is not an emitted InstanceStatus"
        );
    }
}

#[test]
fn legacy_error_alias_is_receive_compat_only_and_absent_from_the_contract() {
    // `FromStr` accepts the legacy `error` alias as `Failed` (receive-compat), but
    // `as_str` NEVER emits it — so it must stay out of the emitted-contract fixture.
    assert_eq!(
        InstanceStatus::from_str("error").unwrap(),
        InstanceStatus::Failed
    );
    assert_eq!(InstanceStatus::Failed.as_str(), "failed");

    let parsed: Value = serde_json::from_str(FIXTURE).unwrap();
    let wires: Vec<&str> = parsed["statuses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["wire"].as_str().unwrap())
        .collect();
    assert!(
        !wires.contains(&"error"),
        "the legacy `error` alias must not appear in the emitted-contract fixture"
    );

    // An unknown/future status is an error on parse (never silently a variant).
    assert!(InstanceStatus::from_str("deleting").is_err());
}
