//! Cross-language fixture parity guard for `UnavailableReasonCode`.
//!
//! Pins that `tests/fixtures/claw_unavailable_reason_codes.json` - the cross-repo
//! contract vendored into soyeht-ios - stays in lockstep with the Rust enum:
//! every emitted variant has a fixture row whose `wire` is the serde `snake_case`
//! string, the set is exhaustive (a variant added/removed without updating the
//! fixture breaks compilation), and the wire round-trips through serde. The Swift
//! `ClawUnavailableReasonCode.unknown` is a receive-only fail-soft fallback (PR-B
//! validates it) and is intentionally NOT an emitted-contract wire here.

use core_rs::manifest::UnavailableReasonCode;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/claw_unavailable_reason_codes.json");

/// Every emitted variant. `_exhaustive` below fails to compile if a variant is
/// added without updating this list (and the fixture).
fn all_codes() -> Vec<UnavailableReasonCode> {
    use UnavailableReasonCode::{CatalogOnly, DetectedUnverified, NoInstallPlan};
    vec![CatalogOnly, DetectedUnverified, NoInstallPlan]
}

#[allow(dead_code)]
fn _exhaustive(c: UnavailableReasonCode) {
    // Adding a variant breaks compilation here -> update all_codes() AND the fixture.
    match c {
        UnavailableReasonCode::CatalogOnly
        | UnavailableReasonCode::DetectedUnverified
        | UnavailableReasonCode::NoInstallPlan => {}
    }
}

/// The serde wire string (`rename_all = "snake_case"`) for a variant.
fn wire_of(c: UnavailableReasonCode) -> String {
    match serde_json::to_value(c).expect("serialize UnavailableReasonCode") {
        Value::String(s) => s,
        other => panic!("expected a JSON string wire, got {other:?}"),
    }
}

#[test]
fn fixture_matches_rust_unavailable_reason_set() {
    let parsed: Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");
    let rows = parsed["codes"].as_array().expect("`codes` is an array");

    // Count parity: exactly one fixture row per emitted variant.
    assert_eq!(
        rows.len(),
        all_codes().len(),
        "fixture row count != UnavailableReasonCode variant count (a code was added/removed \
         without updating the fixture)"
    );

    let wires: Vec<&str> = rows
        .iter()
        .map(|r| r["wire"].as_str().expect("row has a string `wire`"))
        .collect();

    // Every emitted variant has a fixture row and round-trips through serde.
    for code in all_codes() {
        let wire = wire_of(code);
        assert!(
            wires.contains(&wire.as_str()),
            "fixture is missing a row for `{wire}`"
        );
        let back: UnavailableReasonCode =
            serde_json::from_value(Value::String(wire.clone())).expect("deserialize wire");
        assert_eq!(
            back, code,
            "serde round-trip for `{wire}` did not return the same variant"
        );
    }

    // Bidirectional: every fixture wire is an emitted variant.
    for wire in &wires {
        assert!(
            all_codes().iter().any(|c| wire_of(*c) == *wire),
            "fixture wire `{wire}` is not an emitted UnavailableReasonCode"
        );
    }

    // The Swift `.unknown` fail-soft fallback is receive-only, never emitted.
    assert!(
        !wires.contains(&"unknown"),
        "`unknown` is the Swift receive-only fallback, not an emitted-contract wire"
    );
}
