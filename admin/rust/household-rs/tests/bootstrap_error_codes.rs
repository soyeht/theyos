//! Cross-language parity guard for `BootstrapErrorCode` ↔ the vendored fixture
//! (`tests/fixtures/bootstrap_error_codes.json`, the cross-repo contract
//! soyeht-ios vendors). Locks the bounded set: every concrete enum code is in
//! the fixture and vice-versa, decode is fail-soft, and `Unknown` is receive-only
//! (never a producer code in the fixture).

use household_rs::bootstrap_error::BootstrapErrorCode;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/bootstrap_error_codes.json");

#[test]
fn fixture_matches_enum_set_and_is_failsoft() {
    let parsed: Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");
    let rows = parsed["codes"].as_array().expect("`codes` array");

    // Count parity: exactly one fixture row per concrete enum variant.
    assert_eq!(
        rows.len(),
        BootstrapErrorCode::ALL.len(),
        "fixture row count != BootstrapErrorCode::ALL count"
    );

    // Every fixture wire is a known concrete code, round-trips, and has a status.
    for row in rows {
        let wire = row["wire"].as_str().expect("row has `wire`");
        let code = BootstrapErrorCode::from_wire(wire);
        assert_ne!(
            code,
            BootstrapErrorCode::Unknown,
            "fixture wire `{wire}` is not a known BootstrapErrorCode"
        );
        assert_eq!(code.as_str(), wire, "round-trip mismatch for `{wire}`");
        assert!(
            row["http_status"].as_u64().is_some(),
            "fixture row `{wire}` is missing `http_status`"
        );
    }

    // Every concrete enum code appears in the fixture (bidirectional).
    let wires: Vec<&str> = rows.iter().filter_map(|r| r["wire"].as_str()).collect();
    for code in BootstrapErrorCode::ALL {
        assert!(
            wires.contains(&code.as_str()),
            "enum code `{}` is missing from the fixture",
            code.as_str()
        );
    }

    // `Unknown` is receive-only: it must never be listed as a producer code.
    assert!(
        !wires.contains(&"unknown"),
        "Unknown is fail-soft/receive-only and must not appear in the producer fixture"
    );
    // Fail-soft: a future/unknown wire decodes to Unknown.
    assert_eq!(
        BootstrapErrorCode::from_wire("brand_new_future_code"),
        BootstrapErrorCode::Unknown
    );
}
