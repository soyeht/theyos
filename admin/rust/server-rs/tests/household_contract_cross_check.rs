//! Cross-check between the two theyos household Claw Store contract declarations.
//!
//! Household routes declared in BOTH `admin/contracts/claw-store/v1/contract.json`
//! (surface "household") and `docs/contracts/claw-store-household-v1.json` must
//! agree on path / method / operation. The household-only doc also includes
//! attach-token routes that are intentionally deferred from the cross-repo C4.2a
//! contract, so this test pins the overlap instead of requiring both files to
//! have the same full route set.

use std::collections::BTreeSet;

use serde_json::Value;

const V1_CONTRACT: &str = include_str!("../../../contracts/claw-store/v1/contract.json");
const HOUSEHOLD_V1: &str = include_str!("../../../../docs/contracts/claw-store-household-v1.json");

/// `(path, method, operation)` tuples for household routes present in the
/// cross-repo v1 contract.
fn household_routes_from_v1_contract() -> BTreeSet<(String, String, String)> {
    let doc: Value = serde_json::from_str(V1_CONTRACT).expect("v1 contract is valid JSON");
    doc["routes"]
        .as_array()
        .expect("v1 contract has a routes array")
        .iter()
        .filter(|r| r["surface"] == "household")
        .map(|r| {
            (
                r["path_template"].as_str().unwrap_or_default().to_string(),
                r["method"].as_str().unwrap_or_default().to_string(),
                r["household_operation"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect()
}

fn household_routes_from_household_v1(
    overlap: &BTreeSet<(String, String, String)>,
) -> BTreeSet<(String, String, String)> {
    let doc: Value = serde_json::from_str(HOUSEHOLD_V1).expect("household-v1 is valid JSON");
    doc["routes"]
        .as_array()
        .expect("household-v1 has a routes array")
        .iter()
        .filter_map(|r| {
            let tuple = (
                r["path"].as_str().unwrap_or_default().to_string(),
                r["method"].as_str().unwrap_or_default().to_string(),
                r["operation"].as_str().unwrap_or_default().to_string(),
            );
            overlap.contains(&tuple).then_some(tuple)
        })
        .collect()
}

#[test]
fn household_overlap_routes_agree_across_both_contract_files() {
    let from_v1 = household_routes_from_v1_contract();
    let from_household = household_routes_from_household_v1(&from_v1);

    assert!(
        !from_v1.is_empty(),
        "v1 contract declares no household routes — did the surface tag change?"
    );
    assert_eq!(
        from_v1,
        from_household,
        "household overlap routes diverge between the two contract files.\n\
         in claw-store/v1/contract.json only: {:?}\n\
         in docs/contracts/claw-store-household-v1.json only: {:?}",
        from_v1.difference(&from_household).collect::<Vec<_>>(),
        from_household.difference(&from_v1).collect::<Vec<_>>(),
    );
}
