//! Cross-check between the two theyos household-claw contract declarations.
//!
//! The household claw routes (list / availability / install / uninstall) are
//! declared in BOTH `admin/contracts/claw-store/v1/contract.json` (surface
//! "household") and `docs/contracts/claw-store-household-v1.json`. Each file is
//! independently guarded against the Rust route registry, but nothing asserted
//! the two files AGREE with each other — so a path / method / operation edit in
//! one could silently diverge from the other. This test pins their overlap (the
//! four household claw routes) so the two contract documents cannot drift apart.

use std::collections::BTreeSet;

use serde_json::Value;

const V1_CONTRACT: &str = include_str!("../../../contracts/claw-store/v1/contract.json");
const HOUSEHOLD_V1: &str = include_str!("../../../../docs/contracts/claw-store-household-v1.json");

const CLAW_PATH_PREFIX: &str = "/api/v1/household/claws";

/// `(path, method, operation)` tuples for the household claw routes.
fn claw_routes_from_v1_contract() -> BTreeSet<(String, String, String)> {
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

fn claw_routes_from_household_v1() -> BTreeSet<(String, String, String)> {
    let doc: Value = serde_json::from_str(HOUSEHOLD_V1).expect("household-v1 is valid JSON");
    let claw_prefix = format!("{CLAW_PATH_PREFIX}/");
    doc["routes"]
        .as_array()
        .expect("household-v1 has a routes array")
        .iter()
        .filter(|r| {
            r["path"]
                .as_str()
                .is_some_and(|p| p == CLAW_PATH_PREFIX || p.starts_with(&claw_prefix))
        })
        .map(|r| {
            (
                r["path"].as_str().unwrap_or_default().to_string(),
                r["method"].as_str().unwrap_or_default().to_string(),
                r["operation"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

#[test]
fn household_claw_routes_agree_across_both_contract_files() {
    let from_v1 = claw_routes_from_v1_contract();
    let from_household = claw_routes_from_household_v1();

    assert!(
        !from_v1.is_empty(),
        "v1 contract declares no household routes — did the surface tag change?"
    );
    assert_eq!(
        from_v1,
        from_household,
        "household claw routes diverge between the two contract files.\n\
         in claw-store/v1/contract.json only: {:?}\n\
         in docs/contracts/claw-store-household-v1.json only: {:?}",
        from_v1.difference(&from_household).collect::<Vec<_>>(),
        from_household.difference(&from_v1).collect::<Vec<_>>(),
    );
}
