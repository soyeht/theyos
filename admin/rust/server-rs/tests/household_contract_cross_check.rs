//! Cross-check between the executable Claw Store contract and the household docs mirror.
//!
//! `admin/contracts/claw-store/v1/contract.json` is the source of truth. The
//! household-only docs JSON must stay a projection of its `surface == "household"`
//! routes, keyed by the same route ids.

use std::collections::BTreeMap;

use serde::Deserialize;

const V1_CONTRACT: &str = include_str!("../../../contracts/claw-store/v1/contract.json");
const HOUSEHOLD_V1: &str = include_str!("../../../../docs/contracts/claw-store-household-v1.json");

#[derive(Debug, Deserialize)]
struct ExecutableContract {
    routes: Vec<ExecutableRoute>,
}

#[derive(Debug, Deserialize)]
struct ExecutableRoute {
    id: String,
    surface: String,
    method: String,
    path_template: String,
    auth_kind: String,
    household_operation: Option<String>,
    #[serde(default)]
    peer_guard: bool,
}

#[derive(Debug, Deserialize)]
struct DocsHouseholdContract {
    routes: Vec<DocsHouseholdRoute>,
}

#[derive(Debug, Deserialize)]
struct DocsHouseholdRoute {
    id: String,
    method: String,
    path: String,
    operation: Option<String>,
    auth: String,
    #[serde(default)]
    peer_guard: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableRoute {
    method: String,
    path: String,
    operation: Option<String>,
    auth_kind: String,
    peer_guard: bool,
}

fn docs_auth_to_contract_auth(auth: &str) -> &'static str {
    match auth {
        "pop" => "household_pop",
        "attach_token" => "household_attach_token",
        "owner_site_pre_effect" => "owner_site_pre_effect",
        "owner_site_ake" => "owner_site_ake",
        other => panic!("docs household route uses unknown auth kind {other}"),
    }
}

fn insert_route(
    routes: &mut BTreeMap<String, ComparableRoute>,
    id: String,
    route: ComparableRoute,
    source: &str,
) {
    assert!(
        routes.insert(id.clone(), route).is_none(),
        "{source} declares duplicate household route id {id}"
    );
}

fn household_routes_from_v1_contract() -> BTreeMap<String, ComparableRoute> {
    let doc: ExecutableContract =
        serde_json::from_str(V1_CONTRACT).expect("v1 contract is valid JSON");
    let mut routes = BTreeMap::new();

    for route in doc
        .routes
        .into_iter()
        .filter(|route| route.surface == "household")
    {
        insert_route(
            &mut routes,
            route.id,
            ComparableRoute {
                method: route.method,
                path: route.path_template,
                operation: route.household_operation,
                auth_kind: route.auth_kind,
                peer_guard: route.peer_guard,
            },
            "admin/contracts/claw-store/v1/contract.json",
        );
    }

    routes
}

fn household_routes_from_docs_contract() -> BTreeMap<String, ComparableRoute> {
    let doc: DocsHouseholdContract =
        serde_json::from_str(HOUSEHOLD_V1).expect("household-v1 is valid JSON");
    let mut routes = BTreeMap::new();

    for route in doc.routes {
        let auth_kind = docs_auth_to_contract_auth(&route.auth).to_string();
        insert_route(
            &mut routes,
            route.id,
            ComparableRoute {
                method: route.method,
                path: route.path,
                operation: route.operation,
                auth_kind,
                peer_guard: route.peer_guard,
            },
            "docs/contracts/claw-store-household-v1.json",
        );
    }

    routes
}

#[test]
fn household_docs_contract_tracks_executable_household_subset_by_id() {
    let executable = household_routes_from_v1_contract();
    let docs = household_routes_from_docs_contract();

    assert!(
        !executable.is_empty(),
        "v1 contract declares no household routes; did the surface tag change?"
    );

    let missing_ids = executable
        .keys()
        .filter(|id| !docs.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    let extra_ids = docs
        .keys()
        .filter(|id| !executable.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    let divergent = executable
        .iter()
        .filter_map(|(id, expected)| {
            docs.get(id).and_then(|actual| {
                (actual != expected)
                    .then(|| format!("{id}: expected {expected:?}; docs {actual:?}"))
            })
        })
        .collect::<Vec<_>>();

    assert!(
        missing_ids.is_empty() && extra_ids.is_empty() && divergent.is_empty(),
        "docs/contracts/claw-store-household-v1.json must be a projection of \
         admin/contracts/claw-store/v1/contract.json household routes.\n\
         missing ids: {missing_ids:?}\n\
         extra ids: {extra_ids:?}\n\
         divergent routes:\n{}",
        divergent.join("\n")
    );
}
