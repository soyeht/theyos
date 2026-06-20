use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Contract {
    #[serde(rename = "contract")]
    name: String,
    version: u32,
    routes: Vec<Route>,
    fixtures: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct Route {
    id: String,
    surface: String,
    method: String,
    path_template: String,
    auth_kind: String,
    household_operation: Option<String>,
    handler: String,
    mount: Mount,
    expectations: BTreeMap<String, Expectation>,
}

#[derive(Debug, Deserialize)]
struct Mount {
    file: String,
    slice: String,
    route_literal: String,
    method_helper: String,
}

#[derive(Debug, Deserialize)]
struct Expectation {
    status: u16,
    fixture: Option<String>,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(
        "../../../contracts/claw-store/v1/contract.json"
    ))
    .expect("claw-store v1 contract must be valid JSON")
}

fn main_source() -> &'static str {
    include_str!("../src/main.rs")
}

fn household_bootstrap_source() -> &'static str {
    include_str!("../src/household_bootstrap.rs")
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start_idx = source
        .find(start)
        .unwrap_or_else(|| panic!("missing source slice start marker: {start}"));
    let rest = &source[start_idx..];
    let end_idx = rest
        .find(end)
        .unwrap_or_else(|| panic!("missing source slice end marker: {end}"));
    &rest[..end_idx]
}

fn source_slice(mount: &Mount) -> &'static str {
    match (mount.file.as_str(), mount.slice.as_str()) {
        ("admin/rust/server-rs/src/main.rs", "main_api_rest") => between(
            main_source(),
            "let api_rest = Router::new()",
            "let api_uploads = Router::new()",
        ),
        ("admin/rust/server-rs/src/main.rs", "main_mobile_api") => between(
            main_source(),
            "let mobile_api = Router::new()",
            "let app = Router::new()",
        ),
        ("admin/rust/server-rs/src/main.rs", "main_app_mobile_direct") => between(
            main_source(),
            "// Mobile claw install/uninstall/availability",
            ".nest(\"/api/v1/mobile\", mobile_api)",
        ),
        ("admin/rust/server-rs/src/household_bootstrap.rs", "household_claws_router") => between(
            household_bootstrap_source(),
            "let claws_router = shared_state.map(|state| {",
            "// Pre-household router.",
        ),
        other => panic!("unknown mount source/slice: {other:?}"),
    }
}

fn operation_variant(operation: &str) -> &'static str {
    match operation {
        "claws.list" => "Operation::ClawsList",
        "claws.create" => "Operation::ClawsCreate",
        "claws.delete" => "Operation::ClawsDelete",
        other => panic!("unknown household operation: {other}"),
    }
}

#[test]
fn claw_store_v1_contract_metadata_is_valid() {
    let contract = contract();
    assert_eq!(contract.name, "claw-store");
    assert_eq!(contract.version, 1);
    assert_eq!(contract.routes.len(), 13);

    let mut ids = HashSet::new();
    for route in &contract.routes {
        assert!(ids.insert(&route.id), "duplicate route id {}", route.id);
        assert!(
            route.path_template.starts_with("/api/v1/"),
            "{} must declare a full API path template",
            route.id
        );
        assert!(
            matches!(route.method.as_str(), "GET" | "POST"),
            "{} uses unexpected method {}",
            route.id,
            route.method
        );
        assert!(
            matches!(route.surface.as_str(), "admin" | "mobile" | "household"),
            "{} uses unexpected surface {}",
            route.id,
            route.surface
        );
        assert!(
            !route.expectations.is_empty(),
            "{} must declare current status expectations",
            route.id
        );
        for (name, expectation) in &route.expectations {
            assert!(
                (200..600).contains(&usize::from(expectation.status)),
                "{} expectation {name} has invalid HTTP status {}",
                route.id,
                expectation.status
            );
            if let Some(fixture) = &expectation.fixture {
                assert!(
                    contract.fixtures.contains_key(fixture),
                    "{} expectation {name} references missing fixture {fixture}",
                    route.id
                );
            }
        }
    }
}

#[test]
fn claw_store_v1_routes_are_mounted_with_declared_handlers() {
    for route in contract().routes {
        let slice = source_slice(&route.mount);
        let route_token = format!("\"{}\"", route.mount.route_literal);
        let route_idx = slice.find(&route_token).unwrap_or_else(|| {
            panic!(
                "{} must mount route literal {} in {}#{}",
                route.id, route.mount.route_literal, route.mount.file, route.mount.slice
            )
        });
        let local = &slice[route_idx..slice.len().min(route_idx + 700)];

        assert!(
            local.contains(&route.handler),
            "{} route {} must point to handler {}",
            route.id,
            route.mount.route_literal,
            route.handler
        );
        assert!(
            local.contains(&format!("{}(", route.mount.method_helper))
                || local.contains(&format!(".{}(", route.mount.method_helper)),
            "{} route {} must use {} routing helper",
            route.id,
            route.mount.route_literal,
            route.mount.method_helper
        );
    }
}

#[test]
fn household_routes_keep_declared_pop_operations() {
    let handlers = include_str!("../src/handlers_household_claws.rs");
    let contract = contract();

    for route in contract
        .routes
        .iter()
        .filter(|route| route.surface == "household")
    {
        assert_eq!(
            route.auth_kind, "household_pop",
            "{} must stay household PoP authenticated",
            route.id
        );
        let operation = route
            .household_operation
            .as_deref()
            .unwrap_or_else(|| panic!("{} must declare household operation", route.id));
        let marker = format!(
            "pub async fn {}",
            route.handler.rsplit("::").next().unwrap()
        );
        let start = handlers
            .find(&marker)
            .unwrap_or_else(|| panic!("missing household handler {}", route.handler));
        let body = &handlers[start..handlers.len().min(start + 900)];

        assert!(
            body.contains(operation_variant(operation)),
            "{} must authorize {}",
            route.handler,
            operation
        );
    }
}

#[test]
fn current_wire_quirks_are_explicitly_pinned() {
    let contract = contract();
    let route = |id: &str| {
        contract
            .routes
            .iter()
            .find(|route| route.id == id)
            .unwrap_or_else(|| panic!("missing route {id}"))
    };

    assert_eq!(
        route("admin_install_claw").expectations["already_installing"].status,
        200
    );
    assert_eq!(
        route("household_install_claw").expectations["already_installing"].status,
        200
    );
    assert_eq!(
        route("mobile_install_claw").expectations["already_installing"].status,
        409
    );

    for id in [
        "admin_claw_availability",
        "mobile_claw_availability",
        "household_claw_availability",
    ] {
        assert_eq!(route(id).expectations["unknown"].status, 200);
        assert_eq!(
            route(id).expectations["unknown"].fixture.as_deref(),
            Some("unknown_availability")
        );
    }

    for id in [
        "admin_install_claw",
        "mobile_install_claw",
        "household_install_claw",
    ] {
        assert_eq!(route(id).expectations["unavailable"].status, 400);
        assert_eq!(
            route(id).expectations["unavailable"].fixture.as_deref(),
            Some("install_unavailable_reasons_object")
        );
    }
}
