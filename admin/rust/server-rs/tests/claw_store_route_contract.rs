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

fn status_for_error_code(code: &str) -> Option<u16> {
    match code {
        "INVALID_INPUT" => Some(400),
        "UNAUTHORIZED" => Some(401),
        "FORBIDDEN" => Some(403),
        "NOT_FOUND" => Some(404),
        "CONFLICT" => Some(409),
        _ => None,
    }
}

fn is_allowed_schema_fixture(fixture: &str) -> bool {
    matches!(
        fixture,
        "install_queued_job_schema" | "uninstall_queued_job_schema"
    )
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
                let body = contract.fixtures.get(fixture).unwrap_or_else(|| {
                    panic!(
                        "{} expectation {name} references missing fixture {fixture}",
                        route.id
                    )
                });
                if fixture.ends_with("_schema") {
                    assert!(
                        is_allowed_schema_fixture(fixture),
                        "{} expectation {name} references unknown schema fixture {fixture}",
                        route.id
                    );
                    assert_eq!(
                        name, "queued",
                        "{} schema fixture {fixture} may only describe queued dynamic responses",
                        route.id
                    );
                    assert_eq!(
                        expectation.status, 200,
                        "{} queued schema fixture {fixture} must stay HTTP 200",
                        route.id
                    );
                    assert_eq!(
                        body.get("schema").and_then(Value::as_str),
                        Some("claw_job_response_pattern"),
                        "{fixture} must declare the Claw job response schema class"
                    );
                    assert!(
                        body.get("job_id_pattern").and_then(Value::as_str).is_some(),
                        "{fixture} must declare the dynamic job_id pattern"
                    );
                    assert!(
                        body.get("message").and_then(Value::as_str).is_some(),
                        "{fixture} must declare the exact queued message"
                    );
                    continue;
                }
                if let Some(code) = body.get("code").and_then(Value::as_str) {
                    if let Some(expected_status) = status_for_error_code(code) {
                        assert_eq!(
                            expectation.status, expected_status,
                            "{} expectation {name} status must match fixture {fixture} code {code}",
                            route.id
                        );
                    }
                }
                if fixture == "empty_body" {
                    assert_eq!(
                        expectation.status, 401,
                        "{} expectation {name} uses empty_body outside the current 401 auth shape",
                        route.id
                    );
                }
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
        assert_eq!(
            route(id).expectations["queued"].fixture.as_deref(),
            Some("install_queued_job_schema")
        );
        assert_eq!(
            route(id).expectations["already_installing"]
                .fixture
                .as_deref(),
            Some("already_installing_job_body")
        );
        assert_eq!(route(id).expectations["unavailable"].status, 400);
        assert_eq!(
            route(id).expectations["unavailable"].fixture.as_deref(),
            Some("install_unavailable_reasons_object")
        );
    }

    for id in [
        "admin_uninstall_claw",
        "mobile_uninstall_claw",
        "household_uninstall_claw",
    ] {
        assert_eq!(
            route(id).expectations["queued"].fixture.as_deref(),
            Some("uninstall_queued_job_schema")
        );
    }

    for id in [
        "admin_list_claws",
        "admin_get_claw",
        "admin_claw_availability",
        "admin_install_claw",
        "admin_uninstall_claw",
    ] {
        assert_eq!(
            route(id).expectations["auth_error"].fixture.as_deref(),
            Some("admin_auth_unauthorized")
        );
    }

    for id in [
        "mobile_list_claws",
        "mobile_claw_availability",
        "mobile_install_claw",
        "mobile_uninstall_claw",
    ] {
        assert_eq!(
            route(id).expectations["auth_error"].fixture.as_deref(),
            Some("mobile_missing_auth")
        );
    }

    for id in ["mobile_install_claw", "mobile_uninstall_claw"] {
        assert_eq!(
            route(id).expectations["admin_required"].fixture.as_deref(),
            Some("mobile_admin_required")
        );
    }

    for id in [
        "admin_get_claw",
        "admin_install_claw",
        "admin_uninstall_claw",
        "mobile_install_claw",
        "mobile_uninstall_claw",
        "household_install_claw",
        "household_uninstall_claw",
    ] {
        assert_eq!(
            route(id).expectations["unknown"].fixture.as_deref(),
            Some("unknown_claw_error")
        );
    }

    for id in [
        "admin_install_claw",
        "mobile_install_claw",
        "household_install_claw",
    ] {
        assert_eq!(
            route(id).expectations["already_ready"].fixture.as_deref(),
            Some("already_ready_error")
        );
    }

    for id in [
        "admin_uninstall_claw",
        "mobile_uninstall_claw",
        "household_uninstall_claw",
    ] {
        assert_eq!(
            route(id).expectations["not_ready"].fixture.as_deref(),
            Some("not_installed_error")
        );
        assert_eq!(
            route(id).expectations["instances_exist"].fixture.as_deref(),
            Some("uninstall_instances_exist_error")
        );
    }
}
