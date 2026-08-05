use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;
use serde_json::Value;
use server_rs::claw_store_routes;

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
    #[serde(default = "default_route_kind")]
    kind: String,
    auth_kind: String,
    household_operation: Option<String>,
    #[serde(default)]
    peer_guard: bool,
    attach_token_header: Option<String>,
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
    protocol: Option<String>,
}

fn default_route_kind() -> String {
    claw_store_routes::KIND_HTTP_JSON.to_string()
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

fn production_app_source() -> &'static str {
    include_str!("../src/production_app.rs")
}

fn mobile_api_routes_source() -> &'static str {
    include_str!("../src/mobile_api_routes.rs")
}

fn household_bootstrap_source() -> &'static str {
    include_str!("../src/household_bootstrap.rs")
}

fn claw_store_routes_source() -> &'static str {
    include_str!("../src/claw_store_routes.rs")
}

fn handlers_claws_source() -> &'static str {
    include_str!("../src/handlers_claws.rs")
}

fn handlers_mobile_source() -> &'static str {
    include_str!("../src/handlers_mobile.rs")
}

fn claw_store_service_source() -> &'static str {
    include_str!("../src/claw_store_service.rs")
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

fn function_slice<'a>(source: &'a str, function_name: &str) -> &'a str {
    let async_marker = format!("pub async fn {function_name}");
    let sync_marker = format!("pub fn {function_name}");
    let start_idx = source
        .find(&async_marker)
        .or_else(|| source.find(&sync_marker))
        .unwrap_or_else(|| panic!("missing function marker for {function_name}"));
    let rest = &source[start_idx..];
    let end_idx = rest
        .find("\n/// ")
        .or_else(|| rest.find("\n#[cfg(test)]"))
        .unwrap_or(rest.len());
    &rest[..end_idx]
}

fn source_slice(mount: &Mount) -> &'static str {
    match (mount.file.as_str(), mount.slice.as_str()) {
        ("admin/rust/server-rs/src/claw_store_routes.rs", slice) => {
            function_slice(claw_store_routes_source(), slice)
        }
        ("admin/rust/server-rs/src/mobile_api_routes.rs", "routes") => {
            function_slice(mobile_api_routes_source(), "routes")
        }
        ("admin/rust/server-rs/src/production_app.rs", "production_api_rest") => between(
            production_app_source(),
            "let api_rest = Router::new()",
            "let api_uploads = Router::new()",
        ),
        ("admin/rust/server-rs/src/production_app.rs", "production_api_streaming") => between(
            production_app_source(),
            "let api_streaming = Router::new()",
            "let api_rest = Router::new()",
        ),
        ("admin/rust/server-rs/src/household_bootstrap.rs", "household_claws_router") => between(
            household_bootstrap_source(),
            // Not the full statement: `shared_state` grew a second consumer
            // (the post-pairing relay-stream remounts, see the `shared_state`
            // field doc-comment) and now needs `.clone()` here. This prefix
            // is unique to the one call site regardless of what follows it.
            "let claws_router = shared_state",
            "// Pre-household router.",
        ),
        other => panic!("unknown mount source/slice: {other:?}"),
    }
}

#[test]
fn production_main_mounts_the_canonical_mobile_router_once() {
    let mount = ".merge(mobile_api_routes::routes(state))";
    assert_eq!(
        production_app_source().matches(mount).count(),
        1,
        "production app must mount the shared mobile route graph exactly once"
    );
    assert_eq!(
        main_source()
            .matches("server_rs::production_app::compose(&state, &cfg)")
            .count(),
        1,
        "production main must delegate to the complete app composer exactly once"
    );
}

#[test]
fn household_claws_router_start_marker_is_unique() {
    // The `household_claws_router` slice above starts on a prefix, not the
    // full statement, so it survives `shared_state` growing more consumers
    // (it already gained a `.clone()` once — see the field doc-comment on
    // `shared_state` in household_bootstrap.rs). A prefix marker is only
    // safe to shorten as long as it stays unique to the one call site.
    assert_eq!(
        household_bootstrap_source()
            .matches("let claws_router = shared_state")
            .count(),
        1,
        "the household_claws_router start marker must match exactly one call site"
    );
}

fn operation_variant(operation: &str) -> &'static str {
    match operation {
        "claws.list" => "Operation::ClawsList",
        "claws.create" => "Operation::ClawsCreate",
        "claws.use" => "Operation::ClawsUse",
        "claws.delete" => "Operation::ClawsDelete",
        other => panic!("unknown household operation: {other}"),
    }
}

#[test]
fn claw_store_action_handlers_delegate_to_shared_service() {
    let handlers = [
        (
            handlers_claws_source(),
            "handle_install_claw",
            "claw_store_service::install_claw(&state, name)",
        ),
        (
            handlers_claws_source(),
            "handle_uninstall_claw",
            "claw_store_service::uninstall_claw(&state, name)",
        ),
        (
            handlers_mobile_source(),
            "handle_mobile_install_claw",
            "claw_store_service::install_claw(&state, name)",
        ),
        (
            handlers_mobile_source(),
            "handle_mobile_uninstall_claw",
            "claw_store_service::uninstall_claw(&state, name)",
        ),
    ];

    for (source, function_name, service_call) in handlers {
        let body = function_slice(source, function_name);
        assert!(
            body.contains(service_call),
            "{function_name} must delegate to {service_call}"
        );
        for forbidden in [
            "core_rs::manifest::get(",
            "core_rs::manifest::is_known(",
            ".installability()",
            "jobs_rs::Job::new(",
            "mark_installing(",
            "mark_uninstalling(",
            "delete_by_id(",
            "count_by_claw_type(",
            "bad_request_with_reasons(",
        ] {
            assert!(
                !body.contains(forbidden),
                "{function_name} must not reimplement shared Claw Store action semantics with {forbidden}"
            );
        }
    }

    let service = claw_store_service_source();
    for required in [
        "core_rs::manifest::get(&name)",
        "core_rs::manifest::is_known(&name)",
        "entry.installability()",
        "jobs_rs::Job::new(jobs_rs::JobType::InstallClaw",
        "jobs_rs::Job::new(jobs_rs::JobType::UninstallClaw",
        "mark_installing(&claw_name, &job_id)",
        "mark_uninstalling(&claw_name)",
        // Rollback wiring: the service owns the orphan-job cleanup on a failed
        // mark_* transition (see install_claw / uninstall_claw).
        "delete_by_id(&rollback_job)",
        "count_by_claw_type(&n)",
        "ApiError::bad_request_with_reasons(",
    ] {
        assert!(
            service.contains(required),
            "claw_store_service must own shared action semantic: {required}"
        );
    }
}

#[test]
fn claw_store_v1_contract_metadata_is_valid() {
    let contract = contract();
    assert_eq!(contract.name, "claw-store");
    assert_eq!(contract.version, 1);
    assert_eq!(contract.routes.len(), claw_store_routes::ROUTES.len());

    let mut ids = HashSet::new();
    for route in &contract.routes {
        let registry = claw_store_routes::route_by_id(&route.id)
            .unwrap_or_else(|| panic!("{} must exist in claw_store_routes", route.id));
        assert!(ids.insert(&route.id), "duplicate route id {}", route.id);
        assert_eq!(
            route.surface, registry.surface,
            "{} surface must match claw_store_routes",
            route.id
        );
        assert_eq!(
            route.method, registry.method,
            "{} method must match claw_store_routes",
            route.id
        );
        assert_eq!(
            route.path_template, registry.path_template,
            "{} path template must match claw_store_routes",
            route.id
        );
        assert_eq!(
            route.kind,
            registry.kind(),
            "{} kind must match claw_store_routes",
            route.id
        );
        assert_eq!(
            route.household_operation.as_deref(),
            registry.household_operation,
            "{} household operation must match claw_store_routes",
            route.id
        );
        assert_eq!(
            route.mount.file, registry.mount_file,
            "{} mount file must match claw_store_routes",
            route.id
        );
        assert_eq!(
            route.mount.slice, registry.mount_slice,
            "{} mount slice must match claw_store_routes",
            route.id
        );
        assert_eq!(
            route.mount.route_literal, registry.route_literal,
            "{} route literal must match claw_store_routes",
            route.id
        );
        assert!(
            route.path_template.starts_with("/api/v1/"),
            "{} must declare a full API path template",
            route.id
        );
        assert!(
            matches!(route.method.as_str(), "GET" | "POST" | "PATCH" | "DELETE"),
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
        assert!(
            matches!(
                route.kind.as_str(),
                claw_store_routes::KIND_HTTP_JSON | claw_store_routes::KIND_WEBSOCKET_UPGRADE
            ),
            "{} uses unexpected kind {}",
            route.id,
            route.kind
        );
        if route.kind == claw_store_routes::KIND_WEBSOCKET_UPGRADE {
            let upgrade = route
                .expectations
                .get("upgrade")
                .unwrap_or_else(|| panic!("{} websocket route must declare upgrade", route.id));
            assert_eq!(
                upgrade.status, 101,
                "{} websocket upgrade must declare HTTP 101",
                route.id
            );
            assert_eq!(
                upgrade.protocol.as_deref(),
                Some("websocket"),
                "{} websocket upgrade must declare protocol websocket",
                route.id
            );
            assert!(
                upgrade.fixture.is_none(),
                "{} websocket upgrade must not point to a body fixture",
                route.id
            );
            assert!(
                !route.expectations.contains_key("success"),
                "{} websocket route must not declare a JSON success body",
                route.id
            );
        } else {
            assert_eq!(
                route.kind,
                claw_store_routes::KIND_HTTP_JSON,
                "{} non-websocket route must default to http_json",
                route.id
            );
            assert!(
                !route.expectations.contains_key("upgrade"),
                "{} http_json route must not declare websocket upgrade expectations",
                route.id
            );
        }
        for (name, expectation) in &route.expectations {
            assert!(
                (100..600).contains(&usize::from(expectation.status)),
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
        let registry = claw_store_routes::route_by_id(&route.id)
            .unwrap_or_else(|| panic!("{} must exist in claw_store_routes", route.id));
        let slice = source_slice(&route.mount);
        let route_idx = slice.find(registry.route_expr).unwrap_or_else(|| {
            panic!(
                "{} must mount route expression {} in {}#{}",
                route.id, registry.route_expr, route.mount.file, route.mount.slice
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
fn household_instances_mount_distinguishes_get_list_from_post_create() {
    let contract = contract();
    let route = |id: &str| {
        contract
            .routes
            .iter()
            .find(|route| route.id == id)
            .unwrap_or_else(|| panic!("missing route {id}"))
    };

    let list = route("household_list_instances");
    let create = route("household_create_instance");
    assert_eq!(list.method, "GET");
    assert_eq!(list.mount.method_helper, "get");
    assert_eq!(
        list.handler,
        "handlers_household_claws::handle_household_list_instances"
    );
    assert_eq!(list.household_operation.as_deref(), Some("claws.list"));
    assert_eq!(create.method, "POST");
    assert_eq!(create.mount.method_helper, "post");
    assert_eq!(
        create.handler,
        "handlers_household_claws::handle_household_create_instance"
    );
    assert_eq!(create.household_operation.as_deref(), Some("claws.create"));
    assert_eq!(list.path_template, create.path_template);
    assert_eq!(list.mount.route_literal, create.mount.route_literal);

    let slice = source_slice(&list.mount);
    let route_idx = slice
        .find("\"/api/v1/household/instances\"")
        .expect("household instances mount must be present");
    let local = &slice[route_idx..slice.len().min(route_idx + 400)];

    assert!(
        local.contains("get(handlers_household_claws::handle_household_list_instances)"),
        "GET /api/v1/household/instances must route to list handler"
    );
    assert!(
        local.contains(".post(handlers_household_claws::handle_household_create_instance)"),
        "POST /api/v1/household/instances must route to create handler"
    );
}

#[test]
fn household_routes_keep_declared_pop_operations() {
    let handlers = include_str!("../src/handlers_household_claws.rs");
    let contract = contract();

    for route in contract
        .routes
        .iter()
        .filter(|route| route.surface == "household" && route.auth_kind == "household_pop")
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
        if route.peer_guard {
            assert!(
                body.contains("terminal_attach_peer_rejection(peer_addr(peer),"),
                "{} must keep its declared shared peer guard",
                route.handler
            );
        }
    }

    let peer_gate = between(
        handlers,
        "async fn terminal_attach_peer_rejection",
        "\nasync fn household_list_workspaces",
    );
    assert!(
        peer_gate.contains("post_trust_household_peer_gate(peer).await"),
        "household terminal routes must delegate their declared peer gate to the shared live exposure policy"
    );

    let mint = function_slice(handlers, "handle_household_mint_attach_token");
    let mint_gate = mint
        .find("terminal_attach_peer_rejection")
        .expect("attach-token handler must contain the shared peer gate");
    let mint_authorize = mint
        .find("let authorized")
        .expect("attach-token handler must contain household PoP authorization");
    assert!(
        mint_gate < mint_authorize,
        "attach-token peer rejection must precede household PoP authorization"
    );
    let pty = function_slice(handlers, "handle_household_terminal_pty");
    let pty_gate = pty
        .find("terminal_attach_peer_rejection")
        .expect("PTY handler must contain the shared peer gate");
    let pty_redeem = pty
        .rfind("household_terminal_pty")
        .expect("PTY handler must delegate to attach-token redemption");
    assert!(
        pty_gate < pty_redeem,
        "PTY peer rejection must precede attach-token redemption"
    );
}

#[test]
fn websocket_routes_pin_stream_auth_and_attach_token_guards() {
    let contract = contract();
    let route = |id: &str| {
        contract
            .routes
            .iter()
            .find(|route| route.id == id)
            .unwrap_or_else(|| panic!("missing route {id}"))
    };

    let admin = route("admin_terminal_pty");
    assert_eq!(admin.kind, claw_store_routes::KIND_WEBSOCKET_UPGRADE);
    assert_eq!(admin.auth_kind, "admin_stream_auth");
    assert_eq!(
        admin.expectations["auth_error"].fixture.as_deref(),
        Some("admin_auth_unauthorized")
    );

    let main = production_app_source();
    assert!(
        main.contains(".merge(api_streaming)") && main.contains("require_auth"),
        "admin PTY websocket routes must stay under require_auth"
    );
    let auth = include_str!("../src/auth.rs");
    for required in [
        "extract_session_cookie(req.headers())",
        "extract_bearer_token(req.headers())",
        "extract_query_token(req.uri())",
    ] {
        assert!(
            auth.contains(required),
            "admin_stream_auth must keep supporting {required}"
        );
    }

    let household = route("household_terminal_pty");
    assert_eq!(household.kind, claw_store_routes::KIND_WEBSOCKET_UPGRADE);
    assert_eq!(household.auth_kind, "household_attach_token");
    assert_eq!(household.household_operation, None);
    assert_eq!(
        household.attach_token_header.as_deref(),
        Some("x-soyeht-household-attach-token")
    );
    assert_eq!(household.expectations["auth_error"].status, 401);
    assert!(
        household.expectations["auth_error"].fixture.is_none(),
        "household attach-token auth failures are bodyless and must not reuse PoP fixtures"
    );
    assert_eq!(household.expectations["peer_rejected"].status, 403);
    assert!(household.peer_guard);

    let handlers = include_str!("../src/handlers_household_claws.rs");
    for required in [
        "const HOUSEHOLD_ATTACH_TOKEN_HEADER: &str = \"x-soyeht-household-attach-token\"",
        "fn attach_token_from_headers(headers: &HeaderMap)",
        ".consume(token)",
        "terminal_attach_peer_rejection(peer_addr(peer), \"terminal_pty\").await",
    ] {
        assert!(
            handlers.contains(required),
            "household_attach_token PTY contract must stay backed by {required}"
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
        "admin_resource_options",
        "admin_users",
        "admin_create_instance",
        "admin_instance_status",
        "admin_stop_instance",
        "admin_restart_instance",
        "admin_rebuild_instance",
        "admin_delete_instance",
        "admin_list_workspaces",
        "admin_create_workspace",
        "admin_rename_workspace",
        "admin_delete_workspace",
    ] {
        assert_eq!(
            route(id).expectations["auth_error"].fixture.as_deref(),
            Some("admin_auth_unauthorized")
        );
    }
    assert_eq!(
        route("admin_terminal_pty").expectations["auth_error"]
            .fixture
            .as_deref(),
        Some("admin_auth_unauthorized")
    );

    for id in ["admin_resource_options", "admin_users"] {
        assert_eq!(
            route(id).expectations["admin_required"].fixture.as_deref(),
            Some("admin_required")
        );
    }

    for id in [
        "mobile_list_claws",
        "mobile_create_instance",
        "mobile_instance_status",
        "mobile_claw_availability",
        "mobile_install_claw",
        "mobile_uninstall_claw",
    ] {
        assert_eq!(
            route(id).expectations["auth_error"].fixture.as_deref(),
            Some("mobile_missing_auth")
        );
    }

    for id in [
        "mobile_create_instance",
        "mobile_install_claw",
        "mobile_uninstall_claw",
    ] {
        assert_eq!(
            route(id).expectations["admin_required"].fixture.as_deref(),
            Some("mobile_admin_required")
        );
    }

    for id in [
        "household_list_claws",
        "household_claw_availability",
        "household_install_claw",
        "household_uninstall_claw",
        "household_list_instances",
        "household_create_instance",
        "household_instance_status",
        "household_stop_instance",
        "household_restart_instance",
        "household_rebuild_instance",
        "household_delete_instance",
        "household_list_workspaces",
        "household_create_workspace",
        "household_rename_workspace",
        "household_delete_workspace",
        "household_attach_token",
    ] {
        assert_eq!(
            route(id).expectations["auth_error"].fixture.as_deref(),
            Some("empty_body")
        );
    }
    assert_eq!(
        route("household_terminal_pty").expectations["auth_error"].status,
        401
    );
    assert!(
        route("household_terminal_pty").expectations["auth_error"]
            .fixture
            .is_none()
    );
    assert_eq!(
        route("household_attach_token").expectations["success"]
            .fixture
            .as_deref(),
        Some("household_attach_token_minted")
    );
    assert_eq!(
        route("household_attach_token").expectations["peer_rejected"].status,
        403
    );
    assert!(
        route("household_attach_token").peer_guard,
        "attach token mint must keep the peer guard explicit in the contract"
    );

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

#[test]
fn contract_scope_includes_core_lifecycle_workspaces_and_c4_2b_ws_pty() {
    let contract = contract();
    let route_ids = contract
        .routes
        .iter()
        .map(|route| route.id.as_str())
        .collect::<HashSet<_>>();

    for required in [
        "admin_create_instance",
        "admin_instance_status",
        "admin_stop_instance",
        "admin_restart_instance",
        "admin_rebuild_instance",
        "admin_delete_instance",
        "admin_resource_options",
        "admin_users",
        "mobile_create_instance",
        "mobile_instance_status",
        "household_list_instances",
        "household_create_instance",
        "household_instance_status",
        "household_stop_instance",
        "household_restart_instance",
        "household_rebuild_instance",
        "household_delete_instance",
        "admin_list_workspaces",
        "admin_create_workspace",
        "admin_rename_workspace",
        "admin_delete_workspace",
        "household_list_workspaces",
        "household_create_workspace",
        "household_rename_workspace",
        "household_delete_workspace",
        "household_attach_token",
        "admin_terminal_pty",
        "household_terminal_pty",
    ] {
        assert!(
            route_ids.contains(required),
            "missing declared contract route {required}"
        );
    }

    for not_mounted in [
        "mobile_delete_instance",
        "mobile_stop_instance",
        "mobile_restart_instance",
        "mobile_rebuild_instance",
        "mobile_list_workspaces",
        "mobile_create_workspace",
        "mobile_rename_workspace",
        "mobile_delete_workspace",
        "mobile_terminal_pty",
    ] {
        assert!(
            !route_ids.contains(not_mounted),
            "{not_mounted} is outside C4.2b-2 and must not be declared as a success route"
        );
    }
}
