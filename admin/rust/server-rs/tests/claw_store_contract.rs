use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract {
    #[serde(rename = "contract")]
    name: String,
    version: u32,
    attach_token_header: String,
    routes: Vec<Route>,
}

#[derive(Debug, Deserialize)]
struct Route {
    name: String,
    method: String,
    path: String,
    handler: String,
    operation: Option<String>,
    auth: String,
    #[serde(default)]
    peer_guard: bool,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(
        "../../../../docs/contracts/claw-store-household-v1.json"
    ))
    .expect("contract fixture must be valid JSON")
}

fn operation_variant(operation: &str) -> &'static str {
    match operation {
        "claws.list" => "Operation::ClawsList",
        "claws.create" => "Operation::ClawsCreate",
        "claws.use" => "Operation::ClawsUse",
        "claws.delete" => "Operation::ClawsDelete",
        other => panic!("unknown operation in contract: {other}"),
    }
}

fn handler_body<'a>(source: &'a str, handler: &str) -> &'a str {
    let marker = format!("pub async fn {handler}");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("handler {handler} must exist"));
    let rest = &source[start + marker.len()..];
    let end = rest.find("\npub async fn ").unwrap_or(rest.len());
    &rest[..end]
}

fn terminal_peer_rejection_body(source: &str) -> &str {
    let marker = "async fn terminal_attach_peer_rejection";
    let start = source
        .find(marker)
        .expect("terminal peer rejection helper must exist");
    let rest = &source[start..];
    let end = rest
        .find("\nasync fn household_list_workspaces")
        .expect("terminal peer rejection helper must end before workspace helpers");
    &rest[..end]
}

#[test]
fn household_claw_contract_routes_are_mounted_with_declared_handlers() {
    let contract = contract();
    assert_eq!(contract.name, "claw-store-household");
    assert_eq!(contract.version, 1);

    let bootstrap = include_str!("../src/household_bootstrap.rs");
    let claw_store_routes = include_str!("../src/claw_store_routes.rs");
    assert!(
        bootstrap.contains("crate::claw_store_routes::household_routes()"),
        "household bootstrap must merge the shared Claw Store route owner"
    );
    for route in &contract.routes {
        let mount_source = if route.path.starts_with("/api/v1/household/claws") {
            claw_store_routes
        } else {
            bootstrap
        };
        assert!(
            mount_source.contains(&format!("\"{}\"", route.path)),
            "{} {} must be mounted",
            route.method,
            route.path
        );
        assert!(
            mount_source.contains(&route.handler),
            "{} must mount {}",
            route.name,
            route.handler
        );
    }
}

#[test]
fn household_claw_contract_handlers_require_declared_auth() {
    let contract = contract();
    let handlers = include_str!("../src/handlers_household_claws.rs");

    assert!(
        handlers.contains(
            "const HOUSEHOLD_ATTACH_TOKEN_HEADER: &str = \"x-soyeht-household-attach-token\";"
        ),
        "attach token header constant must stay aligned with the contract"
    );
    assert_eq!(
        contract.attach_token_header.to_ascii_lowercase(),
        "x-soyeht-household-attach-token"
    );
    assert!(
        terminal_peer_rejection_body(handlers)
            .contains("post_trust_household_peer_gate(peer).await"),
        "terminal peer rejection must delegate to the shared live exposure gate"
    );

    for route in &contract.routes {
        let body = handler_body(handlers, &route.handler);
        match route.auth.as_str() {
            "pop" => {
                let operation = route
                    .operation
                    .as_deref()
                    .unwrap_or_else(|| panic!("{} must declare an operation", route.name));
                assert!(
                    body.contains(operation_variant(operation)),
                    "{} must authorize {}",
                    route.handler,
                    operation
                );
            }
            "attach_token" => {
                assert!(
                    route.operation.is_none(),
                    "{} attach-token route must not declare direct PoP operation",
                    route.name
                );
                assert!(
                    body.contains("household_terminal_pty"),
                    "{} must delegate to the attach-token PTY handler",
                    route.handler
                );
            }
            other => panic!("unknown auth kind in contract: {other}"),
        }

        if route.peer_guard {
            let expected_gate = match route.handler.as_str() {
                "handle_household_mint_attach_token" => {
                    "terminal_attach_peer_rejection(peer_addr(peer), \"mint_attach_token\").await"
                }
                "handle_household_terminal_pty" => {
                    "terminal_attach_peer_rejection(peer_addr(peer), \"terminal_pty\").await"
                }
                handler => panic!("unexpected peer-gated household handler: {handler}"),
            };
            assert!(
                body.contains(expected_gate),
                "{} must keep its declared shared peer gate",
                route.handler
            );
            let gate_index = body
                .find(expected_gate)
                .expect("declared peer gate must be present after assertion");
            let first_effect_index = match route.handler.as_str() {
                "handle_household_mint_attach_token" => body
                    .find("let authorized")
                    .expect("mint handler must retain PoP authorization"),
                "handle_household_terminal_pty" => body
                    .rfind("household_terminal_pty")
                    .expect("PTY handler must retain attach-token redemption"),
                handler => panic!("unexpected peer-gated household handler: {handler}"),
            };
            assert!(
                gate_index < first_effect_index,
                "{} must reject the peer before its authorization or attach-token effect",
                route.handler
            );
        }
    }
}
