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
    let markers = [
        format!("pub async fn {handler}"),
        format!("pub(crate) async fn {handler}"),
    ];
    let (start, marker) = markers
        .iter()
        .filter_map(|marker| source.find(marker).map(|start| (start, marker)))
        .min_by_key(|(start, _)| *start)
        .unwrap_or_else(|| panic!("handler {handler} must exist"));
    let rest = &source[start + marker.len()..];
    let end = [
        "\npub async fn ",
        "\npub(crate) async fn ",
        "\n#[cfg(test)]",
    ]
    .iter()
    .filter_map(|marker| rest.find(marker))
    .min()
    .unwrap_or(rest.len());
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
            "owner_site_pre_effect" => {
                assert!(
                    route.operation.is_none(),
                    "{} pre-effect owner-site route must not repurpose a current PoP operation",
                    route.name
                );
                let peer_gate = "owner_site_pre_effect_peer_rejection(peer_addr(peer)).await";
                let admission = "store.pre_effect_admission(&resource)";
                assert!(
                    body.contains(peer_gate) && body.contains(admission),
                    "{} must keep the shared peer gate and typed pre-effect admission",
                    route.handler
                );
                assert!(
                    body.find(peer_gate)
                        .expect("owner-site peer gate must be present")
                        < body
                            .find(admission)
                            .expect("owner-site admission must be present"),
                    "{} must reject the peer before capability admission",
                    route.handler
                );
                for forbidden in [
                    "authorize(",
                    "household_mint_attach_token(",
                    "household_terminal_pty(",
                    ".consume(",
                    "TcpStream",
                    "connect(",
                ] {
                    assert!(
                        !body.contains(forbidden),
                        "{} PR1 pre-effect handler must not contain {forbidden}",
                        route.handler
                    );
                }
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
                "handle_household_owner_site_preflight" => {
                    "owner_site_pre_effect_peer_rejection(peer_addr(peer)).await"
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
                "handle_household_owner_site_preflight" => body
                    .find("store.pre_effect_admission(&resource)")
                    .expect("owner-site handler must retain typed pre-effect admission"),
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

#[test]
fn owner_site_pre_effect_route_is_router_only_and_capability_sibling() {
    let routes = include_str!("../src/claw_store_routes.rs");
    let bootstrap = include_str!("../src/household_bootstrap.rs");
    let capability = include_str!("../src/owner_site_capability.rs");
    let handlers = include_str!("../src/handlers_household_claws.rs");
    let lib = include_str!("../src/lib.rs");

    let route = contract()
        .routes
        .into_iter()
        .find(|route| route.name == "owner_site_preflight")
        .expect("owner-site pre-effect route must be declared");
    assert_eq!(route.auth, "owner_site_pre_effect");
    assert!(route.operation.is_none());
    assert_eq!(
        route.path,
        "/api/v1/household/claws/{name}/owner-site/preflight"
    );
    assert!(
        routes.contains("household::OWNER_SITE_PREFLIGHT")
            && routes.contains("handle_household_owner_site_preflight"),
        "owner-site route must be owned by claw_store_routes::household_routes"
    );
    assert!(
        !bootstrap.contains("owner_site"),
        "PR1 must not add owner-site lifecycle or routing to household_bootstrap"
    );
    assert!(
        lib.contains("pub(crate) mod owner_site_capability;"),
        "owner-site capability types must stay crate-private server-owned material"
    );
    assert!(
        capability.contains("#[cfg(test)]\n    pub(crate) fn injected_for_harness"),
        "only crate tests may construct an admitting owner-site capability in PR1"
    );
    assert!(
        capability.contains("effects: Arc<OwnerSiteEffectCounters>")
            && capability.contains("self.effects.record_pre_effect_admission()"),
        "the route-real harness counters must be attached to the injected provider"
    );

    let handler = handler_body(handlers, "handle_household_owner_site_preflight");
    for forbidden in [
        "HouseholdAttachTokenStore",
        "GuestCredential",
        "relay_stream",
        "Hermes",
        "TcpListener",
        "spawn_household_listeners",
        "bonjour",
    ] {
        assert!(
            !handler.contains(forbidden),
            "owner-site pre-effect handler must not acquire {forbidden}"
        );
    }
    for forbidden in [
        "household_attach_token",
        "GuestCredential",
        "relay_stream",
        "Hermes",
        "TcpStream",
        "TcpListener",
        "tokio::net",
        "connect(",
        "fn mint",
        "fn consume",
        "fn bind",
        "write_all(",
        "copy_bidirectional",
    ] {
        assert!(
            !capability.contains(forbidden),
            "owner-site capability family must remain effect-free and not reuse {forbidden}"
        );
    }

    let route_start = routes
        .find("pub fn household_routes()")
        .expect("household route owner must exist");
    let route_slice = &routes[route_start..];
    for forbidden in ["TcpListener", "bind_", "spawn_household", "bonjour"] {
        assert!(
            !route_slice.contains(forbidden),
            "owner-site registration must not create a listener or discovery side effect: {forbidden}"
        );
    }
}
