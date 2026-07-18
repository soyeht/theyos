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
            "owner_site_ake" => {
                assert!(
                    route.operation.is_none(),
                    "{} A2 route must not repurpose a current PoP operation",
                    route.name
                );
                let peer_gate = "owner_site_ake_peer_rejection(peer_addr(peer)).await";
                let provider_gate = "provider.admits_resource(&resource)";
                let upgrade = ".on_upgrade";
                assert!(
                    body.contains(peer_gate)
                        && body.contains(provider_gate)
                        && body.contains(upgrade),
                    "{} must keep the shared peer gate, typed provider gate, and one WS upgrade",
                    route.handler
                );
                assert!(
                    body.find(peer_gate).expect("A2 peer gate")
                        < body.find(provider_gate).expect("A2 provider gate")
                        && body.find(provider_gate).expect("A2 provider gate")
                            < body.find(upgrade).expect("A2 upgrade"),
                    "{} must reject before provider admission and WebSocket upgrade",
                    route.handler
                );
                for forbidden in [
                    "authorize(",
                    "HouseholdAttachTokenStore",
                    "GuestCredential",
                    "relay_stream",
                    "Hermes",
                    "TcpStream",
                    "connect(",
                    "household_terminal_pty(",
                ] {
                    assert!(
                        !body.contains(forbidden),
                        "{} A2 handler must not acquire {forbidden}",
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
                "handle_household_owner_site_ake" => {
                    "owner_site_ake_peer_rejection(peer_addr(peer)).await"
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
                "handle_household_owner_site_ake" => body
                    .find("provider.admits_resource(&resource)")
                    .expect("A2 handler must retain typed provider admission"),
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
fn owner_site_ake_route_is_single_ws_record_aead_and_stays_pre_effect_after_c3() {
    let routes = include_str!("../src/claw_store_routes.rs");
    let bootstrap = include_str!("../src/household_bootstrap.rs");
    let handlers = include_str!("../src/handlers_household_claws.rs");
    let ake = include_str!("../src/owner_site_ake.rs");
    let lib = include_str!("../src/lib.rs");

    let route = contract()
        .routes
        .into_iter()
        .find(|route| route.name == "owner_site_ake")
        .expect("owner-site A2 route must be declared");
    assert_eq!(route.auth, "owner_site_ake");
    assert_eq!(route.method, "GET");
    assert_eq!(route.path, "/api/v1/household/claws/{name}/owner-site/ake");
    assert!(route.operation.is_none());
    assert!(
        routes.contains("household::OWNER_SITE_AKE")
            && routes.contains("handle_household_owner_site_ake"),
        "A2 must remain owned by claw_store_routes::household_routes"
    );
    assert!(
        !bootstrap.contains("owner_site_ake"),
        "A2 must not add bootstrap lifecycle or production provider wiring"
    );
    assert!(
        lib.contains("pub(crate) mod owner_site_ake;"),
        "the A2 state machine must remain crate-private server material"
    );

    let handler = handler_body(handlers, "handle_household_owner_site_ake");
    assert!(handler.contains("Option<Extension<Arc<OwnerSiteAkeProvider>>>"));
    assert!(handler.contains("WebSocketUpgrade"));
    assert!(handler.contains("provider.serve(socket, resource, peer).await"));
    let size_limit = handler
        .find("max_message_size(OWNER_SITE_AKE_MAX_RECORD_ENVELOPE_BYTES)")
        .expect("A2 must bound complete WebSocket messages before upgrade");
    let frame_limit = handler
        .find("max_frame_size(OWNER_SITE_AKE_MAX_RECORD_ENVELOPE_BYTES)")
        .expect("A2 must bound WebSocket frames before upgrade");
    let upgrade = handler
        .find(".on_upgrade")
        .expect("A2 must use one WebSocket upgrade");
    assert!(
        size_limit < upgrade && frame_limit < upgrade,
        "A2 record bounds must be installed before the WebSocket is upgraded"
    );
    assert_eq!(
        handler.matches(".on_upgrade").count(),
        1,
        "A2 must retain exactly one WebSocket upgrade; no second raw or post-login channel"
    );
    for forbidden in [
        "GuestCredential",
        "relay_stream",
        "Hermes",
        "TcpStream",
        "connect(",
        "household_attach_token",
    ] {
        assert!(
            !handler.contains(forbidden),
            "A2 handler must not acquire {forbidden}"
        );
    }
    for required in [
        "Noise_XXa2v1_25519_ChaChaPoly_SHA256",
        "NoiseParams::new(",
        "a2_noise_prologue",
        "a2_noise_builder",
        "bstr(canonical-CBOR(X))",
        "a2_r1_pretransport_kat_matches_normative_noise_and_binding_bytes",
        "a2_r1_transport_kat_matches_frozen_s2_c3_split_and_inverse_opens",
        "a2_r1_records_fail_closed_for_tamper_replay_direction_and_context_swaps",
        "a2_r1_rejects_raw_noncanonical_oversize_and_c3_before_s2",
        "assert_each_s2_wire_byte_is_terminal",
        "assert_each_c3_wire_byte_is_terminal",
        "A2_R1_SEMANTIC_CORPUS_V1_SHA256",
        "a2_r1_prologue_swap_fails_before_an_authenticated_m3",
        "a2_r1_profile_name_swap_fails_before_an_authenticated_m3",
        "soyeht/owner-site/a2/v1",
        "A2RecordEnvelope",
        "A2S2Plain",
        "A2C3Plain",
        "TransportState",
        "seal_a2_record",
        "open_a2_record",
        "s2_wire_hash",
        "OwnerSiteAkePendingFinished",
        "next_a2_binary",
        "A2_HARNESS_WS_STEP_TIMEOUT",
        "claim_after_verified_pop_for_harness",
        "pause_after_claim_for_harness",
        "pause_after_s2_for_harness",
        "post_claim_recheck_rejections",
        "post_c3_recheck_rejections",
        "completed_m3_closures",
        "dial_permits_issued",
        "post_trust_household_peer_gate(peer)",
        "certificate.verify(&self.expected_household_key)",
        "relay_forwarding_splices_only_a2_ciphertext_and_gets_no_peer_or_site_bytes",
        "tombstone_after_consume_burns_challenge_without_a_peer",
    ] {
        assert!(ake.contains(required), "A2 source must retain `{required}`");
    }
    assert!(
        !ake.contains("\"Noise_XX_25519_ChaChaPoly_SHA256\""),
        "A2 must not silently accept the unprofiled XX protocol name"
    );
    assert!(
        handlers.contains("owner_site_ake_uses_one_binary_ws_for_s2_c3_then_closes_pre_effect")
            && handlers
                .contains("owner_site_ake_route_real_rejects_raw_c3_and_closes_without_effects")
            && handlers.contains("owner_site_ake_route_real_c3_timeout_closes_without_effects")
            && handlers
                .contains("owner_site_ake_route_real_revoke_after_consume_closes_without_effects")
            && handlers.contains(
                "owner_site_ake_route_real_revoke_between_s2_and_c3_closes_without_effects"
            )
            && handlers.contains("record-confirmed pre-effect state must emit zero raw bytes")
            && handlers.contains("revoke must expose no raw site bytes"),
        "route-real A2 coverage must prove confirmed and both revoke intervals close without site bytes"
    );
    let emit_s2 = ake
        .find("pending.emit_s2()")
        .expect("A2 must emit the server-finished S2 record");
    let accept_c3 = ake
        .find("pending.accept_c3(&c3)")
        .expect("A2 must accept C3 only through pending record state");
    let final_recheck = ake
        .find("self.recheck_pending_finished(&pending)")
        .expect("A2 must recheck exact authority after C3");
    assert!(
        emit_s2 < accept_c3 && accept_c3 < final_recheck,
        "A2 must preserve S2 -> C3 -> final recheck order on the same WS"
    );
    assert!(
        ake.contains("#[cfg(test)]\n    #[must_use]\n    pub(crate) fn injected_for_harness")
            && ake.contains("#[cfg(not(test))]")
            && ake.contains("let _ = socket.close().await;"),
        "only the test harness may admit A2; production must remain fail-closed and close"
    );
    for forbidden in [
        "struct VerifiedMeshPeer",
        "enum VerifiedMeshPeer",
        "verified_peers.fetch_add",
        "dial_permits_issued.fetch_add",
        "struct DialPermit",
        "enum DialPermit",
        "DialPermit",
        "TcpStream",
        "connect(",
        "copy_bidirectional",
        "proxy_dials.fetch_add",
        "site_bytes.fetch_add",
        "set_receiving_nonce",
        "StatelessTransportState",
        "risky-raw-split",
        "rekey",
        "rekey_manual",
        "Hkdf",
        "HKDF",
        "chacha20poly1305",
        "Aead",
    ] {
        assert!(
            !ake.contains(forbidden),
            "the S2/C3 transport slice must not acquire deferred `{forbidden}` behavior"
        );
    }
}

#[test]
fn owner_site_promotion_skeleton_is_deny_only_and_unwired() {
    let promotion = include_str!("../src/owner_site_promotion.rs");
    let ake = include_str!("../src/owner_site_ake.rs");
    let handlers = include_str!("../src/handlers_household_claws.rs");
    let routes = include_str!("../src/claw_store_routes.rs");
    let bootstrap = include_str!("../src/household_bootstrap.rs");
    let lib = include_str!("../src/lib.rs");

    for required in [
        "pub(crate) struct VerifiedMeshPeer(VerifiedMeshPeerSeal);",
        "pub(crate) struct DialPermit(DialPermitSeal);",
        "pub(crate) struct OwnerSitePromotedChannel",
        "pub(crate) struct OwnerSitePromotionRequest(OwnerSitePromotionRequestSeal);",
        "#[cfg(test)]\nimpl OwnerSitePromotionRequest",
        "ContractUnavailable",
        "Err(OwnerSitePromotionRejection::ContractUnavailable)",
        "promotion_boundary_is_deny_only_before_the_data_plane_contract",
    ] {
        assert!(
            promotion.contains(required),
            "the inert promotion skeleton must retain `{required}`"
        );
    }
    assert!(
        promotion.contains("#[derive(Debug, Eq, PartialEq)]\npub(crate) struct VerifiedMeshPeer")
            && promotion.contains("#[derive(Debug, Eq, PartialEq)]\npub(crate) struct DialPermit"),
        "peer and permit must remain opaque and non-clonable"
    );
    assert_eq!(
        promotion.matches("VerifiedMeshPeer(").count(),
        1,
        "the inert skeleton must not construct a mesh peer"
    );
    assert_eq!(
        promotion.matches("DialPermit(").count(),
        1,
        "the inert skeleton must not construct a dial permit"
    );
    assert_eq!(
        promotion.matches("pub(crate) fn").count(),
        1,
        "the boundary must expose only its deny-only promotion attempt"
    );
    assert!(
        !promotion.contains("Ok("),
        "the deny-only skeleton must not report a promotion success"
    );
    assert!(
        lib.contains("pub(crate) mod owner_site_promotion;"),
        "the promotion boundary must remain an explicit crate-private module"
    );
    assert!(
        !ake.contains("owner_site_promotion") && !handlers.contains("owner_site_promotion"),
        "the A2 route must still close after C3 without wiring peer promotion"
    );
    assert!(
        !routes.contains("owner_site_promotion"),
        "peer promotion must not register a route in this inert slice"
    );
    assert!(
        !bootstrap.contains("owner_site_promotion"),
        "peer promotion must not enter household bootstrap wiring"
    );
    for forbidden in [
        "impl VerifiedMeshPeer",
        "impl DialPermit",
        "SocketAddr",
        "ConnectInfo",
        "IpAddr",
        "CIDR",
        "10.44",
        "TcpStream",
        "connect(",
        "copy_bidirectional",
        "WebSocket",
        "Router",
        "Extension<",
        "Serialize",
        "Deserialize",
        "serde",
        "GuestCredential",
        "household_attach_token",
        "relay_stream",
        "Hermes",
        "proxy_dials.fetch_add",
        "site_bytes.fetch_add",
        "verified_peers.fetch_add",
        "dial_permits_issued.fetch_add",
        "fetch_add",
    ] {
        assert!(
            !promotion.contains(forbidden),
            "the inert promotion skeleton must not acquire `{forbidden}`"
        );
    }
}

#[test]
fn owner_site_pre_effect_route_is_router_only_and_capability_sibling() {
    let routes = include_str!("../src/claw_store_routes.rs");
    let bootstrap = include_str!("../src/household_bootstrap.rs");
    let capability = include_str!("../src/owner_site_capability.rs");
    let authority = include_str!("../src/owner_site_authority.rs");
    let challenge = include_str!("../src/owner_site_challenge.rs");
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
        lib.contains("pub(crate) mod owner_site_authority;")
            && lib.contains("pub(crate) mod owner_site_challenge;"),
        "pre-effect A2 authority/challenge shapes must stay crate-private server-owned material"
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
    assert!(
        capability.contains("challenge_issues: AtomicUsize")
            && capability.contains("challenge_claims: AtomicUsize"),
        "the route-real harness must keep explicit zero challenge issue/claim probes"
    );
    assert!(
        !capability.contains("use crate::owner_site_challenge"),
        "the inert preflight capability must not acquire the A2 challenge table"
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

    assert!(
        !handler.contains("owner_site_challenge"),
        "the inert preflight handler must not issue or claim an A2 challenge"
    );
    assert!(
        challenge.contains("#[cfg(test)]\npub(crate) struct OwnerSiteChallengeTable")
            && challenge.contains("Sha256::digest")
            && challenge.contains("ct_eq"),
        "the B+C table must be test-only here and retain only a constant-time checked hash"
    );
    for source in [authority, challenge] {
        for forbidden in [
            "use axum",
            "TcpStream",
            "TcpListener",
            "tokio::net",
            "GuestCredential",
            "relay_stream",
            "Hermes",
            "household_attach_token",
            "connect(",
            "write_all(",
            "copy_bidirectional",
        ] {
            assert!(
                !source.contains(forbidden),
                "pre-effect owner-site authority/challenge shapes must not acquire {forbidden}"
            );
        }
    }
    assert!(
        authority.contains("pub(crate) struct PendingFinished {")
            && authority.contains("pub(crate) struct AuthenticatedConfidentialChannel {")
            && authority.contains("pub(crate) struct Pending {")
            && authority.contains("pub(crate) struct Promoted {")
            && authority.contains("pub(crate) struct Dialing {")
            && authority.contains("pub(crate) struct Pumping {")
            && authority.contains("pub(crate) struct Closing {")
            && authority.contains("pub(crate) struct Revoking {")
            && authority.contains("pub(crate) struct Closed {")
            && authority.contains("owner_site_transition_is_allowed")
            && authority.contains("compare_owner_site_generations"),
        "the authority sibling must carry the inert Pending/state graph and pure helpers"
    );
    for forbidden in [
        "VerifiedMeshPeer(",
        "DialPermit(",
        "fn promote",
        "impl Promoted",
        "impl Dialing",
        "impl Pumping",
    ] {
        assert!(
            !authority.contains(forbidden),
            "the pre-effect authority must not acquire a promotion path: {forbidden}"
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

#[test]
fn owner_site_pending_finished_is_sealed_inert_and_non_promoting() {
    let authority = include_str!("../src/owner_site_authority.rs");
    let start = authority
        .find("pub(crate) struct PendingFinished {")
        .expect("production PendingFinished type must exist");
    let rest = &authority[start..];
    let declaration_end = rest
        .find("\n}\n\nimpl std::fmt::Debug for PendingFinished")
        .expect("PendingFinished must have a custom Debug implementation");
    let declaration = &rest[..declaration_end + 2];
    let prefix = &authority[start.saturating_sub(160)..start];

    assert!(
        !prefix.contains("#[derive("),
        "PendingFinished must not inherit a derived Debug/Clone/serde path"
    );
    for field in [
        "household: HouseholdId",
        "exact_resource: OwnerSiteResource",
        "exact_route: OwnerSiteCanonicalRequest",
        "machine_cert: MachineCert",
        "device_binding: MemberDeviceBinding",
        "principal_d: OwnerSiteRemotePrincipal",
        "ws_instance: OwnerSiteWebSocketInstance",
        "channel_id: OwnerSiteChannelId",
        "channel_epoch: OwnerSiteChannelEpoch",
        "channel_binding: [u8; 32]",
        "authz_epoch: NonZeroU64",
        "roster_digest: [u8; 32]",
        "fresh_until: u64",
        "provider_generation: u64",
        "cancellation_generation: u64",
    ] {
        assert!(
            declaration.contains(field),
            "PendingFinished must retain private tuple field {field}"
        );
    }
    assert_eq!(
        declaration
            .lines()
            .filter(|line| line.contains(':'))
            .count(),
        15,
        "PendingFinished must contain exactly the complete 15-field tuple"
    );
    assert!(
        declaration
            .lines()
            .skip(1)
            .all(|line| !line.trim_start().starts_with("pub")),
        "every PendingFinished tuple field must remain private"
    );

    let pending_impl_start = authority
        .find("impl PendingFinished {")
        .expect("PendingFinished implementation must exist");
    let pending_impl_rest = &authority[pending_impl_start..];
    let pending_impl_end = pending_impl_rest
        .find("\n}\n\n/// Non-forgeable app-layer proof")
        .expect("PendingFinished implementation must end before the channel proof");
    let pending_impl = &pending_impl_rest[..pending_impl_end + 2];
    assert!(
        pending_impl.contains(
            "#[cfg(test)]\n    #[allow(clippy::too_many_arguments)]\n    pub(crate) fn injected_for_harness("
        ),
        "only crate tests may construct PendingFinished in this slice"
    );
    for forbidden in [
        "pub fn ",
        "pub(crate) fn new",
        "&mut self",
        "Serialize",
        "Deserialize",
        "Default",
        "impl Clone",
        "impl From",
        "impl TryFrom",
    ] {
        assert!(
            !pending_impl.contains(forbidden),
            "PendingFinished must not acquire construction or mutation path {forbidden}"
        );
    }
    assert!(
        authority.contains("formatter.write_str(\"PendingFinished(REDACTED)\")")
            && authority
                .contains("formatter.write_str(\"AuthenticatedConfidentialChannel(REDACTED)\")"),
        "PendingFinished and its channel proof must use custom redacted Debug"
    );
    assert_eq!(
        authority
            .matches("\npub(crate) struct PendingFinished {")
            .count(),
        1,
        "only the type declaration may name a PendingFinished struct literal"
    );
    assert_eq!(
        authority.matches("\npub(crate) struct Promoted {").count(),
        1,
        "Promoted must exist only as a type declaration in this slice"
    );
    assert!(
        authority.contains("pub(crate) struct Promoted {\n    channel: OwnerSitePromotedChannel,"),
        "Promoted must carry the existing atomic peer/permit carrier without constructing it"
    );
    assert_eq!(
        authority.matches("\npub(crate) struct Dialing {").count(),
        1,
        "Dialing must exist only as a type declaration in this slice"
    );
    assert_eq!(
        authority.matches("\npub(crate) struct Pumping {").count(),
        1,
        "Pumping must exist only as a type declaration in this slice"
    );
    assert!(
        authority.contains(
            "#[cfg(test)]\n    pub(crate) fn injected_for_harness(\n        ws_instance: OwnerSiteWebSocketInstance"
        ),
        "the channel proof must remain constructible only by crate tests"
    );
    for forbidden in [
        "VerifiedMeshPeer(",
        "DialPermit(",
        "fn promote",
        "impl Promoted",
        "impl Dialing",
        "impl Pumping",
        "use axum",
        "TcpStream",
        "TcpListener",
        "tokio::net",
        "connect(",
        "write_all(",
        "copy_bidirectional",
        "fn mint",
        "fn consume",
    ] {
        assert!(
            !authority.contains(forbidden),
            "the inert Pending graph must not acquire {forbidden}"
        );
    }
}
