//! P7-A — `PoP` / `Operation` gate-completeness guard.
//!
//! `claw_store_route_contract.rs` pins the four Claw Store *catalog* household
//! routes (list / availability / install / uninstall) against the declarative
//! `claw_store_routes::ROUTES` registry. The remaining household-namespaced
//! handlers (instances, workspaces, terminal) plus the owner add-machine
//! handlers are NOT in that registry, so this source-contract guard pins each of
//! them to its documented `Operation` caveat — or to an explicit, justified
//! non-PoP gate. It fails if a new household handler appears without a declared
//! caveat, so a missing gate cannot merge silently.
//!
//! Test-only: it asserts the existing source and changes no runtime behaviour.

use std::collections::BTreeSet;

const HANDLERS_HOUSEHOLD_CLAWS: &str = include_str!("../src/handlers_household_claws.rs");
const HANDLERS_OWNER_EVENTS: &str = include_str!("../src/handlers_owner_events.rs");

/// How a household handler is authenticated.
enum Gate {
    /// PoP-gated: the handler must call `authorize(...)` with this `Operation`.
    Pop(&'static str),
    /// PoP-gated and additionally requires the shared post-trust peer gate.
    PopAndPeer {
        operation: &'static str,
        peer_gate: &'static str,
    },
    /// PR1 owner-site wire: shared live transport gate followed only by an
    /// inert typed admission. It deliberately has no PoP/challenge/effect
    /// until the later owner-site slices are reviewed.
    PreEffectPeer {
        peer_gate: &'static str,
        admission: &'static str,
    },
    /// A2's separate WebSocket route: the same shared peer gate must reject
    /// before an optional typed provider or WebSocket upgrade.  It is not a
    /// current PoP/attach-token caveat and cannot create a principal in the
    /// M1/M2/M3-only slice.
    OwnerSiteAke {
        peer_gate: &'static str,
        provider_gate: &'static str,
        upgrade: &'static str,
    },
    /// Intentionally NOT a `PoP`-`Operation` caveat — gated by a different,
    /// documented mechanism (this marker substring must be present in the body).
    NonPop(&'static str),
}

/// Documented caveat per `handle_household_*` handler — the `SSoT` mirrors the
/// `handlers_household_claws.rs` module docs. This IS the explicit allowlist.
const HOUSEHOLD_CLAWS_GATES: &[(&str, Gate)] = &[
    (
        "handle_household_list_claws",
        Gate::Pop("Operation::ClawsList"),
    ),
    (
        "handle_household_claw_availability",
        Gate::Pop("Operation::ClawsList"),
    ),
    (
        "handle_household_install_claw",
        Gate::Pop("Operation::ClawsCreate"),
    ),
    (
        "handle_household_uninstall_claw",
        Gate::Pop("Operation::ClawsDelete"),
    ),
    (
        "handle_household_list_instances",
        Gate::Pop("Operation::ClawsList"),
    ),
    (
        "handle_household_create_instance",
        Gate::Pop("Operation::ClawsCreate"),
    ),
    (
        "handle_household_instance_status",
        Gate::Pop("Operation::ClawsList"),
    ),
    (
        "handle_household_list_workspaces",
        Gate::Pop("Operation::ClawsList"),
    ),
    (
        "handle_household_create_workspace",
        Gate::Pop("Operation::ClawsUse"),
    ),
    (
        "handle_household_rename_workspace",
        Gate::Pop("Operation::ClawsUse"),
    ),
    (
        "handle_household_delete_workspace",
        Gate::Pop("Operation::ClawsUse"),
    ),
    (
        "handle_household_mint_attach_token",
        Gate::PopAndPeer {
            operation: "Operation::ClawsUse",
            peer_gate: "terminal_attach_peer_rejection(peer_addr(peer), \"mint_attach_token\").await",
        },
    ),
    (
        "handle_household_owner_site_preflight",
        Gate::PreEffectPeer {
            peer_gate: "owner_site_pre_effect_peer_rejection(peer_addr(peer)).await",
            admission: "store.pre_effect_admission(&resource)",
        },
    ),
    (
        "handle_household_owner_site_ake",
        Gate::OwnerSiteAke {
            peer_gate: "owner_site_ake_peer_rejection(peer_addr(peer)).await",
            provider_gate: "provider.admits_resource(&resource)",
            upgrade: ".on_upgrade",
        },
    ),
    (
        "handle_household_stop_instance",
        Gate::Pop("Operation::ClawsUse"),
    ),
    (
        "handle_household_restart_instance",
        Gate::Pop("Operation::ClawsUse"),
    ),
    (
        "handle_household_rebuild_instance",
        Gate::Pop("Operation::ClawsUse"),
    ),
    (
        "handle_household_delete_instance",
        Gate::Pop("Operation::ClawsDelete"),
    ),
    // Non-PoP: the WebSocket terminal PTY upgrade is gated by the shared live
    // exposure/Ready-state peer gate (loopback/Tailnet or verified Mesh) + a
    // single-use attach token (minted by
    // `handle_household_mint_attach_token`, which IS `ClawsUse`-gated).
    // Intentionally not a PoP-`Operation` caveat.
    (
        "handle_household_terminal_pty",
        Gate::NonPop("terminal_attach_peer_rejection(peer_addr(peer), \"terminal_pty\").await"),
    ),
];

/// Owner add-machine handlers — all gated by `Operation::HouseholdAddMachine`.
const ADD_MACHINE_HANDLERS: &[&str] = &[
    "owner_events_long_poll",
    "push_token_register_handler",
    "owner_approve_handler",
    "owner_decline_handler",
];

/// Owner passkey initial enrollment is not delegable to add-machine caveats.
/// These handlers must use the explicit owner-only authorizer.
const OWNER_AUTH_ENROLL_INITIAL_HANDLERS: &[&str] = &[
    "owner_webauthn_registration_start_handler",
    "owner_webauthn_registration_finish_handler",
];

/// Source of a public or crate-private household handler up to the next top-level fn / test module.
fn handler_body<'a>(source: &'a str, name: &str) -> &'a str {
    let markers = [
        format!("pub async fn {name}"),
        format!("pub(crate) async fn {name}"),
    ];
    let (start, marker) = markers
        .iter()
        .filter_map(|marker| source.find(marker).map(|start| (start, marker)))
        .min_by_key(|(start, _)| *start)
        .unwrap_or_else(|| panic!("handler `{name}` not found in source"));
    let rest = &source[start + marker.len()..];
    let end = [
        "\npub async fn ",
        "\npub(crate) async fn ",
        "\npub fn ",
        "\n#[cfg(test)]",
    ]
    .iter()
    .filter_map(|m| rest.find(m))
    .min()
    .unwrap_or(rest.len());
    &rest[..end]
}

/// Names of every externally mounted `handle_household_*` in the source.
fn household_handler_names(source: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (prefix, needle) in [
        ("pub async fn ", "pub async fn handle_household_"),
        (
            "pub(crate) async fn ",
            "pub(crate) async fn handle_household_",
        ),
    ] {
        let mut from = 0;
        while let Some(idx) = source[from..].find(needle) {
            let at = from + idx + prefix.len();
            from = at;
            let tail = &source[at..];
            let end = tail.find('(').unwrap_or(tail.len());
            out.insert(tail[..end].trim().to_string());
        }
    }
    out
}

#[test]
fn every_household_claws_handler_enforces_its_caveat() {
    for (handler, gate) in HOUSEHOLD_CLAWS_GATES {
        let body = handler_body(HANDLERS_HOUSEHOLD_CLAWS, handler);
        match gate {
            Gate::Pop(op) => assert!(
                body.contains("authorize(") && body.contains(op),
                "{handler} must PoP-authorize {op}"
            ),
            Gate::PopAndPeer {
                operation,
                peer_gate,
            } => {
                assert!(
                    body.contains("authorize(")
                        && body.contains(operation)
                        && body.contains(peer_gate),
                    "{handler} must PoP-authorize {operation} and enforce its shared peer gate `{peer_gate}`"
                );
                assert!(
                    body.find(peer_gate)
                        .expect("peer gate must be present after assertion")
                        < body
                            .find("authorize(")
                            .expect("PoP authorization must be present after assertion"),
                    "{handler} must reject the peer before PoP authorization"
                );
            }
            Gate::PreEffectPeer {
                peer_gate,
                admission,
            } => {
                assert!(
                    body.contains(peer_gate) && body.contains(admission),
                    "{handler} must enforce shared peer gate `{peer_gate}` before typed admission `{admission}`"
                );
                assert!(
                    body.find(peer_gate)
                        .expect("peer gate must be present after assertion")
                        < body
                            .find(admission)
                            .expect("pre-effect admission must be present after assertion"),
                    "{handler} must reject the peer before pre-effect admission"
                );
                assert!(
                    !body.contains("authorize("),
                    "{handler} must not pretend a current PoP caveat is owner-site authority"
                );
                for forbidden in [
                    "household_mint_attach_token(",
                    "household_terminal_pty(",
                    ".consume(",
                    "TcpStream",
                    "connect(",
                ] {
                    assert!(
                        !body.contains(forbidden),
                        "{handler} PR1 pre-effect wire must not contain {forbidden}"
                    );
                }
            }
            Gate::OwnerSiteAke {
                peer_gate,
                provider_gate,
                upgrade,
            } => {
                assert!(
                    body.contains(peer_gate)
                        && body.contains(provider_gate)
                        && body.contains(upgrade),
                    "{handler} must enforce peer, typed-provider, and one-WebSocket A2 gates"
                );
                assert!(
                    body.find(peer_gate).expect("A2 peer gate")
                        < body.find(provider_gate).expect("A2 provider gate")
                        && body.find(provider_gate).expect("A2 provider gate")
                            < body.find(upgrade).expect("A2 upgrade"),
                    "{handler} must reject before provider work and before WebSocket upgrade"
                );
                for forbidden in [
                    "authorize(",
                    "HouseholdAttachTokenStore",
                    "GuestCredential",
                    "relay_stream",
                    "TcpStream",
                    "connect(",
                ] {
                    assert!(
                        !body.contains(forbidden),
                        "{handler} A2 route must not acquire {forbidden}"
                    );
                }
            }
            Gate::NonPop(marker) => assert!(
                body.contains(marker),
                "{handler} must enforce its documented non-PoP gate `{marker}`"
            ),
        }
    }
}

#[test]
fn no_household_claws_handler_is_missing_a_declared_gate() {
    let declared: BTreeSet<String> = HOUSEHOLD_CLAWS_GATES
        .iter()
        .map(|(h, _)| (*h).to_string())
        .collect();
    let actual = household_handler_names(HANDLERS_HOUSEHOLD_CLAWS);

    let undeclared: Vec<&String> = actual.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "household handler(s) without a declared caveat gate: {undeclared:?} — add each to \
         HOUSEHOLD_CLAWS_GATES with the correct Operation (or a justified non-PoP gate)"
    );

    let stale: Vec<&String> = declared.difference(&actual).collect();
    assert!(
        stale.is_empty(),
        "stale gate allowlist entries (handler removed): {stale:?}"
    );
}

#[test]
fn add_machine_handlers_enforce_household_add_machine() {
    for handler in ADD_MACHINE_HANDLERS {
        let body = handler_body(HANDLERS_OWNER_EVENTS, handler);
        assert!(
            body.contains("Operation::HouseholdAddMachine"),
            "{handler} must authorize Operation::HouseholdAddMachine"
        );
    }
}

#[test]
fn owner_auth_initial_enrollment_uses_dedicated_owner_authorizer() {
    for handler in OWNER_AUTH_ENROLL_INITIAL_HANDLERS {
        let body = handler_body(HANDLERS_OWNER_EVENTS, handler);
        assert!(
            body.contains("authorize_owner_auth_enroll_initial_request"),
            "{handler} must use the dedicated owner-auth enrollment authorizer"
        );
        assert!(
            !body.contains("Operation::HouseholdAddMachine"),
            "{handler} must not authorize initial owner passkey enrollment with add-machine caveats"
        );
    }
}
