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
        Gate::Pop("Operation::ClawsUse"),
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
    // Non-PoP: the WebSocket terminal PTY upgrade is gated by a peer-address
    // allowlist + a single-use attach token (minted by
    // `handle_household_mint_attach_token`, which IS `ClawsUse`-gated).
    // Intentionally not a PoP-`Operation` caveat.
    (
        "handle_household_terminal_pty",
        Gate::NonPop("is_terminal_attach_peer_allowed"),
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

/// Source of `pub async fn {name}` up to the next top-level fn / test module.
fn handler_body<'a>(source: &'a str, name: &str) -> &'a str {
    let marker = format!("pub async fn {name}");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("handler `{name}` not found in source"));
    let rest = &source[start + marker.len()..];
    let end = ["\npub async fn ", "\npub fn ", "\n#[cfg(test)]"]
        .iter()
        .filter_map(|m| rest.find(m))
        .min()
        .unwrap_or(rest.len());
    &rest[..end]
}

/// Names of every `pub async fn handle_household_*` in the source.
fn household_handler_names(source: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let prefix = "pub async fn ";
    let needle = "pub async fn handle_household_";
    let mut from = 0;
    while let Some(idx) = source[from..].find(needle) {
        let at = from + idx + prefix.len();
        from = at;
        let tail = &source[at..];
        let end = tail.find('(').unwrap_or(tail.len());
        out.insert(tail[..end].trim().to_string());
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
