//! P7-C (PR-A) — rate-limit coverage guard. Test-only; no runtime change, no 429.
//!
//! Pins the CURRENT rate-limit coverage so it cannot silently regress:
//!  * the create-instance surfaces stay behind the limiter;
//!  * household create-instance keeps inheriting the limiter by delegating to
//!    `create_mobile_instance_for_actor`;
//!  * NO new `rate_limiter.check(...)` site can appear without updating the
//!    classification table below (forcing a coverage decision); a removed one is
//!    flagged as a protection regression;
//!  * every sensitive/mutating endpoint is classified in `COVERAGE` (the P7-C
//!    inventory `SSoT`): `RateLimited` / inherited / PoP-only / loopback-only /
//!    token-or-secret-gated / state-gated / admin-only.
//!
//! This asserts EXISTING behaviour only. It adds no limiter call, no 429, and
//! changes no handler/auth/status/body/wire. Wiring an actual limiter onto any
//! of the PoP-only / token-gated candidates is a separate, approval-gated PR.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(file: &str) -> String {
    fs::read_to_string(src_dir().join(file)).unwrap_or_else(|e| panic!("read src/{file}: {e}"))
}

fn rs_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![src_dir()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out
}

/// Actions passed to a `rate_limiter ... .check(..., "ACTION")` call in `source`.
/// Window-scans after each `rate_limiter` token so it is robust to the call
/// being line-wrapped, and ignores non-`.check(` uses (e.g. `.get_remaining`).
fn limiter_check_actions(source: &str) -> Vec<String> {
    let mut actions = Vec::new();
    let mut from = 0;
    while let Some(idx) = source[from..].find("rate_limiter") {
        let at = from + idx;
        from = at + "rate_limiter".len();
        let window = &source[at..(at + 200).min(source.len())];
        let Some(check_pos) = window.find(".check(") else {
            continue;
        };
        let after = &window[check_pos..];
        if let Some(q1) = after.find('"') {
            if let Some(q2) = after[q1 + 1..].find('"') {
                actions.push(after[q1 + 1..q1 + 1 + q2].to_string());
            }
        }
    }
    actions
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// Directly behind the limiter with this action string.
    RateLimited(&'static str),
    /// Inherits the limiter by delegating to a rate-limited helper fn.
    RateLimitedViaInheritance(&'static str),
    /// owner-PoP caveat gated, NOT rate-limited (a P7-C candidate for a future,
    /// approval-gated limiter PR).
    PoPOnly(&'static str),
    /// Bound to the loopback interface only (not remotely reachable).
    LoopbackOnly,
    /// Gated by a high-entropy token / anchor secret / nonce.
    TokenOrSecretGated,
    /// Only reachable in a specific bootstrap state (state gate).
    StateGated,
    /// Behind the `AdminUser` session auth (requires admin credentials).
    AdminOnly,
}

/// P7-C coverage `SSoT`. Adding a new auth-sensitive MUTATING endpoint? Classify
/// it here. A new `rate_limiter.check` site that is not reflected here will fail
/// `limiter_check_sites_are_exactly_the_classified_set`.
const COVERAGE: &[(&str, &str, Class)] = &[
    // --- Rate-limited today (action "create_instance", 3 entrypoints) ---
    (
        "handle_create_instance_body",
        "handlers_instances.rs",
        Class::RateLimited("create_instance"),
    ),
    (
        "create_mobile_instance_for_actor",
        "handlers_mobile.rs",
        Class::RateLimited("create_instance"),
    ),
    (
        "handle_household_create_instance",
        "handlers_household_claws.rs",
        Class::RateLimitedViaInheritance("create_mobile_instance_for_actor"),
    ),
    // --- owner-PoP gated, currently NOT rate-limited (limiter candidates) ---
    (
        "handle_household_install_claw",
        "handlers_household_claws.rs",
        Class::PoPOnly("ClawsCreate"),
    ),
    (
        "handle_household_uninstall_claw",
        "handlers_household_claws.rs",
        Class::PoPOnly("ClawsDelete"),
    ),
    (
        "sign_machine_cert_handler",
        "handlers_sign_machine_cert.rs",
        Class::PoPOnly("HouseholdAddMachine"),
    ),
    (
        "owner_approve_handler",
        "handlers_owner_events.rs",
        Class::PoPOnly("HouseholdAddMachine"),
    ),
    (
        "owner_decline_handler",
        "handlers_owner_events.rs",
        Class::PoPOnly("HouseholdAddMachine"),
    ),
    // --- Intentionally unlimited: gated by other mechanisms ---
    (
        "post_claim_setup_invitation",
        "handlers_bootstrap.rs",
        Class::TokenOrSecretGated,
    ),
    (
        "post_accept_household",
        "handlers_bootstrap.rs",
        Class::TokenOrSecretGated,
    ),
    (
        "post_initialize",
        "handlers_bootstrap.rs",
        Class::StateGated,
    ),
    (
        "post_pair_machine_local_stage",
        "handlers_bootstrap.rs",
        Class::LoopbackOnly,
    ),
    (
        "local_anchor_handler",
        "handlers_pair_machine.rs",
        Class::TokenOrSecretGated,
    ),
    (
        "handle_warm_pool_refill",
        "handlers_admin.rs",
        Class::AdminOnly,
    ),
    (
        "handle_create_invite",
        "handlers_invites.rs",
        Class::AdminOnly,
    ),
];

#[test]
fn create_instance_surfaces_remain_rate_limited() {
    for file in ["handlers_instances.rs", "handlers_mobile.rs"] {
        let actions = limiter_check_actions(&read(file));
        assert!(
            actions.iter().any(|a| a == "create_instance"),
            "{file} must keep the create_instance rate-limit check"
        );
    }
}

#[test]
fn household_create_instance_inherits_the_limiter() {
    let src = read("handlers_household_claws.rs");
    let start = src
        .find("pub async fn handle_household_create_instance")
        .expect("handle_household_create_instance must exist");
    let body = &src[start..(start + 1500).min(src.len())];
    assert!(
        body.contains("create_mobile_instance_for_actor("),
        "handle_household_create_instance must delegate to the rate-limited \
         create_mobile_instance_for_actor (otherwise household create-instance loses the limiter)"
    );
}

#[test]
fn limiter_check_sites_are_exactly_the_classified_set() {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in rs_files() {
        let source = fs::read_to_string(&path).unwrap();
        let actions = limiter_check_actions(&source);
        if !actions.is_empty() {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            found.entry(name).or_default().extend(actions);
        }
    }
    for actions in found.values_mut() {
        actions.sort();
    }

    let mut expected: BTreeMap<String, Vec<String>> = BTreeMap::new();
    expected.insert(
        "handlers_instances.rs".to_string(),
        vec!["create_instance".to_string()],
    );
    expected.insert(
        "handlers_mobile.rs".to_string(),
        vec!["create_instance".to_string()],
    );

    assert_eq!(
        found, expected,
        "rate_limiter.check sites changed. A NEW limiter site must be added to COVERAGE \
         (and reviewed for the right scope/threshold via the approval-gated PR); a REMOVED one is \
         a protection regression. found={found:?}"
    );
}

#[test]
fn coverage_table_is_not_stale_and_rate_limited_entries_are_proven() {
    for (handler, file, class) in COVERAGE {
        let src = read(file);
        assert!(
            src.contains(&format!("fn {handler}")),
            "COVERAGE lists `{handler}` in {file} but it is not found there — the table is stale"
        );
        match *class {
            Class::RateLimited(action) => assert!(
                limiter_check_actions(&src).iter().any(|a| a == action),
                "{handler} ({file}) is classified RateLimited({action}) but no such limiter check is present"
            ),
            Class::RateLimitedViaInheritance(via) => assert!(
                src.contains(&format!("{via}(")),
                "{handler} ({file}) is classified as inheriting the limiter via {via} but does not call it"
            ),
            // PoP-only / loopback / token-gated / state-gated / admin-only are
            // documentation of the current (unlimited-by-the-limiter) state; no
            // source assertion beyond the handler existing.
            _ => {}
        }
    }
}
