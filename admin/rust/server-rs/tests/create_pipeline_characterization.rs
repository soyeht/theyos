//! PR-2a characterization guards for the two create pipelines.
//!
//! These pin the CURRENT (pre-extraction) source shape of the admin
//! (`handle_create_instance_body`) and mobile/household
//! (`create_mobile_instance_for_actor`) create paths so PR-2b's
//! `create_instance_core` extraction is provably behavior-preserving. They are
//! deliberately NARROW source-text scans of specific existing regions, not broad
//! scans that give false confidence.
//!
//! DEFERRED (by design): a behavioral rollback/lease e2e test (insert -> force a
//! later-step failure -> assert the warm-pool lease is restored) needs replicating
//! the heavy `shared_state()`/`AppState` harness (env + fake IPC bins + tempdirs +
//! ~20 fields). These guards protect the rollback WIRING / source shape only,
//! until PR-2b.

use std::fs;
use std::path::Path;

fn src(file: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// The body of `sig`, bounded to the next top-level fn declaration.
fn fn_body(source: &str, sig: &str) -> String {
    let start = source
        .find(sig)
        .unwrap_or_else(|| panic!("missing fn: {sig}"));
    let rest = &source[start + sig.len()..];
    let end = [
        "\npub async fn ",
        "\npub(crate) async fn ",
        "\nasync fn ",
        "\npub fn ",
        "\nfn ",
    ]
    .iter()
    .filter_map(|m| rest.find(m))
    .min()
    .map_or(rest.len(), |i| i);
    source[start..start + sig.len() + end].to_string()
}

const ADMIN: &str = "pub async fn handle_create_instance_body";
const MOBILE: &str = "pub(crate) async fn create_mobile_instance_for_actor";

// ── converged drifts (PR-2a behavior change) ────────────────────────────────

#[test]
fn both_create_paths_use_the_shared_length_consts() {
    for file in ["handlers_instances.rs", "handlers_mobile.rs"] {
        let s = src(file);
        assert!(
            s.contains("MAX_NAME_LEN") && s.contains("MAX_CLAW_TYPE_LEN"),
            "{file} must use the shared MAX_NAME_LEN/MAX_CLAW_TYPE_LEN consts (no per-surface drift)"
        );
    }
    // The mobile create path must not reuse the old bare 64/32 literals.
    let mobile = fn_body(&src("handlers_mobile.rs"), MOBILE);
    assert!(
        !mobile.contains("len() > 64") && !mobile.contains("len() > 32"),
        "mobile create must reference the shared consts, not bare 64/32"
    );
}

#[test]
fn availability_copy_is_converged_across_both_paths() {
    for needle in [
        "is not installed — install it from the claw store first",
        "— wait for it to finish",
        "no base rootfs or golden image available on this host",
    ] {
        for file in ["handlers_instances.rs", "handlers_mobile.rs"] {
            assert!(
                src(file).contains(needle),
                "{file} must carry the converged availability copy: {needle:?}"
            );
        }
    }
    // The old mobile-only string is gone.
    assert!(
        !src("handlers_mobile.rs").contains("host rootfs missing"),
        "the old mobile-only 'host rootfs missing' copy must be converged away"
    );
}

// ── divergences PR-2b must PRESERVE (pinned now) ────────────────────────────

#[test]
fn rate_limit_429_richness_diverges_admin_rich_mobile_bare() {
    // Admin enriches the 429 with X-RateLimit-Remaining (+ Retry-After:3600);
    // mobile/household return a bare 429. PR-2b must preserve this per-surface.
    let admin = fn_body(&src("handlers_instances.rs"), ADMIN);
    assert!(
        admin.contains("X-RateLimit-Remaining"),
        "admin 429 keeps its X-RateLimit-Remaining header"
    );
    let mobile = fn_body(&src("handlers_mobile.rs"), MOBILE);
    assert!(
        !mobile.contains("X-RateLimit-Remaining"),
        "mobile/household 429 stays bare (no X-RateLimit-Remaining)"
    );
}

#[test]
fn household_scope_is_stamped_only_on_the_mobile_household_path() {
    // The mobile/household path DERIVES household_id/household_machine_id from the
    // PoP household_scope; the admin path stamps them None. PR-2b must keep the
    // scope threading on the household path only.
    let mobile = fn_body(&src("handlers_mobile.rs"), MOBILE);
    assert!(
        mobile.contains("scope.household_id") && mobile.contains("scope.household_machine_id"),
        "the mobile/household path must derive household_id/household_machine_id from household_scope"
    );
    let admin = fn_body(&src("handlers_instances.rs"), ADMIN);
    assert!(
        admin.contains("household_machine_id: None"),
        "the admin path must stamp household_machine_id: None (no household scope)"
    );
}

#[test]
fn admin_capacity_lock_orders_host_detect_then_lock_then_check_then_insert() {
    let admin = fn_body(&src("handlers_instances.rs"), ADMIN);
    let detect = admin
        .find("host_resources::detect_all")
        .expect("admin detects host resources");
    let lock = admin
        .find("capacity_lock.lock")
        .expect("admin takes the capacity lock");
    // The CALL (crate::capacity::check_capacity(...)), not the doc-comment mention.
    let check = admin
        .find("crate::capacity::check_capacity(")
        .expect("admin checks capacity");
    let insert = admin
        .find("insert_with")
        .expect("admin inserts the instance");
    assert!(
        detect < lock && lock < check && check < insert,
        "host detect must precede the capacity lock; check_capacity + insert must run under it \
         (order: detect < lock < check < insert)"
    );
}

#[test]
fn both_paths_roll_back_owner_and_job_failures_with_warm_pool_arg() {
    // NARROW: pin the two existing rollback failure sites (owner assignment, job
    // creation) carry use_warm_pool on BOTH paths — the atomicity PR-2b preserves.
    for (file, sig) in [
        ("handlers_instances.rs", ADMIN),
        ("handlers_mobile.rs", MOBILE),
    ] {
        let body = fn_body(&src(file), sig);
        assert!(
            body.contains("rollback_inserted_instance"),
            "{file} must roll back inserted instances on a later-step failure"
        );
        for needle in [
            "\"owner assignment\", use_warm_pool",
            "\"job creation\", use_warm_pool",
        ] {
            assert!(
                body.contains(needle),
                "{file}: the create path must roll back the {needle} failure site"
            );
        }
    }
}
