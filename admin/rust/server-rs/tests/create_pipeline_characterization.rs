//! PR-2b characterization guards for the shared create pipeline.
//!
//! After the PR-2b extraction the create logic lives in
//! `instance_create::create_instance_core`; the admin / mobile / household
//! handlers are thin adapters. These NARROW source scans pin the post-extraction
//! architecture: the moved logic (length consts, availability copy, 429 richness,
//! household-scope stamping, capacity-lock ordering, rollback wiring) lives in the
//! core, while the per-surface response envelopes stay in the adapters (pinned by
//! `admin_guest_image_gate_guard::create_response_envelopes_stay_distinct_for_pr2`).

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
const CORE: &str = "pub(crate) async fn create_instance_core";

/// The `create_instance_core` body, excluding the in-file `#[cfg(test)]` module.
fn core_body() -> String {
    let s = src("instance_create.rs");
    let prod = s.split("#[cfg(test)]").next().unwrap_or(&s).to_string();
    fn_body(&prod, CORE)
}

#[test]
fn length_consts_are_shared_and_used_in_the_core() {
    let s = src("instance_create.rs");
    assert!(
        s.contains("MAX_NAME_LEN") && s.contains("MAX_CLAW_TYPE_LEN"),
        "instance_create.rs must define + use the shared length consts"
    );
    assert!(
        core_body().contains("MAX_NAME_LEN") && core_body().contains("MAX_CLAW_TYPE_LEN"),
        "create_instance_core must validate name/claw length via the shared consts"
    );
    // No bare 64/32 literals reintroduced on any create surface.
    for file in [
        "instance_create.rs",
        "handlers_mobile.rs",
        "handlers_instances.rs",
    ] {
        let f = src(file);
        assert!(
            !f.contains("len() > 64") && !f.contains("len() > 32"),
            "{file} must use the shared consts, not bare 64/32"
        );
    }
}

#[test]
fn availability_copy_lives_once_in_the_core() {
    let core = core_body();
    for needle in [
        "is not installed — install it from the claw store first",
        "— wait for it to finish",
        "no base rootfs or golden image available on this host",
    ] {
        assert!(
            core.contains(needle),
            "create_instance_core must carry the converged availability copy: {needle:?}"
        );
    }
    // The old mobile-only string is gone everywhere.
    assert!(!src("handlers_mobile.rs").contains("host rootfs missing"));
    assert!(!src("instance_create.rs").contains("host rootfs missing"));
}

#[test]
fn rate_limit_429_richness_diverges_admin_rich_mobile_bare() {
    // The 429 richness lives in the core's rate_limited_response (Rich keeps the
    // X-RateLimit-Remaining header, Bare does not); each adapter selects its style.
    let s = src("instance_create.rs");
    assert!(
        s.contains("X-RateLimit-Remaining"),
        "the core's Rich 429 keeps X-RateLimit-Remaining"
    );
    assert!(
        s.contains("enum RateLimitResponseStyle"),
        "the core defines the per-surface 429 style"
    );
    assert!(
        fn_body(&src("handlers_instances.rs"), ADMIN).contains("RateLimitResponseStyle::Rich"),
        "admin adapter selects the Rich 429 style"
    );
    assert!(
        fn_body(&src("handlers_mobile.rs"), MOBILE).contains("RateLimitResponseStyle::Bare"),
        "mobile/household adapter selects the Bare 429 style"
    );
}

#[test]
fn household_scope_is_stamped_by_the_core_only_when_present() {
    assert!(
        core_body().contains("household_scope.map("),
        "the core threads household_id/household_machine_id from household_scope onto the row"
    );
    // Admin passes None; mobile/household pass the scope through. The admin None
    // is checked in a bounded window around the create_instance_core(...) call so
    // an unrelated `None` elsewhere in the adapter cannot satisfy it.
    let admin = fn_body(&src("handlers_instances.rs"), ADMIN);
    let call = admin
        .find("create_instance_core(")
        .expect("admin adapter must call create_instance_core");
    let window = &admin[call..(call + 240).min(admin.len())];
    assert!(
        window.contains("None,") && window.contains("RateLimitResponseStyle::Rich"),
        "admin adapter must pass household_scope = None (+ Rich style) to create_instance_core"
    );
    assert!(
        fn_body(&src("handlers_mobile.rs"), MOBILE).contains("household_scope.as_ref()"),
        "mobile/household adapter passes its household_scope through"
    );
}

#[test]
fn core_capacity_lock_orders_host_detect_then_lock_then_check_then_insert() {
    let core = core_body();
    let detect = core
        .find("host_resources::detect_all")
        .expect("core detects host resources");
    let lock = core
        .find("capacity_lock.lock")
        .expect("core takes the capacity lock");
    let check = core
        .find("crate::capacity::check_capacity(")
        .expect("core checks capacity");
    let insert = core.find("insert_with").expect("core inserts the instance");
    assert!(
        detect < lock && lock < check && check < insert,
        "host detect must precede the capacity lock; check_capacity + insert run under it \
         (order: detect < lock < check < insert)"
    );
}

#[test]
fn core_rolls_back_owner_and_job_failures_with_warm_pool_arg() {
    // NARROW: pin the two rollback failure sites (owner assignment, job creation)
    // carry use_warm_pool, now consolidated in the core.
    let core = core_body();
    assert!(
        core.contains("rollback_inserted_instance"),
        "the core must roll back inserted instances on a later-step failure"
    );
    for needle in [
        "\"owner assignment\", use_warm_pool",
        "\"job creation\", use_warm_pool",
    ] {
        assert!(
            core.contains(needle),
            "the core must roll back the {needle} failure site"
        );
    }
}
