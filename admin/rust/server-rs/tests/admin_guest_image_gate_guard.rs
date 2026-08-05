//! PR-1 source guards for the macOS guest-image admission gate.
//!
//! The admin create path (`handle_create_instance_body`) must gate on macOS
//! guest-image readiness — equivalently to the mobile/household path — BEFORE any
//! rate-limit / DB insert / Job work, so an unready host never enqueues a
//! `CreateInstance` Job that can only fail late in `clone_base_image`. Both paths
//! share the one `409 GUEST_IMAGE_NOT_READY` shape (`instance_create`).
//!
//! These are source-text scans because driving the full handlers needs a live
//! app plus real macOS guest-image state; the gate DECISION itself is unit-tested
//! in `instance_create::tests` (cross-platform, no `init-state.json`).

use std::fs;
use std::path::Path;

fn read(file: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// The body of `sig`, bounded to the next top-level fn declaration, or to the
/// start of the file's test module if `sig` names the last top-level fn.
fn fn_body(src: &str, sig: &str) -> String {
    let start = src.find(sig).unwrap_or_else(|| panic!("missing fn: {sig}"));
    let rest = &src[start + sig.len()..];
    let end = [
        "\npub async fn ",
        "\npub(crate) async fn ",
        "\nasync fn ",
        "\npub fn ",
        "\nfn ",
        // When `sig` names the file's last top-level fn, none of the above
        // ever match and `rest` runs to EOF, swallowing `mod tests` (its `fn`s
        // are indented, so they can never bound the search). Cut at the
        // module's own `#[cfg(test)]` instead.
        "\n#[cfg(test)]",
    ]
    .iter()
    .filter_map(|m| rest.find(m))
    .min()
    .map_or(rest.len(), |i| i);
    src[start..start + sig.len() + end].to_string()
}

#[test]
fn core_gates_guest_image_before_rate_limit_insert_and_job() {
    // PR-2b: the macOS guest-image gate now lives in the shared create_instance_core
    // and must run BEFORE rate limit / DB insert / Job creation, so an unready host
    // never enqueues work that can only fail late.
    let src = read("instance_create.rs");
    let body = fn_body(&src, "pub(crate) async fn create_instance_core");
    // The call site uses the guest_os-aware wrapper, not the inner responder
    // directly: macOS guests gate on base-image readiness, Linux guests boot
    // from their own rootfs and must pass even with no macOS image present.
    // Accept either spelling so the guard tracks whichever the call site uses.
    let gate = body
        .find("guest_image_gate_for_guest_os")
        .or_else(|| body.find("guest_image_not_ready_response"))
        .expect("create_instance_core must call the shared macOS guest-image gate");
    for (needle, what) in [
        ("rate_limiter", "rate limit"),
        ("insert_with", "DB insert"),
        ("JobType::CreateInstance", "Job creation"),
    ] {
        let idx = body
            .find(needle)
            .unwrap_or_else(|| panic!("create_instance_core must still perform: {what}"));
        assert!(
            gate < idx,
            "the guest-image gate must run BEFORE {what} so an unready macOS host \
             never enqueues work that can only fail late"
        );
    }
}

#[test]
fn the_core_gates_guest_image_and_handlers_do_not_inline_it() {
    // PR-2b: the shared core calls the gate helper; the adapters delegate to the
    // core and must not inline the 409 shape.
    assert!(
        read("instance_create.rs").contains("guest_image_not_ready_response"),
        "create_instance_core must gate macOS create on guest-image readiness via the shared helper"
    );
    for file in ["handlers_instances.rs", "handlers_mobile.rs"] {
        assert!(
            !read(file).contains("GUEST_IMAGE_NOT_READY"),
            "{file} must not inline the GUEST_IMAGE_NOT_READY shape; it lives once in instance_create"
        );
    }
    // The 409 shape is defined in exactly one place.
    assert!(
        read("instance_create.rs").contains("GUEST_IMAGE_NOT_READY"),
        "the GUEST_IMAGE_NOT_READY response shape must live once in instance_create"
    );
}

#[test]
fn create_response_envelopes_stay_distinct_for_pr2() {
    // Characterization for the PR-2 core extraction: the admin path keeps its
    // NESTED accepted{instance, job_id, message} envelope; the mobile path keeps
    // its FLAT {id, name, job_id} body. Pinned so the future create_instance_core
    // extraction preserves both response shapes (and doesn't homogenize them).
    let admin = fn_body(
        &read("handlers_instances.rs"),
        "pub async fn handle_create_instance_body",
    );
    assert!(
        admin.contains("accepted(json!(")
            && admin.contains("\"instance\":")
            && admin.contains("\"message\":"),
        "admin create keeps its nested accepted{{instance, job_id, message}} envelope (PR-2 must preserve it)"
    );

    let mobile = fn_body(
        &read("handlers_mobile.rs"),
        "pub(crate) async fn create_mobile_instance_for_actor",
    );
    assert!(
        mobile.contains("\"id\":") && mobile.contains("\"name\":") && !mobile.contains("accepted("),
        "mobile create keeps its flat id/name/job_id body and must not adopt the admin envelope (PR-2 must not homogenize the two)"
    );
}
