#![cfg(test)]

use super::*;
use std::os::unix::fs::PermissionsExt;

/// Write a shell-script fake imagebuilder at `path` with the given body.
/// Returns the path; caller must keep the surrounding tempdir alive.
fn write_fake_imagebuilder(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("fake-imagebuilder.sh");
    std::fs::write(&path, body).expect("write fake imagebuilder");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod fake imagebuilder");
    path
}

#[test]
fn run_imagebuilder_build_success_returns_ok() {
    let tmp = tempfile::TempDir::new().unwrap();
    // Script that checks args and writes a marker file to prove it ran.
    let marker = tmp.path().join("subprocess-ran");
    let body = format!(
        "#!/bin/sh\n\
             [ \"$1\" = build ] || {{ echo 'missing build arg' >&2; exit 2; }}\n\
             [ \"$2\" = testclaw ] || {{ echo 'wrong claw arg' >&2; exit 3; }}\n\
             touch {}\n\
             exit 0\n",
        marker.display()
    );
    let bin = write_fake_imagebuilder(tmp.path(), &body);

    let result = run_imagebuilder_build(bin.to_str().unwrap(), "testclaw", tmp.path());
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    assert!(
        marker.exists(),
        "fake imagebuilder should have written marker"
    );
}

#[test]
fn run_imagebuilder_build_nonzero_exit_returns_err_with_stderr() {
    let tmp = tempfile::TempDir::new().unwrap();
    let body = "#!/bin/sh\n\
                    echo 'base rootfs missing' >&2\n\
                    exit 1\n";
    let bin = write_fake_imagebuilder(tmp.path(), body);

    let result = run_imagebuilder_build(bin.to_str().unwrap(), "picoclaw", tmp.path());
    assert!(result.is_err(), "expected Err, got {result:?}");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("picoclaw"),
        "error should name the claw, got: {msg}"
    );
    assert!(
        msg.contains("exit"),
        "error should mention exit code, got: {msg}"
    );
    assert!(
        msg.contains("base rootfs missing"),
        "error should include stderr, got: {msg}"
    );
}

#[test]
fn run_imagebuilder_build_missing_binary_returns_err() {
    let tmp = tempfile::TempDir::new().unwrap();
    let bogus = tmp.path().join("does-not-exist");
    let result = run_imagebuilder_build(bogus.to_str().unwrap(), "picoclaw", tmp.path());
    assert!(result.is_err(), "expected spawn-failure Err");
    assert!(
        result.unwrap_err().contains("failed to spawn imagebuilder"),
        "error should describe spawn failure"
    );
}

#[test]
fn run_imagebuilder_build_tolerates_nonexistent_working_dir() {
    // When theyos_dir doesn't exist, the helper should NOT set
    // current_dir and should still invoke the binary successfully.
    let tmp = tempfile::TempDir::new().unwrap();
    let body = "#!/bin/sh\nexit 0\n";
    let bin = write_fake_imagebuilder(tmp.path(), body);

    let missing = tmp.path().join("definitely-not-a-dir");
    let result = run_imagebuilder_build(bin.to_str().unwrap(), "picoclaw", &missing);
    assert!(
        result.is_ok(),
        "helper should tolerate missing working dir, got {result:?}"
    );
}

#[test]
fn resolve_imagebuilder_bin_respects_env_var() {
    // Use core_rs::env helpers so the `unsafe` contract around
    // std::env::set_var (2024 edition) is encapsulated there.
    //
    // Other tests in this module do not touch THEYOS_IMAGEBUILDER_BIN,
    // so there is no TOCTOU risk within this crate. `cargo test` runs
    // tests with `--test-threads=1` in CI; developer-local runs share
    // this env var only with the tests below.
    let sentinel = "/tmp/sentinel-imagebuilder-xyz-test";
    core_rs::env::set_test_env("THEYOS_IMAGEBUILDER_BIN", sentinel);
    let resolved = resolve_imagebuilder_bin();
    assert_eq!(resolved, sentinel);
    core_rs::env::remove_test_env("THEYOS_IMAGEBUILDER_BIN");

    // When unset, falls back to "imagebuilder" (on $PATH).
    let resolved = resolve_imagebuilder_bin();
    assert_eq!(resolved, "imagebuilder");
}

// runtime_min_version gate

fn manifest_with_runtime_min(min: Option<&str>) -> core_rs::artifact_registry::ArtifactManifest {
    core_rs::artifact_registry::ArtifactManifest {
        manifest_version: 1,
        claw: "testclaw".into(),
        version: "1.0.0".into(),
        arch: "x86_64-linux".into(),
        fingerprint: "e".repeat(64),
        base_rootfs_version: "v2".into(),
        sha256: "a".repeat(64),
        size_bytes: 100,
        url: "https://example.com/rootfs.ext4.zst".into(),
        published_at: "2026-04-01T00:00:00Z".into(),
        channel: "stable".into(),
        base_rootfs_sha256: "b".repeat(64),
        installer_plan_sha256: "c".repeat(64),
        kernel_sha256: "d".repeat(64),
        kernel_version: None,
        firecracker_version: None,
        runtime_min_version: min.map(str::to_string),
    }
}

#[test]
fn runtime_gate_blocks_when_engine_too_old() {
    let m = manifest_with_runtime_min(Some("999.0.0"));
    let reason = runtime_min_version_block_reason(&m, "1.2.3")
        .expect("engine older than min must be blocked");
    assert!(
        reason.contains("999.0.0") && reason.contains("1.2.3"),
        "reason should name required + current versions: {reason}"
    );
}

#[test]
fn runtime_gate_allows_absent_or_satisfied() {
    // Absent -> fail-open.
    assert!(runtime_min_version_block_reason(&manifest_with_runtime_min(None), "1.2.3").is_none());
    // Engine newer than min -> allowed.
    assert!(
        runtime_min_version_block_reason(&manifest_with_runtime_min(Some("1.0.0")), "1.2.3")
            .is_none()
    );
}

#[test]
fn runtime_gate_real_engine_version_satisfies_low_minimum() {
    // Guards the call-site wiring of env!(CARGO_PKG_VERSION): the running
    // engine must satisfy a trivially-low minimum.
    let m = manifest_with_runtime_min(Some("0.0.1"));
    assert!(runtime_min_version_block_reason(&m, env!("CARGO_PKG_VERSION")).is_none());
}

// select_install_route

#[test]
fn select_install_route_prebuilt_wins() {
    assert_eq!(
        select_install_route("prebuilt", false),
        InstallRoute::Prebuilt
    );
    // has_plan is irrelevant for prebuilt.
    assert_eq!(
        select_install_route("prebuilt", true),
        InstallRoute::Prebuilt
    );
}

#[test]
fn select_install_route_from_plan_when_plan_present() {
    assert_eq!(select_install_route("source", true), InstallRoute::FromPlan);
}

#[test]
fn select_install_route_no_path_when_no_plan() {
    assert_eq!(select_install_route("source", false), InstallRoute::NoPath);
}

// assets_dir_from_locks_dir

#[test]
fn assets_dir_nested_resolves_sibling_assets() {
    let assets = assets_dir_from_locks_dir(std::path::Path::new("/var/lib/theyos/locks"));
    assert_eq!(assets, std::path::PathBuf::from("/var/lib/assets"));
}

#[test]
fn assets_dir_shallow_falls_back_to_tmp() {
    // No grandparent -> /tmp/assets, matching the original inline fallback.
    let assets = assets_dir_from_locks_dir(std::path::Path::new("/locks"));
    assert_eq!(assets, std::path::PathBuf::from("/tmp/assets"));
}

// remove_claw_artifacts

#[test]
fn remove_claw_artifacts_deletes_goldens_and_snapshots() {
    let tmp = tempfile::TempDir::new().unwrap();
    let assets = tmp.path();
    let goldens = assets.join("goldens").join("picoclaw");
    let snapshots = assets.join("snapshots").join("picoclaw");
    std::fs::create_dir_all(&goldens).unwrap();
    std::fs::create_dir_all(&snapshots).unwrap();
    std::fs::write(goldens.join("rootfs.ext4"), b"x").unwrap();

    remove_claw_artifacts(assets, "picoclaw");

    assert!(!goldens.exists(), "goldens should be removed");
    assert!(!snapshots.exists(), "snapshots should be removed");
}

#[test]
fn remove_claw_artifacts_absent_is_noop() {
    let tmp = tempfile::TempDir::new().unwrap();
    // Neither dir exists; must not panic.
    remove_claw_artifacts(tmp.path(), "ghostclaw");
}

#[test]
fn remove_claw_artifacts_partial_and_leaves_other_claws() {
    let tmp = tempfile::TempDir::new().unwrap();
    let assets = tmp.path();
    let goldens = assets.join("goldens").join("picoclaw");
    std::fs::create_dir_all(&goldens).unwrap();
    // No snapshots dir for picoclaw. A sibling claw has goldens.
    let other = assets.join("goldens").join("otherclaw");
    std::fs::create_dir_all(&other).unwrap();

    remove_claw_artifacts(assets, "picoclaw");

    assert!(!goldens.exists(), "present goldens should be removed");
    assert!(
        !assets.join("snapshots").join("picoclaw").exists(),
        "absent snapshots stays absent"
    );
    assert!(other.exists(), "other claw's goldens must be untouched");
}

// check_macos_base_ready (macOS only)

/// Serializes the macOS-only base-readiness tests: they all mutate the
/// process-global THEYOS_VM_ASSETS_DIR and would otherwise race under the
/// default parallel test runner (same pattern as RELOAD_ENV_LOCK in
/// cloudflared_sync.rs).
#[cfg(target_os = "macos")]
static VM_ASSETS_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "macos")]
#[test]
fn check_macos_base_ready_state_machine() {
    let _guard = VM_ASSETS_ENV_LOCK.lock().unwrap();
    // Owns THEYOS_VM_ASSETS_DIR for the duration; macos_base_dir() reads it.
    let tmp = tempfile::TempDir::new().unwrap();
    let base = tmp.path().join("macos-base");
    std::fs::create_dir_all(&base).unwrap();
    let state_file = base.join("init-state.json");
    core_rs::env::set_test_env("THEYOS_VM_ASSETS_DIR", tmp.path().to_str().unwrap());

    // 1. Missing init-state.json -> not initialized.
    let err = check_macos_base_ready().unwrap_err();
    assert!(err.contains("not initialized"), "got: {err}");

    // 2. phase == complete -> Ok.
    std::fs::write(&state_file, r#"{"phase":"complete"}"#).unwrap();
    assert!(check_macos_base_ready().is_ok());

    // 3. Incomplete phase -> Err naming the phase.
    std::fs::write(&state_file, r#"{"phase":"install_macos"}"#).unwrap();
    let err = check_macos_base_ready().unwrap_err();
    assert!(err.contains("install_macos"), "got: {err}");

    // 4. Missing phase field -> Err.
    std::fs::write(&state_file, r#"{"foo":"bar"}"#).unwrap();
    let err = check_macos_base_ready().unwrap_err();
    assert!(err.contains("missing phase"), "got: {err}");

    // 5. Invalid JSON -> Err.
    std::fs::write(&state_file, b"not json{").unwrap();
    let err = check_macos_base_ready().unwrap_err();
    assert!(err.contains("parse init-state.json"), "got: {err}");

    core_rs::env::remove_test_env("THEYOS_VM_ASSETS_DIR");
}

#[cfg(target_os = "macos")]
#[test]
fn check_any_guest_base_ready_passes_with_linux_base_only() {
    // Acceptance: installing a claw must pass with the macOS base ABSENT
    // when the Linux base is complete — the install is state-only and
    // serves both guest types. Explicit side effect (per review): a later
    // macOS-guest create still fails at the instance_create gate, which
    // is tested there (`gate_still_blocks_macos_guests_until_image_done`).
    // Owns THEYOS_VM_ASSETS_DIR for the duration (same convention as the
    // sibling macos-base test above).
    let _guard = VM_ASSETS_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let linux = tmp.path().join("linux-base");
    std::fs::create_dir_all(&linux).unwrap();
    core_rs::env::set_test_env("THEYOS_VM_ASSETS_DIR", tmp.path().to_str().unwrap());

    // Neither base present -> Err naming both probes.
    let err = check_any_guest_base_ready().unwrap_err();
    assert!(
        err.contains("linux-base") && err.contains("macos-base"),
        "error should report both probes, got: {err}"
    );

    // disk.img alone is NOT enough (it appears mid-init).
    std::fs::write(linux.join("disk.img"), b"x").unwrap();
    assert!(check_any_guest_base_ready().is_err());

    // Complete Linux base with NO macos-base -> Ok.
    std::fs::write(linux.join("init-state.json"), r#"{"phase":"complete"}"#).unwrap();
    assert!(
        check_any_guest_base_ready().is_ok(),
        "a complete Linux base must satisfy the install precondition"
    );

    // Interrupted init (phase not complete) fails closed again.
    std::fs::write(
        linux.join("init-state.json"),
        r#"{"phase":"convert_image"}"#,
    )
    .unwrap();
    assert!(check_any_guest_base_ready().is_err());

    core_rs::env::remove_test_env("THEYOS_VM_ASSETS_DIR");
}

#[cfg(target_os = "macos")]
#[test]
fn check_any_guest_base_ready_passes_with_macos_base_only() {
    let _guard = VM_ASSETS_ENV_LOCK.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let macos = tmp.path().join("macos-base");
    std::fs::create_dir_all(&macos).unwrap();
    core_rs::env::set_test_env("THEYOS_VM_ASSETS_DIR", tmp.path().to_str().unwrap());
    std::fs::write(macos.join("init-state.json"), r#"{"phase":"complete"}"#).unwrap();
    assert!(check_any_guest_base_ready().is_ok());
    core_rs::env::remove_test_env("THEYOS_VM_ASSETS_DIR");
}
