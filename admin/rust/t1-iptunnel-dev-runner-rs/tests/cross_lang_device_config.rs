//! Cross-language round-trip lock for the dev-host Device session config.
//!
//! @alaine (test-fidelity review) flagged a LOW on Item B: the Rust
//! `gen-device-config` output was validated only by the Rust
//! `validate-session-config` path; the CROSS-LANGUAGE round trip — Rust
//! generator -> the Python validator `scripts/validate-t1-device-session-config.py`
//! — was not test-locked, so the two validators could silently drift.
//!
//! This integration test closes that seam end to end:
//!   * it runs the REAL built `t1-iptunnel-dev-runner gen-device-config` CLI to
//!     emit a config, then asserts the Python validator ACCEPTS it (exit 0);
//!   * it asserts the reverse-negative: a deliberately-mangled generated config
//!     is REJECTED by the Python validator (non-zero exit).
//!
//! Per the repo's Python convention the validator is invoked via `uv run`.
//!
//! Compiled only with `--features dev_t1_datapath` (the feature that enables the
//! `gen-device-config` subcommand). It runs under
//! `cargo test -p t1-iptunnel-dev-runner-rs --features dev_t1_datapath`; under
//! default features the whole file compiles to nothing, so the standard
//! `cargo test --workspace` lane never requires `uv`/Python.
#![cfg(feature = "dev_t1_datapath")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Repo root — three levels above this crate's manifest dir
/// (`<root>/admin/rust/t1-iptunnel-dev-runner-rs`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root is three levels above the crate manifest dir")
        .to_path_buf()
}

/// Absolute path to the Python validator under test.
fn python_validator() -> PathBuf {
    let path = repo_root().join("scripts/validate-t1-device-session-config.py");
    assert!(
        path.is_file(),
        "python validator not found at {}",
        path.display()
    );
    path
}

/// A unique output path in this test target's temp dir.
fn tmp_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(name)
}

/// Run the real built CLI to generate a Device session config at `out`.
fn generate_config(platform: &str, out: &Path) {
    let status = Command::new(env!("CARGO_BIN_EXE_t1-iptunnel-dev-runner"))
        .args([
            "gen-device-config",
            "--platform",
            platform,
            "--pool-network",
            "198.18.0.0/24",
            "--out",
        ])
        .arg(out)
        .status()
        .expect("run t1-iptunnel-dev-runner gen-device-config");
    assert!(
        status.success(),
        "gen-device-config should succeed for {platform}"
    );
    assert!(
        out.is_file(),
        "generator should have written {}",
        out.display()
    );
}

/// Invoke the Python validator via `uv run` against `config`, returning the raw
/// exit code (127-style failures to even launch `uv` are surfaced as a panic).
fn python_validate_exit_code(config: &Path) -> i32 {
    let output = Command::new("uv")
        .current_dir(repo_root())
        .arg("run")
        .arg(python_validator())
        .arg(config)
        .output()
        .expect(
            "invoke `uv run` for the cross-language validator; \
             uv must be installed (repo convention: run Python via `uv run`)",
        );
    // Surface the validator's own message to the test log for diagnosis.
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    output
        .status
        .code()
        .expect("python validator exited via signal, not a normal exit code")
}

#[test]
fn generated_config_is_accepted_by_python_validator() {
    for platform in ["linux", "macos"] {
        let out = tmp_path(&format!("xlang-good-{platform}.json"));
        generate_config(platform, &out);

        let code = python_validate_exit_code(&out);
        assert_eq!(
            code, 0,
            "python validator must ACCEPT the Rust-generated {platform} config (exit 0)"
        );
    }
}

#[test]
fn mangled_generated_config_is_rejected_by_python_validator() {
    // Start from a real generated config so the negative is a genuine
    // round-trip: only the flipped field differs from an accepted file.
    let good = tmp_path("xlang-base-for-mangle.json");
    generate_config("linux", &good);
    let text = fs::read_to_string(&good).expect("read generated config");

    // Negative 1: production activation must stay false.
    let flipped = text.replace(
        "\"production_activation\": false",
        "\"production_activation\": true",
    );
    assert_ne!(
        flipped, text,
        "expected production_activation to be flipped"
    );
    let bad_prod = tmp_path("xlang-bad-production.json");
    fs::write(&bad_prod, &flipped).expect("write mangled (production) config");
    assert_ne!(
        python_validate_exit_code(&bad_prod),
        0,
        "python validator must REJECT a production_activation=true config"
    );

    // Negative 2: the claw route prefix must stay a /32 host route.
    let widened = text.replace(
        "\"claw_route_prefix_len\": 32",
        "\"claw_route_prefix_len\": 24",
    );
    assert_ne!(
        widened, text,
        "expected claw_route_prefix_len to be widened"
    );
    let bad_route = tmp_path("xlang-bad-route.json");
    fs::write(&bad_route, &widened).expect("write mangled (route) config");
    assert_ne!(
        python_validate_exit_code(&bad_route),
        0,
        "python validator must REJECT a non-/32 claw_route_prefix_len config"
    );
}
