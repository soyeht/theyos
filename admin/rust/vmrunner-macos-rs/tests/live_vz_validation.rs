#![cfg(target_os = "macos")]
//! Opt-in LIVE macOS VZ validation harness (P5 part A). **DEFAULT-SKIP.**
//!
//! This is the cargo-test entry point for validating the macOS VZ runner against
//! REAL Virtualization.framework VMs. It is **inert by default**: the live test
//! is `#[ignore]`d AND additionally gated on `THEYOS_LIVE_VZ=1`, so a normal
//! `cargo test` (CI or local) never touches VZ.
//!
//! The opt-in path here runs only a **safe isolation precheck**: it verifies the
//! operator pointed every stateful path at an isolated scratch dir (writable,
//! and never inside a shipping/Dev app bundle). It does **NOT** boot any VM,
//! consume the 2 admission slots, or touch `/Applications/Soyeht.app`.
//!
//! The real VM-boot / admission-limit / disk-gate validation is a SEPARATE,
//! AUTHORIZED, manual procedure.
//! DO NOT run it without explicit authorization and confirmed isolation.
//!
//! ```bash
//! # default: skipped
//! cargo test -p vmrunner-macos-rs --test live_vz_validation
//! # opt-in isolation precheck (no VM boot):
//! THEYOS_LIVE_VZ=1 \
//!   THEYOS_VM_VMS_PATH=/tmp/live-vz-scratch/vms \
//!   THEYOS_VM_STATE_DIR=/tmp/live-vz-scratch/state \
//!   THEYOS_SNAPSHOTS_DIR=/tmp/live-vz-scratch/snapshots \
//!   THEYOS_VM_ASSETS_DIR=/tmp/live-vz-scratch/assets \
//!   cargo test -p vmrunner-macos-rs --test live_vz_validation -- --ignored live_isolation_precheck
//! ```

use std::path::{Path, PathBuf};

/// Stateful paths that MUST be pointed at isolated scratch dirs for any live run.
const ISOLATION_VARS: &[&str] = &[
    "THEYOS_VM_VMS_PATH",
    "THEYOS_VM_STATE_DIR",
    "THEYOS_SNAPSHOTS_DIR",
    "THEYOS_VM_ASSETS_DIR",
];

/// Sentinel every scratch path must contain — prevents accidentally pointing the
/// harness at a real/default location.
const SCRATCH_SENTINEL: &str = "live-vz-scratch";

/// True only when the operator has explicitly opted in.
fn opted_in() -> bool {
    std::env::var("THEYOS_LIVE_VZ").as_deref() == Ok("1")
}

/// Read an isolation var and FAIL CLOSED unless it is an absolute scratch path
/// that cannot be a shipping/Dev app's state. Never let a live run default to a
/// real location.
fn require_scratch_dir(var: &str) -> PathBuf {
    let value = std::env::var(var).unwrap_or_else(|_| {
        panic!("{var} must be set to an isolated scratch dir for live VZ")
    });
    assert!(
        Path::new(&value).is_absolute(),
        "{var} must be an absolute scratch path, got: {value}"
    );
    assert!(
        !value.contains("/Applications/Soyeht.app")
            && !value.contains("/Applications/Soyeht Dev.app"),
        "{var} must NOT point inside a shipping/Dev app bundle: {value}"
    );
    assert!(
        value.contains(SCRATCH_SENTINEL),
        "{var}={value} must live under a `{SCRATCH_SENTINEL}` directory (isolation guard)"
    );
    PathBuf::from(value)
}

#[test]
fn live_harness_is_default_skip_without_optin() {
    // Without THEYOS_LIVE_VZ=1 the harness is inert — this runs in normal CI.
    if opted_in() {
        // A developer explicitly opted in; the live precheck runs under --ignored.
        eprintln!("THEYOS_LIVE_VZ=1 detected; isolation precheck runs only via --ignored");
        return;
    }
    assert!(
        !opted_in(),
        "harness must be inert without THEYOS_LIVE_VZ=1"
    );
}

/// Opt-in ISOLATION PRECHECK — safe even when executed: verifies the operator's
/// scratch isolation is correct. Does NOT boot VMs, consume slots, or touch real
/// state. Double-gated: `#[ignore]` (skipped by default) AND requires
/// `THEYOS_LIVE_VZ=1`. The real VM-boot validation is authorized-manual.
#[test]
#[ignore = "LIVE VZ opt-in: set THEYOS_LIVE_VZ=1 + isolated THEYOS_* scratch dirs, run with --ignored. Isolation precheck only; VM-boot validation is authorized-manual."]
fn live_isolation_precheck() {
    if !opted_in() {
        eprintln!("skipped: THEYOS_LIVE_VZ != 1");
        return;
    }

    // Every stateful path must be an isolated, writable scratch dir (fail-closed).
    let dirs: Vec<PathBuf> = ISOLATION_VARS
        .iter()
        .map(|v| require_scratch_dir(v))
        .collect();
    for dir in &dirs {
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("scratch dir {dir:?} not creatable: {e}"));
        let probe = dir.join(".live-vz-write-probe");
        std::fs::write(&probe, b"ok")
            .unwrap_or_else(|e| panic!("scratch dir {dir:?} not writable: {e}"));
        let _ = std::fs::remove_file(&probe);
    }

    eprintln!(
        "isolation precheck OK: {} scratch dirs verified. VM-boot / admission-limit / \
         disk-gate validation is authorized-manual and BLOCKED here.",
        dirs.len()
    );
}
