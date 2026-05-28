//! installer.rs — per-claw-type installer trait + implementations.
// NOTE: VmError is large by design (rich diagnostic context); boxing would require
// pervasive API changes across all callers.
#![allow(clippy::result_large_err)]
//!
//! ## Architecture (P27)
//!
//! Each `ClawInstaller::install()` uses the typed `InstallerPlan` from
//! `installer_plan.rs`. This is a pure Rust approach — no shell scripts.
//!
//! All 8 claw types have Rust-native install plans.
//!
//! # Decision logic
//!   1. If golden image used → fast-path check first; if binary present, skip install.
//!   2. Use the typed `InstallerPlan` for the claw type.

use async_trait::async_trait;

use crate::error::{ErrorContext, VmError};
use crate::installer_plan;
use crate::ssh_client::SshActions;

// ── Installer configuration ────────────────────────────────────────────────

/// Configuration passed to every installer.
#[derive(Debug, Clone)]
pub struct InstallerConfig {
    /// Customer/instance slug (used for informational purposes)
    pub customer: String,
    /// Claw type being installed
    pub claw_type: String,
    /// Whether a golden image was used (skip install if binary already present)
    pub golden_image_used: bool,
    /// Path to installer scripts directory (on host) — deprecated, kept for API compatibility.
    pub installers_dir: Option<std::path::PathBuf>,
}

// ── Trait ──────────────────────────────────────────────────────────────────

/// Trait for installing a claw agent inside a running guest VM via SSH.
#[async_trait]
pub trait ClawInstaller: Send + Sync {
    /// The claw type name this installer handles (e.g. `"picoclaw"`).
    fn claw_type(&self) -> &str;

    /// Install the claw agent via the given SSH session.
    ///
    /// Implementations must be idempotent (safe to call on an already-
    /// installed guest).
    ///
    /// # Errors
    ///
    /// Returns an error if SSH commands fail or the installation steps fail.
    async fn install(&self, ssh: &dyn SshActions, config: &InstallerConfig) -> Result<(), VmError>;
}

// ── Shared helper ──────────────────────────────────────────────────────────

/// Install a claw using the typed `InstallerPlan` (Rust-only, P27).
///
/// Decision logic:
///   1. If golden image used → fast-path check first; if binary present, skip install.
///   2. Use the typed `InstallerPlan` for the claw type.
async fn run_installer_plan(
    ssh: &dyn SshActions,
    claw_type: &str,
    config: &InstallerConfig,
) -> Result<(), VmError> {
    // Fast path: golden image already has the binary — verify and skip install.
    if config.golden_image_used {
        tracing::info!("[installer][{claw_type}] Checking for pre-installed binary...");
        let check_cmd = format!("test -x /usr/local/bin/{claw_type}");
        match ssh.exec(&check_cmd).await {
            Ok(_) => {
                let version_cmd =
                    format!("/usr/local/bin/{claw_type} --version 2>&1 || echo 'unknown'");
                let version = ssh
                    .exec(&version_cmd)
                    .await
                    .unwrap_or_else(|_| "unknown".to_string());
                tracing::info!(
                    "[installer][{claw_type}] FAST_PATH: binary present in golden image (version: {})",
                    version.trim()
                );
                return Ok(());
            }
            Err(_) => {
                tracing::warn!(
                    "[installer][{claw_type}] SLOW_PATH: golden image used but binary missing \
                     — falling back to full install"
                );
            }
        }
    } else {
        tracing::info!(
            "[installer][{claw_type}] SLOW_PATH: no golden image — running full install"
        );
    }

    // Use typed InstallerPlan (P27 — Rust-only, no script fallback).
    match installer_plan::get_plan(claw_type) {
        Some(plan) => {
            tracing::info!("[installer][{claw_type}] using Rust InstallerPlan (P27)");
            plan.execute(ssh).await
        }
        None => Err(VmError::installer_failed(
            format!("no installer plan defined for claw type: {claw_type}"),
            ErrorContext::with_phase("installer.run"),
        )),
    }
}

// ── Installer implementations ──────────────────────────────────────────────

/// Generic installer that delegates to `run_installer_plan`.
pub struct PlanInstaller {
    claw_type: &'static str,
}

#[async_trait]
impl ClawInstaller for PlanInstaller {
    fn claw_type(&self) -> &str {
        self.claw_type
    }

    async fn install(&self, ssh: &dyn SshActions, config: &InstallerConfig) -> Result<(), VmError> {
        run_installer_plan(ssh, self.claw_type, config).await
    }
}

// ── brokenclaw (test-only) ────────────────────────────────────────────────

/// A deliberately-failing installer used to test the error diagnostic pipeline.
/// Only active when `THEYOS_ENABLE_BROKENCLAW=1` is set.
struct BrokenClawInstaller;

#[async_trait]
impl ClawInstaller for BrokenClawInstaller {
    fn claw_type(&self) -> &'static str {
        "brokenclaw"
    }

    async fn install(
        &self,
        _ssh: &dyn SshActions,
        config: &InstallerConfig,
    ) -> Result<(), VmError> {
        Err(VmError::installer_failed(
            "brokenclaw: deliberate installer failure (exit code 42)",
            ErrorContext::with_phase("installer.run.brokenclaw")
                .container(&config.customer)
                .command("/tmp/install-brokenclaw.sh")
                .exit_code(42)
                .elapsed_ms(0)
                .stderr(
                    "brokenclaw: ERROR: this claw type always fails (test-only)\n\
                     Line 1: deliberate exit 42\n",
                ),
        ))
    }
}

// ── Registry helper ────────────────────────────────────────────────────────

/// Return the appropriate installer for a claw type.
///
/// Accepts any claw type from the manifest that has an installer plan
/// (`Tier::Supported` with builtin plans, or `Tier::Available` with a
/// template-rendered plan via `installer_plan::get_plan`). The `'static`
/// string required by `PlanInstaller` is taken from `ManifestEntry::name`,
/// which is already `&'static str` via the codegen in
/// `core-rs/build.rs`.
#[must_use]
pub fn get_installer(claw_type: &str) -> Option<Box<dyn ClawInstaller>> {
    // Test-only broken installer — gated by env var.
    if claw_type == "brokenclaw" && std::env::var("THEYOS_ENABLE_BROKENCLAW").as_deref() == Ok("1")
    {
        return Some(Box::new(BrokenClawInstaller));
    }

    let entry = core_rs::manifest::get(claw_type)?;
    if !matches!(
        entry.installability(),
        core_rs::manifest::ClawInstallability::Installable,
    ) {
        return None;
    }
    installer_plan::get_plan(entry.name)?;
    Some(Box::new(PlanInstaller {
        claw_type: entry.name,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_client::test_utils::{MockSshSession, SshCall};

    fn make_config(claw_type: &str, golden: bool) -> InstallerConfig {
        InstallerConfig {
            customer: "testcustomer".to_string(),
            claw_type: claw_type.to_string(),
            golden_image_used: golden,
            installers_dir: None,
        }
    }

    #[tokio::test]
    async fn picoclaw_installer_runs_via_plan() {
        let ssh = MockSshSession::new();
        let installer = get_installer("picoclaw").unwrap();
        let config = make_config("picoclaw", false);

        installer.install(&ssh, &config).await.unwrap();

        let calls = ssh.recorded_calls().await;
        // Must have at least 1 call (plan steps).
        assert!(!calls.is_empty(), "expected at least 1 SSH call, got 0");

        // With the Rust plan backend (P27):
        // - First call: idempotency check exec (test -x /usr/local/bin/picoclaw)
        // - Remaining: exec_install steps
        let has_plan_exec = calls
            .iter()
            .any(|c| matches!(c, SshCall::Exec(cmd) | SshCall::ExecInstall(cmd) if cmd.contains("picoclaw")));

        assert!(
            has_plan_exec,
            "expected plan exec for picoclaw, got: {calls:?}"
        );
    }

    #[tokio::test]
    async fn golden_image_skips_install_when_binary_present() {
        // Mock: test -x /usr/local/bin/picoclaw succeeds (exit 0 → Ok)
        let ssh = MockSshSession::new();
        let installer = get_installer("picoclaw").unwrap();
        let config = make_config("picoclaw", true);

        installer.install(&ssh, &config).await.unwrap();

        let calls = ssh.recorded_calls().await;
        // Should have `test -x` check and optional `--version` call, but no install steps
        assert!(
            !calls.is_empty() && calls.len() <= 2,
            "expected 1-2 calls (test -x + optional version), got {}: {calls:?}",
            calls.len(),
        );
        // First call must be `test -x`
        if let SshCall::Exec(cmd) = &calls[0] {
            assert!(cmd.contains("test -x"), "expected test -x, got {cmd}");
        } else {
            panic!("expected Exec call, got {:?}", calls[0]);
        }
    }

    #[tokio::test]
    async fn exec_failure_returns_installer_failed_error() {
        let ssh = MockSshSession::with_exec_error("install failed");
        let installer = get_installer("picoclaw").unwrap();
        let config = make_config("picoclaw", false);

        let err = installer.install(&ssh, &config).await.unwrap_err();
        assert!(
            err.to_string().contains("install failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn get_installer_returns_correct_type() {
        for claw in &[
            "picoclaw",
            "zeroclaw",
            "nanobot",
            "nullclaw",
            "ironclaw",
            "openclaw",
            "hermes-agent",
            "noclaw",
        ] {
            let installer = get_installer(claw);
            assert!(installer.is_some(), "no installer for {claw}");
            assert_eq!(installer.unwrap().claw_type(), *claw);
        }
    }

    #[test]
    fn get_installer_unknown_returns_none() {
        assert!(get_installer("unknownclaw").is_none());
    }

    #[test]
    fn all_claw_types_have_installers() {
        let types = [
            "picoclaw",
            "zeroclaw",
            "nanobot",
            "nullclaw",
            "ironclaw",
            "openclaw",
            "hermes-agent",
            "noclaw",
        ];
        for t in &types {
            assert!(
                get_installer(t).is_some(),
                "missing installer for claw type: {t}"
            );
        }
    }
}
