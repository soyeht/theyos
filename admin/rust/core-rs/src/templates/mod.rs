//! P-46 Phase B — install-plan templates.
//!
//! A template takes a declarative [`InstallConfig`](crate::manifest::InstallConfig)
//! — typically supplied by `claws/manifest.yml` for a non-builtin claw — and
//! turns it into an ordered list of [`StepSpec`]s ready to be lifted into a
//! `vmrunner_rs::installer_plan::InstallerPlan`.
//!
//! Templates live in `core-rs` (the shared foundation crate) so that any code
//! path that can read the manifest can also render an install plan, without
//! depending on the heavy-weight VM lifecycle crate. The split also avoids a
//! dependency cycle: `vmrunner-rs` already depends on `core-rs`.
//!
//! # Stability guarantees
//!
//! - Adding a new step to an existing template is a **breaking change** from
//!   the artifact-DAG perspective — it changes the plan `content_hash()` and
//!   invalidates cached goldens. Prefer introducing a new template name.
//! - `StepSpec` is intentionally a plain data struct (no builders) so `core-rs`
//!   stays allocation-light and can produce the same bytes that `vmrunner-rs`
//!   would hash over.
//!
//! # Dispatcher
//!
//! Call [`render`] with the template name (e.g. `"go-binary"`) and the config;
//! it returns `Some(steps)` for a known template or `None` otherwise. Callers
//! should treat `None` as "this claw has no install plan" and refuse the
//! install, rather than silently falling back to a default template.

use crate::manifest::InstallConfig;

pub mod cargo_build;
pub mod go_binary;
pub mod manual_shell;
pub mod node_package;
pub mod pip_package;
pub mod raw_binary;

/// One step of an install plan, as produced by a template.
///
/// Mirrors `vmrunner_rs::installer_plan::InstallerStep`, minus the
/// `vmrunner-rs`-specific types (`Cow<'static, str>`, `Duration`). The
/// translation happens in `vmrunner_rs::installer_plan::from_spec`.
///
/// Every field uses `String` because templates interpolate `InstallConfig`
/// content at runtime; the resulting strings are then leaked into `'static`
/// memory by `from_spec` so they can live inside the existing `InstallerStep`
/// `&'static str` slots.
#[derive(Debug, Clone)]
pub struct StepSpec {
    /// Short, stable identifier for the step (e.g. `"install_deps"`). Shows up
    /// in error messages and log lines.
    pub phase: String,
    /// Shell command to run inside the guest VM (executed via `sh -lc`).
    pub command: String,
    /// Optional fast predicate: if it exits 0, the step is skipped. Mirrors
    /// `InstallerStep::with_check`.
    pub idempotency_check: Option<String>,
    /// Per-step timeout. Defaults vary by step kind — long downloads and
    /// builds get more generous budgets.
    pub timeout_secs: u64,
    /// Bounded retry count. `0` disables retries. Templates pick a
    /// conservative value (0–2) because the scheduler will retry the whole
    /// plan later if needed.
    pub max_retries: u8,
}

impl StepSpec {
    /// Construct a new step with sane defaults (120s timeout, no retries, no check).
    #[must_use]
    pub fn new(phase: impl Into<String>, command: impl Into<String>) -> Self {
        StepSpec {
            phase: phase.into(),
            command: command.into(),
            idempotency_check: None,
            timeout_secs: 120,
            max_retries: 0,
        }
    }

    /// Attach an idempotency check (a fast shell predicate).
    #[must_use]
    pub fn with_check(mut self, check: impl Into<String>) -> Self {
        self.idempotency_check = Some(check.into());
        self
    }

    /// Override the per-step timeout.
    #[must_use]
    pub const fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Override the retry count.
    #[must_use]
    pub const fn with_retries(mut self, n: u8) -> Self {
        self.max_retries = n;
        self
    }
}

/// Resolve and render a template by name.
///
/// Known templates:
/// - `"go-binary"` — download Go-style release tarball from GitHub.
/// - `"cargo-build"` — clone + `cargo install --path . --locked`.
/// - `"pip-package"` — `pipx install <package>` (isolated Python env).
/// - `"node-package"` — `npm install -g <package>`.
/// - `"raw-binary"` — direct `curl` of a prebuilt binary URL.
/// - `"manual-shell"` — **sandbox-only**; runs the raw `manual_script`.
///
/// Returns `None` for an unknown name; callers MUST treat this as a hard
/// refusal rather than a silent default.
#[must_use]
pub fn render(template_name: &str, config: &InstallConfig) -> Option<Vec<StepSpec>> {
    match template_name {
        "go-binary" => Some(go_binary::render(config)),
        "cargo-build" => Some(cargo_build::render(config)),
        "pip-package" => Some(pip_package::render(config)),
        "node-package" => Some(node_package::render(config)),
        "raw-binary" => Some(raw_binary::render(config)),
        "manual-shell" => Some(manual_shell::render(config)),
        _ => None,
    }
}

/// Render an `apt-get install` command covering `config.system_deps`. Used by
/// every template that needs extra packages. Returns `None` when the slice is
/// empty so the template can omit the dependency step entirely.
pub(crate) fn apt_install_step(deps: &[&'static str]) -> Option<StepSpec> {
    if deps.is_empty() {
        return None;
    }
    let pkgs = deps.join(" ");
    let cmd = format!(
        "export DEBIAN_FRONTEND=noninteractive && \
         apt-get update -qq && \
         apt-get install -y --no-install-recommends {pkgs} >/dev/null 2>&1"
    );
    Some(
        StepSpec::new("install_deps", cmd)
            .with_timeout(240)
            .with_retries(2),
    )
}

/// Render a `mkdir -p <config_dir>` step if a directory is configured.
pub(crate) fn config_dir_step(config: &InstallConfig) -> Option<StepSpec> {
    if config.config_dir.is_empty() {
        return None;
    }
    Some(StepSpec::new(
        "create_config_dir",
        format!("mkdir -p {}", config.config_dir),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_cfg() -> InstallConfig {
        InstallConfig::default()
    }

    #[test]
    fn render_unknown_template_returns_none() {
        assert!(render("nonexistent-template", &empty_cfg()).is_none());
        assert!(render("", &empty_cfg()).is_none());
    }

    #[test]
    fn render_dispatches_all_known_templates() {
        for name in &[
            "go-binary",
            "cargo-build",
            "pip-package",
            "node-package",
            "raw-binary",
            "manual-shell",
        ] {
            // Use a non-empty config so `manual-shell` has something to emit.
            let cfg = InstallConfig {
                github_repo: "example/example",
                binary_name: "example",
                pip_package: "example",
                npm_package: "example",
                manual_script: "true",
                ..Default::default()
            };
            assert!(
                render(name, &cfg).is_some(),
                "template {name} should be known",
            );
        }
    }

    #[test]
    fn step_spec_builders_chain() {
        let s = StepSpec::new("phase", "cmd")
            .with_check("test -f /x")
            .with_timeout(42)
            .with_retries(3);
        assert_eq!(s.phase, "phase");
        assert_eq!(s.command, "cmd");
        assert_eq!(s.idempotency_check.as_deref(), Some("test -f /x"));
        assert_eq!(s.timeout_secs, 42);
        assert_eq!(s.max_retries, 3);
    }

    #[test]
    fn apt_install_step_skipped_when_empty() {
        assert!(apt_install_step(&[]).is_none());
    }

    #[test]
    fn apt_install_step_interpolates_deps() {
        let step = apt_install_step(&["curl", "ca-certificates"]).expect("some");
        assert_eq!(step.phase, "install_deps");
        assert!(step.command.contains("curl ca-certificates"));
        assert!(step.command.contains("apt-get update"));
        assert!(step.command.contains("apt-get install"));
        assert!(step.timeout_secs >= 60);
    }

    #[test]
    fn config_dir_step_skipped_when_absent() {
        assert!(config_dir_step(&InstallConfig::default()).is_none());
    }

    #[test]
    fn config_dir_step_emits_mkdir() {
        let cfg = InstallConfig {
            config_dir: "/root/.foo",
            ..Default::default()
        };
        let step = config_dir_step(&cfg).expect("some");
        assert_eq!(step.phase, "create_config_dir");
        assert!(step.command.contains("mkdir -p /root/.foo"));
    }
}
