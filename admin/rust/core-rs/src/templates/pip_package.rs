//! `pip-package` template — install a Python package in an isolated env via
//! `pipx`.
//!
//! **Why pipx and not pip** — starting from Debian 12 / Ubuntu 23.04 the
//! system Python is "externally managed" and `pip3 install` outside a venv
//! fails by default. `pipx` creates one venv per package under
//! `/root/.local/pipx` and symlinks the entry point into `/usr/local/bin`,
//! which keeps the system Python pristine. New claws routed through this
//! template must use pipx.

use super::{StepSpec, apt_install_step, config_dir_step};
use crate::manifest::InstallConfig;

const DEFAULT_DEPS: &[&str] = &["python3", "python3-pip", "python3-venv", "pipx"];

fn pip_project_name(spec: &str) -> &str {
    spec.split_once("==").map_or(spec, |(name, _)| name)
}

/// Render the install steps for a pip-packaged claw.
#[must_use]
pub fn render(config: &InstallConfig) -> Vec<StepSpec> {
    let pkg = config.pip_package;
    let bin = if config.entry_point.is_empty() {
        // Fall back to the package name (a common convention, e.g. `nanobot-ai`
        // ships a `nanobot` entry point — but if the caller doesn't set it we
        // take a best-guess last segment).
        let package_name = pip_project_name(pkg);
        package_name
            .rsplit(&['-', '_'][..])
            .next()
            .unwrap_or(package_name)
    } else {
        config.entry_point
    };

    let mut steps = Vec::with_capacity(5);

    // 1. Dependencies.
    let deps: Vec<&'static str> = if config.system_deps.is_empty() {
        DEFAULT_DEPS.to_vec()
    } else {
        let mut out: Vec<&'static str> = DEFAULT_DEPS.to_vec();
        for &d in config.system_deps {
            if !out.contains(&d) {
                out.push(d);
            }
        }
        out
    };
    if let Some(step) = apt_install_step(&deps) {
        steps.push(step);
    }

    // 2. pipx install. PIPX_BIN_DIR=/usr/local/bin makes the entry point
    //    visible to every user (pipx defaults to ~/.local/bin which isn't on
    //    PATH inside our non-interactive ssh shells).
    let install_cmd = format!(
        "pipx ensurepath >/dev/null 2>&1 || true && \
         PIPX_BIN_DIR=/usr/local/bin pipx install --force '{pkg}'"
    );
    steps.push(
        StepSpec::new("install_package", install_cmd)
            .with_check(format!("test -x /usr/local/bin/{bin}"))
            .with_timeout(300)
            .with_retries(1),
    );

    // 3. Optional config dir.
    if let Some(step) = config_dir_step(config) {
        steps.push(step);
    }

    // 4. Verify.
    steps.push(StepSpec::new(
        "verify",
        format!("{bin} --version 2>/dev/null || {bin} --help 2>/dev/null | head -1 || true"),
    ));

    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pip_package_has_expected_steps() {
        let cfg = InstallConfig {
            pip_package: "mytool==1.2.3",
            entry_point: "mytool",
            ..Default::default()
        };
        let steps = render(&cfg);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].phase, "install_deps");
        assert_eq!(steps[1].phase, "install_package");
        assert_eq!(steps[2].phase, "verify");
    }

    #[test]
    fn pip_package_uses_pipx_not_pip() {
        let cfg = InstallConfig {
            pip_package: "mytool==1.2.3",
            entry_point: "mytool",
            ..Default::default()
        };
        let step = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "install_package")
            .unwrap();
        assert!(
            step.command.contains("pipx install"),
            "must use pipx, got: {}",
            step.command,
        );
        assert!(
            !step
                .command
                .contains(&["break", "-system", "-packages"].concat()),
            "must not use pip's system-package override flag"
        );
        assert!(
            step.command.contains("PIPX_BIN_DIR=/usr/local/bin"),
            "must target /usr/local/bin so the entry point is on PATH",
        );
    }

    #[test]
    fn pip_package_respects_entry_point_override() {
        let cfg = InstallConfig {
            pip_package: "my-tool-ai==1.2.3",
            entry_point: "mytool",
            ..Default::default()
        };
        let step = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "install_package")
            .unwrap();
        assert_eq!(
            step.idempotency_check.as_deref(),
            Some("test -x /usr/local/bin/mytool"),
        );
    }

    #[test]
    fn pip_package_includes_python_deps_by_default() {
        let cfg = InstallConfig {
            pip_package: "foo==1.2.3",
            entry_point: "foo",
            ..Default::default()
        };
        let deps_step = render(&cfg).into_iter().next().unwrap();
        assert!(deps_step.command.contains("python3"));
        assert!(deps_step.command.contains("pipx"));
    }

    #[test]
    fn pip_package_creates_config_dir_when_set() {
        let cfg = InstallConfig {
            pip_package: "foo==1.2.3",
            entry_point: "foo",
            config_dir: "/root/.foo",
            ..Default::default()
        };
        let steps = render(&cfg);
        assert!(steps.iter().any(|s| s.phase == "create_config_dir"));
    }

    #[test]
    fn pip_package_verify_runs_entry_point() {
        let cfg = InstallConfig {
            pip_package: "foo==1.2.3",
            entry_point: "bar",
            ..Default::default()
        };
        let verify = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "verify")
            .unwrap();
        assert!(verify.command.contains("bar --version"));
    }
}
