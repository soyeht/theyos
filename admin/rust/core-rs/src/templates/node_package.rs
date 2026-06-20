//! `node-package` template — install a Node.js package globally via
//! `npm install -g`.
//!
//! Uses `NodeSource`'s APT repo to get Node 22.x; same recipe as the
//! `openclaw`/`noclaw` builtins for consistency.

use super::{StepSpec, apt_install_step, config_dir_step};
use crate::manifest::InstallConfig;
use crate::node_source::{INSTALL_NODE_22_COMMAND, NODE_22_CHECK};

const DEFAULT_DEPS: &[&str] = &["curl", "ca-certificates", "gnupg"];

/// Render the install steps for an npm-global package.
#[must_use]
pub fn render(config: &InstallConfig) -> Vec<StepSpec> {
    let pkg = config.npm_package;
    let bin = if config.entry_point.is_empty() {
        // Best-effort: strip "@scope/" prefix for the binary name fallback.
        let tail = pkg.rsplit('/').next().unwrap_or(pkg);
        tail.split('@').next().unwrap_or(tail)
    } else {
        config.entry_point
    };

    let mut steps = Vec::with_capacity(6);

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

    // 2. Install Node 22 via NodeSource.
    steps.push(
        StepSpec::new("install_node", INSTALL_NODE_22_COMMAND)
            .with_check(NODE_22_CHECK)
            .with_timeout(300)
            .with_retries(2),
    );

    // 3. npm install -g.
    let install_cmd = format!("npm install -g '{pkg}'");
    steps.push(
        StepSpec::new("install_package", install_cmd)
            .with_check(format!("command -v {bin} >/dev/null 2>&1"))
            .with_timeout(240)
            .with_retries(1),
    );

    // 4. Optional config dir.
    if let Some(step) = config_dir_step(config) {
        steps.push(step);
    }

    // 5. Verify.
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
    fn node_package_has_expected_steps() {
        let cfg = InstallConfig {
            npm_package: "cool-cli",
            entry_point: "cool",
            ..Default::default()
        };
        let steps = render(&cfg);
        assert_eq!(steps.len(), 4);
        assert_eq!(steps[0].phase, "install_deps");
        assert_eq!(steps[1].phase, "install_node");
        assert_eq!(steps[2].phase, "install_package");
        assert_eq!(steps[3].phase, "verify");
    }

    #[test]
    fn node_package_installs_nodejs_22() {
        let cfg = InstallConfig {
            npm_package: "foo",
            ..Default::default()
        };
        let node_step = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "install_node")
            .unwrap();
        assert!(node_step.command.contains("nodesource.sources"));
        assert!(!node_step.command.contains("setup_22.x"));
        assert!(node_step.command.contains("node --version"));
    }

    #[test]
    fn node_package_uses_npm_install_g() {
        let cfg = InstallConfig {
            npm_package: "foo",
            entry_point: "foo",
            ..Default::default()
        };
        let step = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "install_package")
            .unwrap();
        assert!(step.command.contains("npm install -g 'foo'"));
        assert_eq!(
            step.idempotency_check.as_deref(),
            Some("command -v foo >/dev/null 2>&1")
        );
    }

    #[test]
    fn node_package_infers_bin_from_scoped_package() {
        let cfg = InstallConfig {
            npm_package: "@anthropic-ai/claude-code",
            // entry_point intentionally empty → fallback.
            ..Default::default()
        };
        let step = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "install_package")
            .unwrap();
        // fallback strips the @scope/ prefix: "claude-code"
        assert_eq!(
            step.idempotency_check.as_deref(),
            Some("command -v claude-code >/dev/null 2>&1")
        );
    }

    #[test]
    fn node_package_config_dir_optional() {
        let cfg_bare = InstallConfig {
            npm_package: "foo",
            ..Default::default()
        };
        assert!(
            !render(&cfg_bare)
                .iter()
                .any(|s| s.phase == "create_config_dir")
        );

        let cfg_dir = InstallConfig {
            npm_package: "foo",
            config_dir: "/root/.foo",
            ..Default::default()
        };
        assert!(
            render(&cfg_dir)
                .iter()
                .any(|s| s.phase == "create_config_dir")
        );
    }
}
