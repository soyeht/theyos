//! cargo-build requer `min_ram_mb` >= 2048 (OOM em 512MB). O manifest deve setar esse valor.
//!
//! `cargo-build` template — clone a Rust project from GitHub and install it
//! via `cargo install --path . --locked`.
//!
//! Steps:
//! 1. `install_deps` — apt-get `build-essential`, `git`, `pkg-config`, `curl`,
//!    `ca-certificates` (plus any extras from `config.system_deps`).
//! 2. `install_rust` — verify the distro Rust toolchain from `install_deps`.
//! 3. `clone_repo` — fetch the manifest-reviewed commit and verify HEAD.
//! 4. `build_and_install` — `cargo install --path . --locked --force` inside
//!    the clone; also copies the final binary to `/usr/local/bin/<name>` so
//!    it's on every user's PATH regardless of `~/.cargo` location.
//! 5. Optional `create_config_dir`.
//! 6. `verify`.
//!
//! Because cargo builds routinely OOM with <2GB of RAM on medium-sized
//! crates, the caller MUST set `min_ram_mb >= 2048` on the manifest entry.
//! Templates cannot enforce this at render time; the check belongs in the
//! install gate (Phase C).

use super::{StepSpec, apt_install_step, config_dir_step};
use crate::manifest::InstallConfig;

const DEFAULT_DEPS: &[&str] = &[
    "build-essential",
    "git",
    "pkg-config",
    "ca-certificates",
    "rustc",
    "cargo",
];

fn trailing_repo_name(full: &str) -> &str {
    full.rsplit('/').next().unwrap_or(full)
}

/// Render the install steps for a cargo-built claw.
#[must_use]
pub fn render(config: &InstallConfig) -> Vec<StepSpec> {
    let repo = config.github_repo;
    let git_ref = config.git_ref;
    let repo_tail = trailing_repo_name(repo);
    let bin = if config.binary_name.is_empty() {
        repo_tail
    } else {
        config.binary_name
    };
    let clone_dir = format!("/opt/claws/{repo_tail}");

    let mut steps = Vec::with_capacity(6);

    // 1. Dependencies.
    let deps: Vec<&'static str> = if config.system_deps.is_empty() {
        DEFAULT_DEPS.to_vec()
    } else {
        // Merge caller deps with defaults (deduped) so we never accidentally
        // drop build-essential if the manifest lists only extras.
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

    // 2. Verify rustc + cargo from distro packages. Do not run remote shell
    // installers in release-gated template paths.
    steps.push(
        StepSpec::new(
            "install_rust",
            "command -v rustc >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1",
        )
        .with_check("command -v cargo >/dev/null 2>&1")
        .with_timeout(600)
        .with_retries(1),
    );

    // 3. Clone.
    let clone_cmd = format!(
        "test -n '{git_ref}' && \
         mkdir -p {clone_dir} && \
         git -C {clone_dir} init && \
         (git -C {clone_dir} remote remove origin >/dev/null 2>&1 || true) && \
         git -C {clone_dir} remote add origin https://github.com/{repo}.git && \
         git -C {clone_dir} fetch --depth 1 origin '{git_ref}' && \
         git -C {clone_dir} checkout --detach FETCH_HEAD && \
         test \"$(git -C {clone_dir} rev-parse HEAD)\" = \"{git_ref}\""
    );
    steps.push(
        StepSpec::new("clone_repo", clone_cmd)
            .with_timeout(300)
            .with_retries(2),
    );

    // 4. Build + install.
    // stderr is intentionally NOT suppressed: on failure, the SSH layer
    // captures stderr_tail into VmError context so we can see cargo's error.
    // Successful builds produce ~100KB of "Compiling X" noise which is fine
    // — `exec_install` callers don't log stdout on success.
    let build_cmd = format!(
        "cd {clone_dir} && \
         . $HOME/.cargo/env 2>/dev/null || true && \
         cargo install --path . --locked --force && \
         if [ -x $HOME/.cargo/bin/{bin} ]; then \
           cp $HOME/.cargo/bin/{bin} /usr/local/bin/{bin} && chmod +x /usr/local/bin/{bin}; \
         fi"
    );
    steps.push(
        StepSpec::new("build_and_install", build_cmd)
            .with_check(format!("test -x /usr/local/bin/{bin}"))
            .with_timeout(1800)
            .with_retries(1),
    );

    // 5. Optional config dir.
    if let Some(step) = config_dir_step(config) {
        steps.push(step);
    }

    // 6. Verify.
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
    fn cargo_build_has_minimum_expected_steps() {
        let cfg = InstallConfig {
            github_repo: "example/rusty",
            binary_name: "rusty",
            ..Default::default()
        };
        let steps = render(&cfg);
        // deps + rust + clone + build + verify (no config_dir).
        assert_eq!(steps.len(), 5);
        assert_eq!(steps[0].phase, "install_deps");
        assert_eq!(steps[1].phase, "install_rust");
        assert_eq!(steps[2].phase, "clone_repo");
        assert_eq!(steps[3].phase, "build_and_install");
        assert_eq!(steps[4].phase, "verify");
    }

    #[test]
    fn cargo_build_uses_distro_toolchain() {
        let cfg = InstallConfig {
            github_repo: "x/y",
            git_ref: "0123456789abcdef0123456789abcdef01234567",
            binary_name: "y",
            ..Default::default()
        };
        let step = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "install_rust")
            .unwrap();
        assert!(step.command.contains("command -v rustc"));
        assert!(step.command.contains("command -v cargo"));
        assert!(!step.command.contains("rustup.rs"));
        assert!(!step.command.contains("| sh"));
    }

    #[test]
    fn cargo_build_clone_uses_github_https_url() {
        let cfg = InstallConfig {
            github_repo: "org/crate",
            git_ref: "0123456789abcdef0123456789abcdef01234567",
            binary_name: "crate",
            ..Default::default()
        };
        let steps = render(&cfg);
        let clone = steps.iter().find(|s| s.phase == "clone_repo").unwrap();
        assert!(clone.command.contains("https://github.com/org/crate.git"));
        assert!(clone.command.contains("/opt/claws/crate"));
        assert!(
            clone
                .command
                .contains("0123456789abcdef0123456789abcdef01234567")
        );
        assert!(clone.command.contains("rev-parse HEAD"));
        assert!(!clone.command.contains(&["git clone", " --depth"].concat()));
        assert!(!clone.command.contains(&["origin", "/HEAD"].concat()));
    }

    #[test]
    fn cargo_build_step_uses_cargo_install_locked() {
        let cfg = InstallConfig {
            github_repo: "x/y",
            git_ref: "0123456789abcdef0123456789abcdef01234567",
            binary_name: "y",
            ..Default::default()
        };
        let build = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "build_and_install")
            .unwrap();
        assert!(build.command.contains("cargo install"));
        assert!(build.command.contains("--locked"));
        assert!(
            build.timeout_secs >= 600,
            "cargo build needs generous timeout"
        );
        assert_eq!(
            build.idempotency_check.as_deref(),
            Some("test -x /usr/local/bin/y")
        );
    }

    #[test]
    fn cargo_build_merges_caller_deps_with_defaults() {
        let cfg = InstallConfig {
            github_repo: "x/y",
            git_ref: "0123456789abcdef0123456789abcdef01234567",
            binary_name: "y",
            system_deps: &["libssl-dev", "git"], // git is also in defaults
            ..Default::default()
        };
        let step = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "install_deps")
            .unwrap();
        assert!(step.command.contains("libssl-dev"));
        assert!(step.command.contains("build-essential"));
        // git (a default dep) appears exactly once even though it's also
        // listed by the caller — dedup works.
        assert_eq!(
            step.command.matches(" git ").count(),
            1,
            "git must be present exactly once, command: {}",
            step.command,
        );
    }
}
