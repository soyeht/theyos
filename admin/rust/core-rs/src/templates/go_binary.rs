//! `go-binary` template — download a Go-style release tarball from GitHub.
//!
//! Works for any project that ships `linux-{arch}` tarballs (or other asset
//! patterns) on GitHub Releases and contains a single binary named
//! `config.binary_name`. Despite the name it is not Go-specific; it just
//! matches the conventions the Go ecosystem popularized.
//!
//! Placeholders in `config.asset_pattern`:
//! - `{version}` — release tag (e.g. `v1.2.3`); the template leaves this
//!   shell-expanded at runtime so the VM picks up the current tag.
//! - `{os}`   — `linux`
//! - `{arch}` — `amd64` (today). The hard-coded value mirrors what the
//!   builtin plans ship; multi-arch support is a P-46 follow-up.
//! - `{repo}` — the trailing segment of `config.github_repo`
//!   (e.g. `"sipeed/picoclaw"` → `picoclaw`).
//!
//! Default pattern when `config.asset_pattern` is empty:
//! `{repo}-linux-{arch}.tar.gz`.

use super::{StepSpec, apt_install_step, config_dir_step};
use crate::manifest::InstallConfig;

const DEFAULT_DEPS: &[&str] = &["curl", "ca-certificates", "tar"];

fn trailing_repo_name(full: &str) -> &str {
    full.rsplit('/').next().unwrap_or(full)
}

fn substitute_placeholders(pattern: &str, repo_tail: &str) -> String {
    pattern
        .replace("{repo}", repo_tail)
        .replace("{os}", "linux")
        .replace("{arch}", "amd64")
}

/// Render the install steps for a Go-style release.
#[must_use]
pub fn render(config: &InstallConfig) -> Vec<StepSpec> {
    let repo = config.github_repo;
    let repo_tail = trailing_repo_name(repo);
    let bin = if config.binary_name.is_empty() {
        repo_tail
    } else {
        config.binary_name
    };

    let pattern = if config.asset_pattern.is_empty() {
        "{repo}-linux-{arch}.tar.gz".to_string()
    } else {
        config.asset_pattern.to_string()
    };
    // Leave {version} unsubstituted — the download step shell-expands it.
    let asset_template = substitute_placeholders(&pattern, repo_tail);

    let mut steps = Vec::with_capacity(5);

    // 1. apt-get dependencies (config-supplied, falling back to defaults).
    let deps: Vec<&'static str> = if config.system_deps.is_empty() {
        DEFAULT_DEPS.to_vec()
    } else {
        config.system_deps.to_vec()
    };
    if let Some(step) = apt_install_step(&deps) {
        steps.push(step);
    }

    // 2. Download + extract. Uses the GitHub "latest release" API to resolve
    //    the tag when `{version}` is present in the asset pattern; otherwise
    //    the pattern is used verbatim.
    let asset_name_expr = asset_template.replace("{version}", "${VERSION}");
    let download_cmd = format!(
        "VERSION=$(curl -fsSL 'https://api.github.com/repos/{repo}/releases/latest' \
           | python3 -c \"import sys,json; print(json.load(sys.stdin)['tag_name'])\") && \
         [ -n \"$VERSION\" ] || {{ echo 'ERROR: could not resolve latest version for {repo}' >&2; exit 1; }} && \
         ASSET=\"{asset_name_expr}\" && \
         URL=\"https://github.com/{repo}/releases/download/${{VERSION}}/${{ASSET}}\" && \
         curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 \
           -o /tmp/{bin}.tar.gz \"$URL\" && \
         tar -xzf /tmp/{bin}.tar.gz -C /tmp/ && \
         BIN=$(find /tmp -maxdepth 3 -name {bin} -type f | head -1) && \
         [ -n \"$BIN\" ] || {{ echo 'ERROR: binary {bin} not found after extraction' >&2; exit 1; }} && \
         install -m 755 \"$BIN\" /usr/local/bin/{bin} && \
         rm -f /tmp/{bin}.tar.gz"
    );
    steps.push(
        StepSpec::new("download_binary", download_cmd)
            .with_check(format!("test -x /usr/local/bin/{bin}"))
            .with_timeout(300)
            .with_retries(2),
    );

    // 3. Optional config dir.
    if let Some(step) = config_dir_step(config) {
        steps.push(step);
    }

    // 4. Verify the binary is callable.
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
    fn go_binary_plan_has_minimum_expected_steps() {
        let cfg = InstallConfig {
            github_repo: "example/widget",
            binary_name: "widget",
            ..Default::default()
        };
        let steps = render(&cfg);
        // install_deps + download_binary + verify (no config_dir).
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].phase, "install_deps");
        assert_eq!(steps[1].phase, "download_binary");
        assert_eq!(steps[2].phase, "verify");
    }

    #[test]
    fn go_binary_includes_config_dir_when_set() {
        let cfg = InstallConfig {
            github_repo: "x/y",
            binary_name: "y",
            config_dir: "/root/.y",
            ..Default::default()
        };
        let steps = render(&cfg);
        assert!(
            steps.iter().any(|s| s.phase == "create_config_dir"),
            "expected create_config_dir step",
        );
    }

    #[test]
    fn go_binary_default_asset_pattern_uses_repo_tail() {
        let cfg = InstallConfig {
            github_repo: "org/MyTool",
            binary_name: "mytool",
            ..Default::default()
        };
        let steps = render(&cfg);
        let download = steps.iter().find(|s| s.phase == "download_binary").unwrap();
        // Default pattern: {repo}-linux-{arch}.tar.gz → MyTool-linux-amd64.tar.gz
        assert!(
            download.command.contains("MyTool-linux-amd64.tar.gz"),
            "command should embed the asset name, got: {}",
            download.command,
        );
    }

    #[test]
    fn go_binary_respects_custom_asset_pattern() {
        let cfg = InstallConfig {
            github_repo: "org/foo",
            binary_name: "foo",
            asset_pattern: "foo_{version}_{os}_{arch}.tar.gz",
            ..Default::default()
        };
        let steps = render(&cfg);
        let download = steps.iter().find(|s| s.phase == "download_binary").unwrap();
        // {version} stays shell-interpolated as ${VERSION}; {os} and {arch} expand.
        assert!(
            download
                .command
                .contains("foo_${VERSION}_linux_amd64.tar.gz"),
            "custom pattern did not expand, got: {}",
            download.command,
        );
    }

    #[test]
    fn go_binary_uses_custom_system_deps_when_provided() {
        let cfg = InstallConfig {
            github_repo: "x/y",
            binary_name: "y",
            system_deps: &["curl", "jq"],
            ..Default::default()
        };
        let steps = render(&cfg);
        let deps_step = steps.iter().find(|s| s.phase == "install_deps").unwrap();
        assert!(deps_step.command.contains("curl jq"));
    }

    #[test]
    fn go_binary_download_has_sane_timeout_and_retries() {
        let cfg = InstallConfig {
            github_repo: "x/y",
            binary_name: "y",
            ..Default::default()
        };
        let steps = render(&cfg);
        let download = steps.iter().find(|s| s.phase == "download_binary").unwrap();
        assert!(download.timeout_secs >= 120);
        assert!(download.max_retries >= 1);
        assert!(
            download.idempotency_check.as_deref() == Some("test -x /usr/local/bin/y"),
            "download should be idempotent on binary presence"
        );
    }

    #[test]
    fn trailing_repo_name_extracts_owner_last_segment() {
        assert_eq!(trailing_repo_name("foo/bar"), "bar");
        assert_eq!(trailing_repo_name("only"), "only");
        assert_eq!(trailing_repo_name("a/b/c"), "c");
    }
}
