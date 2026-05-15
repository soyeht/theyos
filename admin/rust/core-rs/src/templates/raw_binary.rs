//! `raw-binary` template — curl a prebuilt binary from an absolute URL.
//!
//! Use when the claw publishes a single statically-linked binary at a stable
//! URL (CDN, GitHub release asset path, etc.) rather than a tarball. The URL
//! goes in `config.binary_path`.

use super::{StepSpec, apt_install_step, config_dir_step};
use crate::manifest::InstallConfig;

const DEFAULT_DEPS: &[&str] = &["curl", "ca-certificates"];

/// Render the install steps for a single-binary download.
#[must_use]
pub fn render(config: &InstallConfig) -> Vec<StepSpec> {
    let url = config.binary_path;
    let bin = if config.binary_name.is_empty() {
        // Fall back to last URL segment without query string.
        let tail = url.rsplit('/').next().unwrap_or(url);
        tail.split(&['?', '#'][..]).next().unwrap_or(tail)
    } else {
        config.binary_name
    };

    let mut steps = Vec::with_capacity(4);

    // 1. Deps.
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

    // 2. Download + install.
    let download_cmd = format!(
        "curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 \
           -o /tmp/{bin} '{url}' && \
         install -m 755 /tmp/{bin} /usr/local/bin/{bin} && \
         rm -f /tmp/{bin}"
    );
    steps.push(
        StepSpec::new("download_binary", download_cmd)
            .with_check(format!("test -x /usr/local/bin/{bin}"))
            .with_timeout(180)
            .with_retries(2),
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
    fn raw_binary_has_expected_steps() {
        let cfg = InstallConfig {
            binary_path: "https://example.com/downloads/mytool-linux-amd64",
            binary_name: "mytool",
            ..Default::default()
        };
        let steps = render(&cfg);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].phase, "install_deps");
        assert_eq!(steps[1].phase, "download_binary");
        assert_eq!(steps[2].phase, "verify");
    }

    #[test]
    fn raw_binary_downloads_from_exact_url() {
        let cfg = InstallConfig {
            binary_path: "https://example.com/x.bin",
            binary_name: "x",
            ..Default::default()
        };
        let step = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "download_binary")
            .unwrap();
        assert!(step.command.contains("https://example.com/x.bin"));
        assert!(step.command.contains("curl --proto '=https'"));
        assert_eq!(
            step.idempotency_check.as_deref(),
            Some("test -x /usr/local/bin/x")
        );
    }

    #[test]
    fn raw_binary_infers_name_from_url_tail() {
        let cfg = InstallConfig {
            binary_path: "https://cdn.example.com/releases/latest/foo",
            // binary_name intentionally empty → inference.
            ..Default::default()
        };
        let step = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "download_binary")
            .unwrap();
        assert!(step.command.contains("/usr/local/bin/foo"));
    }

    #[test]
    fn raw_binary_strips_query_string_from_inferred_name() {
        let cfg = InstallConfig {
            binary_path: "https://cdn.example.com/foo?token=xyz",
            ..Default::default()
        };
        let step = render(&cfg)
            .into_iter()
            .find(|s| s.phase == "download_binary")
            .unwrap();
        // /tmp/foo, not /tmp/foo?token=xyz
        assert!(step.command.contains("/tmp/foo "));
    }

    #[test]
    fn raw_binary_config_dir_optional() {
        let with = InstallConfig {
            binary_path: "https://x/y",
            binary_name: "y",
            config_dir: "/root/.y",
            ..Default::default()
        };
        assert!(render(&with).iter().any(|s| s.phase == "create_config_dir"));

        let without = InstallConfig {
            binary_path: "https://x/y",
            binary_name: "y",
            ..Default::default()
        };
        assert!(
            !render(&without)
                .iter()
                .any(|s| s.phase == "create_config_dir")
        );
    }
}
