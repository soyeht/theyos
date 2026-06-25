//! macOS claw installer plans — per-instance claw binary installation + launchd service.
//!
//! Equivalent to `vmrunner-rs/src/installer_plan.rs` but for macOS guest VMs.
//! Each claw type has an install plan that:
//! 1. Downloads/installs the claw binary via the fastest method (release binary > brew > npm/pip)
//! 2. Creates a launchd plist to run the claw as a daemon

use crate::VZError;
use crate::macos_guest::ssh_exec;

/// The pinned version for `claw` from the embedded manifest
/// (`claws/manifest.yml` via `core_rs::manifest`). Static lookup, no I/O.
fn manifest_version(claw: &str) -> Result<&'static str, VZError> {
    core_rs::manifest::get(claw)
        .map(|entry| entry.version)
        .ok_or_else(|| VZError::InvalidConfig(format!("no manifest entry for claw: {claw}")))
}

/// Build the shell command that installs `claw_type`'s binary inside a macOS
/// guest VM, or an error for an unknown claw.
///
/// Reads the pinned version from the embedded manifest (`manifest_version`), so
/// it stays a deterministic static lookup with no I/O and is unit-testable.
/// Every `curl` fetch is hardened to https + TLS >= 1.2 + retry. picoclaw,
/// nullclaw, ironclaw and nanobot are pinned to the manifest version; zeroclaw,
/// openclaw and hermes-agent still pull upstream `latest`/HEAD (their manifest
/// versions have no matching upstream release - see
/// `docs/macos-runner-artifact-posture.md`).
fn macos_install_command(claw_type: &str) -> Result<String, VZError> {
    let cmd = match claw_type {
        "picoclaw" => {
            let v = manifest_version("picoclaw")?;
            format!(
                "mkdir -p /usr/local/bin && \
                 curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 https://github.com/sipeed/picoclaw/releases/download/v{v}/picoclaw_Darwin_arm64.tar.gz \
                 | tar xz -C /usr/local/bin/ && chmod +x /usr/local/bin/picoclaw"
            )
        }
        "zeroclaw" => {
            "mkdir -p /usr/local/bin && \
             curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 https://github.com/zeroclaw-labs/zeroclaw/releases/latest/download/zeroclaw-aarch64-apple-darwin.tar.gz \
             | tar xz -C /tmp/ && install -m 755 /tmp/zeroclaw /usr/local/bin/zeroclaw && rm -f /tmp/zeroclaw"
                .to_string()
        }
        "nanobot" => {
            // pip installs to /opt/homebrew/bin/ when using brew Python, or ~/.local/bin/
            let v = manifest_version("nanobot")?;
            format!(
                "export PATH=/opt/homebrew/bin:$HOME/.local/bin:$PATH && \
                 pip3 install --break-system-packages nanobot-ai=={v} 2>/dev/null || \
                 python3 -m pip install --break-system-packages nanobot-ai=={v} 2>/dev/null || \
                 pip3 install nanobot-ai=={v}"
            )
        }
        "openclaw" => {
            // npm global installs to /opt/homebrew/bin/ via brew Node
            "export PATH=/opt/homebrew/bin:$PATH && \
             npm install -g openclaw 2>/dev/null && \
             cd /opt/homebrew/lib/node_modules/openclaw/node_modules/sharp 2>/dev/null && \
             npm install @img/sharp-darwin-arm64 2>/dev/null || true"
                .to_string()
        }
        "hermes-agent" => {
            r#"export PATH=/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH && \
             mkdir -p /opt/claws /usr/local/bin /opt/data /var/root/.hermes && \
             if [ -d /opt/claws/hermes-agent/.git ]; then \
               cd /opt/claws/hermes-agent && git pull --ff-only || true; \
             else \
               git clone --depth 1 https://github.com/NousResearch/hermes-agent /opt/claws/hermes-agent; \
             fi && \
             cd /opt/claws/hermes-agent && \
             python3 -m pip install --break-system-packages --no-cache-dir --ignore-installed -e ".[all]" && \
             npm install --prefer-offline --no-audit || true; \
             HERMES_BIN=$(command -v hermes 2>/dev/null || true); \
             test -n "$HERMES_BIN"; \
             printf '#!/bin/sh\nexport HERMES_HOME="${HERMES_HOME:-/opt/data}"\ncd /opt/claws/hermes-agent || exit 1\nexec "%s" "$@"\n' "$HERMES_BIN" > /usr/local/bin/hermes-agent && \
             chmod +x /usr/local/bin/hermes-agent && \
             hermes-agent --version 2>/dev/null || hermes-agent --help 2>/dev/null | head -1"#
                .to_string()
        }
        "nullclaw" => {
            let v = manifest_version("nullclaw")?;
            format!(
                "mkdir -p /usr/local/bin && \
                 curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 https://github.com/nullclaw/nullclaw/releases/download/v{v}/nullclaw-macos-aarch64.bin \
                 -o /usr/local/bin/nullclaw && chmod +x /usr/local/bin/nullclaw"
            )
        }
        "ironclaw" => {
            // ironclaw needs PostgreSQL 15+ - install via brew (as user theyos), then download binary.
            // Tarball extracts to ironclaw-aarch64-apple-darwin/ironclaw (subdirectory).
            // Upstream tag format migrated from `v<version>` to `ironclaw-v<version>`;
            // the pinned manifest version still resolves with the older `v<version>`
            // tag - re-verify the tag format before bumping the manifest version.
            let v = manifest_version("ironclaw")?;
            format!(
                "export PATH=/opt/homebrew/bin:$PATH && \
                 su - theyos -c 'brew install postgresql@15' 2>/dev/null; \
                 mkdir -p /usr/local/bin && \
                 curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 https://github.com/nearai/ironclaw/releases/download/v{v}/ironclaw-aarch64-apple-darwin.tar.gz \
                 | tar xz -C /tmp/ && install -m 755 /tmp/ironclaw-aarch64-apple-darwin/ironclaw /usr/local/bin/ironclaw \
                 && rm -rf /tmp/ironclaw-aarch64-apple-darwin"
            )
        }
        other => {
            return Err(VZError::InvalidConfig(format!(
                "Unknown claw type for macOS install: {other}"
            )));
        }
    };
    Ok(cmd)
}

/// Install a claw binary and start its service inside a macOS guest VM.
///
/// Called from `handle_create_macos` after the VM has DHCP + SSH.
///
/// # Errors
///
/// Returns `VZError` if claw binary download, launchd plist creation, or env file write fails.
#[allow(clippy::too_many_lines)]
pub async fn install_claw_and_start(
    host: &str,
    claw_type: &str,
    _instance_name: &str,
) -> Result<(), VZError> {
    tracing::info!(host, claw_type, "Installing claw binary...");

    // Step 1: Install the claw binary
    let install_cmd = macos_install_command(claw_type)?;

    ssh_exec(host, &install_cmd)
        .await
        .map_err(|e| VZError::Internal(format!("claw install ({claw_type}): {e}")))?;
    tracing::info!(claw_type, "Claw binary installed");

    // Hermes is an interactive terminal app, not a long-running gateway daemon.
    // `theyos-ssh pty` starts the real chat when a terminal attaches.
    if claw_type == "hermes-agent" {
        tracing::info!(claw_type, "Hermes installed; launchd service skipped");
        return Ok(());
    }

    // Step 2: Determine the run command
    let (binary, args) = match claw_type {
        "picoclaw" => ("/usr/local/bin/picoclaw", vec!["gateway"]),
        "zeroclaw" => ("/usr/local/bin/zeroclaw", vec!["gateway"]),
        "nanobot" => ("/usr/local/bin/nanobot", vec!["gateway"]),
        "openclaw" => (
            "/opt/homebrew/bin/node",
            vec![
                "/opt/homebrew/lib/node_modules/openclaw/dist/openclaw.mjs",
                "gateway",
            ],
        ),
        "nullclaw" => ("/usr/local/bin/nullclaw", vec!["gateway"]),
        "ironclaw" => ("/usr/local/bin/ironclaw", vec!["gateway"]),
        _ => return Err(VZError::InvalidConfig(format!("Unknown claw: {claw_type}"))),
    };

    // Step 3: Create launchd plist and start the service
    let args_xml: String = args
        .iter()
        .map(|a| format!("    <string>{a}</string>"))
        .collect::<Vec<_>>()
        .join("\n");

    let plist_cmd = format!(
        r#"mkdir -p /var/log/theyos && \
cat > /Library/LaunchDaemons/com.theyos.claw.plist << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.theyos.claw</string>
  <key>ProgramArguments</key>
  <array>
    <string>{binary}</string>
{args_xml}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>CLAW_TYPE</key>
    <string>{claw_type}</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>StandardOutPath</key>
  <string>/var/log/theyos/claw.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/theyos/claw.err</string>
</dict>
</plist>
PLIST_EOF
launchctl load /Library/LaunchDaemons/com.theyos.claw.plist"#
    );

    ssh_exec(host, &plist_cmd)
        .await
        .map_err(|e| VZError::Internal(format!("launchd plist create ({claw_type}): {e}")))?;
    tracing::info!(claw_type, "Claw launchd service started");

    tracing::info!(claw_type, "Claw fully provisioned");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every claw the macOS runner knows how to install today.
    const SUPPORTED_MACOS_CLAWS: &[&str] = &[
        "picoclaw",
        "zeroclaw",
        "nanobot",
        "openclaw",
        "hermes-agent",
        "nullclaw",
        "ironclaw",
    ];

    /// Claws whose macOS install is still NOT version-pinned. Their manifest
    /// version has no matching upstream release (no `v0.1.9` tag for zeroclaw,
    /// no npm `2026.4.6` for openclaw, hermes-agent uses date tags), so they
    /// stay on `latest`/HEAD until the manifest version is corrected. A new
    /// claw added with an unpinned fetch (`releases/latest/download`,
    /// `git clone` HEAD, or an unversioned pip/npm install) must be added here
    /// consciously, or pinned. See `docs/macos-runner-artifact-posture.md`.
    const UNPINNED_EXCEPTIONS: &[&str] = &["zeroclaw", "openclaw", "hermes-agent"];

    /// Reliable markers that a command fetches an unpinned upstream artifact.
    fn looks_unpinned(cmd: &str) -> bool {
        cmd.contains("releases/latest/download")
            || cmd.contains("git clone")
            || (cmd.contains("pip3 install") && !cmd.contains("=="))
            || (cmd.contains("npm install -g") && !cmd.contains("openclaw@"))
    }

    #[test]
    fn macos_curl_installs_use_all_hardened_flags() {
        // The full hardened flag set required for every macOS curl fetch.
        const REQUIRED_CURL_FLAGS: &[&str] = &[
            "--proto '=https'",
            "--tlsv1.2",
            "-fsSL",
            "--retry 3",
            "--retry-delay 2",
        ];
        for &claw in SUPPORTED_MACOS_CLAWS {
            let cmd = macos_install_command(claw).expect("supported claw builds a command");
            if cmd.contains("curl") {
                for flag in REQUIRED_CURL_FLAGS {
                    assert!(
                        cmd.contains(flag),
                        "{claw}: every curl must include the hardened flag {flag}"
                    );
                }
            }
        }
    }

    #[test]
    fn macos_unpinned_installs_are_inventoried() {
        // A claw that fetches an unpinned artifact must be acknowledged.
        for &claw in SUPPORTED_MACOS_CLAWS {
            let cmd = macos_install_command(claw).expect("supported claw");
            if looks_unpinned(&cmd) {
                assert!(
                    UNPINNED_EXCEPTIONS.contains(&claw),
                    "{claw} installs from an unpinned source but is not in \
                     UNPINNED_EXCEPTIONS; pin it (version-pin follow-up) or \
                     acknowledge it there"
                );
            }
        }
        // No rot: every inventoried exception must still actually be unpinned.
        for &claw in UNPINNED_EXCEPTIONS {
            let cmd = macos_install_command(claw).expect("supported claw");
            assert!(
                looks_unpinned(&cmd),
                "{claw} is inventoried as unpinned but now looks pinned; remove it \
                 from UNPINNED_EXCEPTIONS"
            );
        }
    }

    #[test]
    fn macos_install_command_rejects_unknown_claw() {
        assert!(macos_install_command("definitely-not-a-claw").is_err());
    }

    #[test]
    fn macos_pinned_installs_use_manifest_version() {
        // The pinned claws embed exactly the manifest version (no `latest`), so a
        // manifest bump is reflected in the install command. Reads the embedded
        // manifest, no network.
        for claw in ["picoclaw", "nullclaw", "ironclaw", "nanobot"] {
            let cmd = macos_install_command(claw).expect("supported claw");
            let version = core_rs::manifest::get(claw)
                .expect("claw is in the manifest")
                .version;
            assert!(
                cmd.contains(version),
                "{claw}: pinned command must contain the manifest version {version}"
            );
            assert!(
                !cmd.contains("releases/latest/download"),
                "{claw}: pinned command must not use releases/latest/download"
            );
        }
        // nanobot specifically pins the pip package version.
        let nanobot = macos_install_command("nanobot").expect("nanobot");
        assert!(
            nanobot.contains("nanobot-ai=="),
            "nanobot must pin the pip package with nanobot-ai=="
        );
    }
}
