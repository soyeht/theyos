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

/// theyos-pinned sha256 of each macOS release asset that has no upstream
/// checksum, keyed by `(claw, manifest version, lowercase 64-hex sha256)`. The
/// installer verifies the downloaded asset against this before extracting; a
/// guard test asserts each version tracks the manifest, so a version bump cannot
/// ship a stale checksum. ironclaw uses its upstream `.sha256` and is not listed
/// here.
const MACOS_PINNED_SHA256: &[(&str, &str, &str)] = &[
    (
        "picoclaw",
        "0.2.5",
        "b42f93dc3c79e2e41f2852c8890beece6334afc1d09acf165e072ce64d2d018f",
    ),
    (
        "nullclaw",
        "2026.3.1",
        "25a037041fe0a1845a4e586d0a3d72a688aff704ef52c4f5f39bbcfd5ea9a198",
    ),
    (
        "zeroclaw",
        "0.8.1",
        "d37c15aba3e4e6ec622d305b3d36172964a1239245704fb758e1d01560362841",
    ),
];

/// The theyos-pinned sha256 for `claw`'s macOS asset, or an error if absent.
fn pinned_sha256(claw: &str) -> Result<&'static str, VZError> {
    MACOS_PINNED_SHA256
        .iter()
        .find(|(c, _, _)| *c == claw)
        .map(|(_, _, sha)| *sha)
        .ok_or_else(|| VZError::InvalidConfig(format!("no pinned sha256 for claw: {claw}")))
}

/// Build the shell command that installs `claw_type`'s binary inside a macOS
/// guest VM, or an error for an unknown claw.
///
/// Reads the pinned version from the embedded manifest (`manifest_version`), so
/// it stays a deterministic static lookup with no I/O and is unit-testable.
/// Every `curl` fetch is hardened to https + TLS >= 1.2 + retry. All seven claws
/// read their version from the manifest; hermes-agent pins its git tag
/// (`git clone --branch`) rather than a release asset - a partial pin, since its
/// pip/npm build deps still float and there is no checksum (it builds from
/// source). See `docs/macos-runner-artifact-posture.md`.
fn macos_install_command(claw_type: &str) -> Result<String, VZError> {
    let cmd = match claw_type {
        "picoclaw" => {
            // Pinned tarball + theyos-pinned sha256 (upstream publishes none):
            // download to a temp dir, verify against the repo-pinned hash, then
            // extract and install. A mismatch breaks the && chain (fail-closed).
            let v = manifest_version("picoclaw")?;
            let sha = pinned_sha256("picoclaw")?;
            format!(
                "mkdir -p /usr/local/bin && \
                 d=$(mktemp -d) && cd \"$d\" && \
                 curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 -O https://github.com/sipeed/picoclaw/releases/download/v{v}/picoclaw_Darwin_arm64.tar.gz && \
                 printf '%s  %s\\n' \"{sha}\" \"picoclaw_Darwin_arm64.tar.gz\" | shasum -a 256 -c - && \
                 tar xzf picoclaw_Darwin_arm64.tar.gz && install -m 755 picoclaw /usr/local/bin/picoclaw && \
                 cd / && rm -rf \"$d\""
            )
        }
        "zeroclaw" => {
            // Pinned tarball + theyos-pinned sha256 (upstream publishes none):
            // download to a temp dir, verify, then extract and install.
            let v = manifest_version("zeroclaw")?;
            let sha = pinned_sha256("zeroclaw")?;
            format!(
                "mkdir -p /usr/local/bin && \
                 d=$(mktemp -d) && cd \"$d\" && \
                 curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 -O https://github.com/zeroclaw-labs/zeroclaw/releases/download/v{v}/zeroclaw-aarch64-apple-darwin.tar.gz && \
                 printf '%s  %s\\n' \"{sha}\" \"zeroclaw-aarch64-apple-darwin.tar.gz\" | shasum -a 256 -c - && \
                 tar xzf zeroclaw-aarch64-apple-darwin.tar.gz && install -m 755 zeroclaw /usr/local/bin/zeroclaw && \
                 cd / && rm -rf \"$d\""
            )
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
            // npm global installs to /opt/homebrew/bin/ via brew Node. Pinned to
            // the manifest version; npm verifies registry integrity on install.
            let v = manifest_version("openclaw")?;
            format!(
                "export PATH=/opt/homebrew/bin:$PATH && \
                 npm install -g openclaw@{v} 2>/dev/null && \
                 cd /opt/homebrew/lib/node_modules/openclaw/node_modules/sharp 2>/dev/null && \
                 npm install @img/sharp-darwin-arm64 2>/dev/null || true"
            )
        }
        "hermes-agent" => {
            // Pinned to the manifest version's git tag (was a HEAD `git clone`).
            // This pins only the source checkout - pip/npm build deps still float
            // and there is no checksum (source build), so it is a partial pin.
            let v = manifest_version("hermes-agent")?;
            format!(
                r#"export PATH=/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH && \
             mkdir -p /opt/claws /usr/local/bin /opt/data /var/root/.hermes && \
             if [ -d /opt/claws/hermes-agent/.git ]; then \
               cd /opt/claws/hermes-agent && git fetch --depth 1 origin tag v{v} && git checkout -f v{v}; \
             else \
               git clone --depth 1 --branch v{v} https://github.com/NousResearch/hermes-agent /opt/claws/hermes-agent; \
             fi && \
             cd /opt/claws/hermes-agent && \
             python3 -m pip install --break-system-packages --no-cache-dir --ignore-installed -e ".[all]" && \
             npm install --prefer-offline --no-audit || true; \
             HERMES_BIN=$(command -v hermes 2>/dev/null || true); \
             test -n "$HERMES_BIN"; \
             printf '#!/bin/sh\nexport HERMES_HOME="${{HERMES_HOME:-/opt/data}}"\ncd /opt/claws/hermes-agent || exit 1\nexec "%s" "$@"\n' "$HERMES_BIN" > /usr/local/bin/hermes-agent && \
             chmod +x /usr/local/bin/hermes-agent && \
             hermes-agent --version 2>/dev/null || hermes-agent --help 2>/dev/null | head -1"#
            )
        }
        "nullclaw" => {
            // Pinned binary + theyos-pinned sha256 (upstream publishes none):
            // download to a temp dir, verify, then install.
            let v = manifest_version("nullclaw")?;
            let sha = pinned_sha256("nullclaw")?;
            format!(
                "mkdir -p /usr/local/bin && \
                 d=$(mktemp -d) && cd \"$d\" && \
                 curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 -O https://github.com/nullclaw/nullclaw/releases/download/v{v}/nullclaw-macos-aarch64.bin && \
                 printf '%s  %s\\n' \"{sha}\" \"nullclaw-macos-aarch64.bin\" | shasum -a 256 -c - && \
                 install -m 755 nullclaw-macos-aarch64.bin /usr/local/bin/nullclaw && \
                 cd / && rm -rf \"$d\""
            )
        }
        "ironclaw" => {
            // ironclaw needs PostgreSQL 15+ - install via brew (as user theyos), then download binary.
            // Tarball extracts to ironclaw-aarch64-apple-darwin/ironclaw (subdirectory).
            // Upstream tag format migrated from `v<version>` to `ironclaw-v<version>`;
            // the pinned manifest version still resolves with the older `v<version>`
            // tag - re-verify the tag and the .sha256 before bumping the manifest version.
            //
            // Integrity: download the pinned tarball and its upstream `<asset>.sha256`
            // into a temp dir and verify with `shasum -a 256 -c` (the macOS guest ships
            // `shasum`, not coreutils `sha256sum`) before extracting. A mismatch breaks
            // the `&&` chain, so nothing is extracted or installed (fail-closed).
            let v = manifest_version("ironclaw")?;
            format!(
                "export PATH=/opt/homebrew/bin:$PATH && \
                 su - theyos -c 'brew install postgresql@15' 2>/dev/null; \
                 mkdir -p /usr/local/bin && \
                 d=$(mktemp -d) && cd \"$d\" && \
                 curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 -O https://github.com/nearai/ironclaw/releases/download/v{v}/ironclaw-aarch64-apple-darwin.tar.gz && \
                 curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 -O https://github.com/nearai/ironclaw/releases/download/v{v}/ironclaw-aarch64-apple-darwin.tar.gz.sha256 && \
                 shasum -a 256 -c ironclaw-aarch64-apple-darwin.tar.gz.sha256 && \
                 tar xzf ironclaw-aarch64-apple-darwin.tar.gz && \
                 install -m 755 ironclaw-aarch64-apple-darwin/ironclaw /usr/local/bin/ironclaw && \
                 cd / && rm -rf \"$d\""
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

    /// Claws whose macOS install is still NOT version-pinned. Empty now that all
    /// macOS claws pin a version (hermes-agent pins its git tag via
    /// `git clone --branch`). A new claw added with an unpinned fetch
    /// (`releases/latest/download`, a HEAD `git clone` without `--branch`, or an
    /// unversioned pip/npm install) must be added here consciously, or pinned.
    /// See `docs/macos-runner-artifact-posture.md`.
    const UNPINNED_EXCEPTIONS: &[&str] = &[];

    /// Reliable markers that a command fetches an unpinned upstream artifact.
    fn looks_unpinned(cmd: &str) -> bool {
        cmd.contains("releases/latest/download")
            || (cmd.contains("git clone") && !cmd.contains("--branch"))
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
            // Check EVERY curl invocation (e.g. ironclaw fetches the tarball and its
            // .sha256), not just that the flags appear somewhere in the command. The
            // options of each curl are the text between `curl ` and the `https://` URL.
            for (i, after) in cmd.split("curl ").enumerate().skip(1) {
                let opts = after.split("https://").next().unwrap_or("");
                for flag in REQUIRED_CURL_FLAGS {
                    assert!(
                        opts.contains(flag),
                        "{claw}: curl #{i} must include the hardened flag {flag}"
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
    fn macos_ironclaw_verifies_checksum_before_extract() {
        let cmd = macos_install_command("ironclaw").expect("ironclaw");
        // Downloads the upstream per-asset checksum and verifies it.
        assert!(
            cmd.contains("ironclaw-aarch64-apple-darwin.tar.gz.sha256"),
            "ironclaw must download the upstream .sha256: {cmd}"
        );
        assert!(
            cmd.contains("shasum -a 256 -c"),
            "ironclaw must verify with shasum -a 256 -c: {cmd}"
        );
        // macOS guest ships `shasum`, not coreutils `sha256sum`.
        assert!(
            !cmd.contains("sha256sum"),
            "use shasum on the macOS guest, not sha256sum: {cmd}"
        );
        // Verification happens before extraction and install (fail-closed).
        let verify = cmd.find("shasum -a 256 -c").expect("shasum present");
        let extract = cmd.find("tar xz").expect("tar present");
        let install = cmd.find("install -m 755").expect("install present");
        assert!(verify < extract, "checksum must precede tar extract: {cmd}");
        assert!(verify < install, "checksum must precede install: {cmd}");
    }

    #[test]
    fn macos_checksummed_claws_verify_a_checksum() {
        // ironclaw verifies its upstream .sha256; picoclaw/nullclaw/zeroclaw
        // verify a theyos-pinned sha256. No other claw fakes a checksum.
        const CHECKSUMMED: &[&str] = &["ironclaw", "picoclaw", "nullclaw", "zeroclaw"];
        for &claw in SUPPORTED_MACOS_CLAWS {
            let cmd = macos_install_command(claw).expect("supported claw");
            let has_checksum = cmd.contains("shasum -a 256 -c");
            assert_eq!(
                has_checksum,
                CHECKSUMMED.contains(&claw),
                "{claw}: checksum verification membership mismatch"
            );
        }
    }

    #[test]
    fn macos_pinned_sha256_matches_manifest_and_is_well_formed() {
        for &(claw, version, sha) in MACOS_PINNED_SHA256 {
            // The pinned version must track the manifest, so a version bump that
            // forgets to recompute the checksum fails here.
            assert_eq!(
                version,
                core_rs::manifest::get(claw)
                    .expect("claw in manifest")
                    .version,
                "{claw}: MACOS_PINNED_SHA256 version is stale vs the manifest"
            );
            // 64 lowercase hex.
            assert_eq!(sha.len(), 64, "{claw}: sha256 must be 64 hex chars");
            assert!(
                sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "{claw}: sha256 must be lowercase hex"
            );
            // The command embeds this sha and verifies before extract/install.
            let cmd = macos_install_command(claw).expect("supported claw");
            assert!(
                cmd.contains(sha),
                "{claw}: command must embed the pinned sha"
            );
            let verify = cmd.find("shasum -a 256 -c").expect("shasum present");
            if let Some(t) = cmd.find("tar xz") {
                assert!(verify < t, "{claw}: checksum must precede tar");
            }
            if let Some(i) = cmd.find("install -m 755") {
                assert!(verify < i, "{claw}: checksum must precede install");
            }
        }
    }

    #[test]
    fn macos_pinned_installs_use_manifest_version() {
        // The pinned claws embed exactly the manifest version (no `latest`), so a
        // manifest bump is reflected in the install command. Reads the embedded
        // manifest, no network.
        for claw in [
            "picoclaw",
            "nullclaw",
            "ironclaw",
            "nanobot",
            "zeroclaw",
            "openclaw",
            "hermes-agent",
        ] {
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
