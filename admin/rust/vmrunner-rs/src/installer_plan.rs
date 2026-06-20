//! `installer_plan.rs` — Typed install step framework (P10).
// NOTE: VmError is large by design (rich diagnostic context); boxing would require
// pervasive API changes across all callers.
#![allow(clippy::result_large_err)]
//!
//! Instead of uploading and running a monolithic `.sh` script, each claw type
//! can define an `InstallerPlan` — an ordered sequence of `InstallerStep`s.
//! Each step runs a single command in the guest VM, captures structured output
//! (`exit_code`, stdout, stderr, `elapsed_ms`, phase), and surfaces a rich
//! `ErrorContext` on failure.
//!
//! Benefits over the shell-script approach:
//! - No parsing of stdout/stderr to detect failure — `exit_code` is authoritative.
//! - `phase` label per step → operator sees exactly which step failed.
//! - Retry policy per step (e.g. network downloads).
//! - Full `ErrorContext` even for the first failure, not just the last.
//! - Idempotency checks expressed as typed predicates, not bash conditions.
//!
//! # Architecture
//!
//! ```text
//! InstallerPlan
//!   └─ Vec<InstallerStep>
//!        ├─ phase: String          (label in ErrorContext)
//!        ├─ command: String        (shell command run in guest)
//!        ├─ idempotency_check: Option<String>  (if exits 0, step is skipped)
//!        ├─ timeout: Duration
//!        └─ max_retries: u8
//! ```

use std::borrow::Cow;
use std::time::Duration;

use core_rs::node_source::{INSTALL_NODE_22_COMMAND, NODE_22_12_CHECK, NODE_22_CHECK};

use crate::error::{ErrorContext, VmError};
use crate::ssh_client::SshActions;

/// A single step within an `InstallerPlan`.
#[derive(Debug, Clone)]
pub struct InstallerStep {
    /// Short label used in `ErrorContext.phase` (e.g. `"install_deps"`).
    pub phase: &'static str,
    /// Shell command to run in the guest (runs via `sh -lc` inside the VM).
    pub command: Cow<'static, str>,
    /// Optional idempotency check: if this command exits 0, skip the step.
    /// Should be a fast test (e.g. `test -x /usr/local/bin/foo`).
    pub idempotency_check: Option<&'static str>,
    /// Per-step timeout. Defaults to 120s; long downloads may need more.
    pub(crate) timeout: Duration,
    /// How many times to retry on failure (0 = no retry).
    pub max_retries: u8,
}

impl InstallerStep {
    pub fn new(phase: &'static str, command: impl Into<Cow<'static, str>>) -> Self {
        InstallerStep {
            phase,
            command: command.into(),
            idempotency_check: None,
            timeout: Duration::from_secs(120),
            max_retries: 0,
        }
    }

    #[must_use]
    pub fn with_check(mut self, check: &'static str) -> Self {
        self.idempotency_check = Some(check);
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout = Duration::from_secs(secs);
        self
    }

    #[must_use]
    pub fn with_retries(mut self, n: u8) -> Self {
        self.max_retries = n;
        self
    }
}

/// An ordered sequence of `InstallerStep`s for a given claw type.
pub struct InstallerPlan {
    pub(crate) claw_type: &'static str,
    pub steps: Vec<InstallerStep>,
}

impl InstallerPlan {
    /// Compute a deterministic SHA-256 hash of this plan's effective configuration.
    ///
    /// Includes: step phases, expanded commands (with env vars already resolved),
    /// idempotency checks, timeouts, and retry counts.  Two plans built from
    /// the same source code with the same environment variables will produce the
    /// same hash; changing any env var that affects the commands will change it.
    ///
    /// The hash is computed over a canonical text representation to ensure
    /// stability across compiler versions and struct layout changes.
    #[must_use]
    pub fn content_hash(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.claw_type.as_bytes());
        hasher.update(b"\n");

        for step in &self.steps {
            hasher.update(step.phase.as_bytes());
            hasher.update(b"|");
            hasher.update(step.command.as_bytes());
            hasher.update(b"|");
            hasher.update(step.idempotency_check.unwrap_or("").as_bytes());
            hasher.update(b"|");
            hasher.update(step.timeout.as_secs().to_string().as_bytes());
            hasher.update(b"|");
            hasher.update(step.max_retries.to_string().as_bytes());
            hasher.update(b"\n");
        }

        // Inline hex encoding (same as core_rs::artifact_meta::hex)
        hasher
            .finalize()
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    /// Execute all steps in order.
    ///
    /// Returns `Ok(())` if every step succeeds (or is idempotently skipped).
    /// Returns `Err(VmError)` on the first step that fails after all retries,
    /// with a structured `ErrorContext` pointing to the exact phase and command.
    ///
    /// # Errors
    ///
    /// Returns an error if any step fails after exhausting its retry budget.
    pub async fn execute(&self, ssh: &dyn SshActions) -> Result<(), VmError> {
        let claw = self.claw_type;

        for step in &self.steps {
            // Idempotency check: skip step if already done
            if let Some(check) = step.idempotency_check {
                tracing::debug!(
                    "[plan][{claw}][{}] checking idempotency: {check}",
                    step.phase
                );
                if ssh.exec(check).await.is_ok() {
                    tracing::info!("[plan][{claw}][{}] already done — skipping", step.phase);
                    continue;
                }
                // Not done yet — proceed with execution
            }

            tracing::info!("[plan][{claw}][{}] running: {}", step.phase, step.command);

            let mut last_err: Option<VmError> = None;
            let max_attempts = 1 + step.max_retries as usize;

            for attempt in 0..max_attempts {
                if attempt > 0 {
                    // NOTE: attempt ≤ max_retries as usize ≤ u8::MAX; safe cast to u32.
                    #[allow(clippy::cast_possible_truncation)]
                    let delay = std::cmp::min(2u64.pow(attempt as u32), 30);
                    tracing::warn!(
                        "[plan][{claw}][{}] attempt {}/{max_attempts}, retrying in {delay}s...",
                        step.phase,
                        attempt + 1,
                    );
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }

                match ssh.exec_install(&step.command).await {
                    Ok(_) => {
                        tracing::info!("[plan][{claw}][{}] OK", step.phase);
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "[plan][{claw}][{}] attempt {} failed: {e}",
                            step.phase,
                            attempt + 1,
                        );
                        last_err = Some(e);
                    }
                }
            }

            if let Some(e) = last_err {
                // Enrich the error with plan-level context
                let base_ctx = e
                    .context()
                    .cloned()
                    .unwrap_or_else(|| ErrorContext::with_phase(step.phase));

                let ctx = ErrorContext {
                    phase: Some(format!("installer.{claw}.{}", step.phase)),
                    command: base_ctx.command.or_else(|| Some(step.command.to_string())),
                    ..base_ctx
                };

                return Err(VmError::installer_failed(
                    format!("{claw} installer failed at step '{}': {e}", step.phase),
                    ctx,
                ));
            }
        }

        tracing::info!("[plan][{claw}] all steps completed");
        Ok(())
    }
}

// ── Shared steps ──────────────────────────────────────────────────────────

/// Create an `InstallerStep` that writes `/root/.bashrc` with the theyOS
/// shell prompt — a bold `> ` that turns green on success, amber on error.
fn shell_prompt_step(_claw_type: &str) -> InstallerStep {
    let ok = core_rs::constants::PROMPT_COLOR_OK;
    let warn = core_rs::constants::PROMPT_COLOR_WARN;
    let cmd = format!(
        r#"cat > /root/.bashrc << 'BASHRC'
# theyOS shell prompt
PROMPT_COMMAND='if [ $? -eq 0 ]; then PS1="\[\{ok}\]> \[\033[0m\]"; else PS1="\[\{warn}\]> \[\033[0m\]"; fi'
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
BASHRC"#
    );
    InstallerStep::new("setup_shell_prompt", cmd)
}

// ── Plan definitions ───────────────────────────────────────────────────────

/// Nullclaw install plan.
///
/// nullclaw is a pre-built binary from GitHub releases — no compilation.
/// Steps: install deps → download binary → create config dir → verify.
#[must_use]
pub fn nullclaw_plan() -> InstallerPlan {
    let version = std::env::var("NULLCLAW_VERSION").unwrap_or_else(|_| "v2026.3.1".into());
    let url = format!(
        "https://github.com/nullclaw/nullclaw/releases/download/{version}/nullclaw-linux-x86_64.bin"
    );
    let download_cmd = format!(
        "export DEBIAN_FRONTEND=noninteractive && \
         apt-get update -qq && \
         apt-get install -y --no-install-recommends curl ca-certificates >/dev/null 2>&1 && \
         curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 \
           -o /tmp/nullclaw '{url}' && \
         install -m 755 /tmp/nullclaw /usr/local/bin/nullclaw && \
         rm -f /tmp/nullclaw"
    );

    InstallerPlan {
        claw_type: "nullclaw",
        steps: vec![
            InstallerStep::new("download_binary", download_cmd)
                .with_check("test -x /usr/local/bin/nullclaw")
                .with_timeout(180)
                .with_retries(2),
            InstallerStep::new("create_config_dir", "mkdir -p /root/.nullclaw"),
            InstallerStep::new(
                "verify",
                "nullclaw --version 2>/dev/null || nullclaw --help 2>/dev/null | head -1 || true",
            ),
            shell_prompt_step("nullclaw"),
        ],
    }
}

/// Picoclaw install plan.
///
/// picoclaw downloads a pre-built binary from GitHub releases.
/// Steps: install deps → fetch latest tag → download tarball → install → verify.
#[must_use]
pub fn picoclaw_plan() -> InstallerPlan {
    let version = std::env::var("PICOCLAW_VERSION").unwrap_or_default();

    // If version is pinned use it directly; otherwise fetch latest from API.
    let download_cmd: Cow<'static, str> = if version.is_empty() {
        Cow::Borrowed(
            "export DEBIAN_FRONTEND=noninteractive && \
             apt-get update -qq && \
             apt-get install -y --no-install-recommends curl ca-certificates python3 >/dev/null 2>&1 && \
             PICOCLAW_VERSION=$(curl -fsSL 'https://api.github.com/repos/sipeed/picoclaw/releases/latest' \
               | python3 -c \"import sys,json; print(json.load(sys.stdin)['tag_name'])\") && \
             [ -n \"$PICOCLAW_VERSION\" ] || { echo 'ERROR: could not determine picoclaw version' >&2; exit 1; } && \
             curl -fsSL --retry 3 \
               \"https://github.com/sipeed/picoclaw/releases/download/${PICOCLAW_VERSION}/picoclaw_Linux_x86_64.tar.gz\" \
               -o /tmp/picoclaw.tar.gz && \
             tar -xzf /tmp/picoclaw.tar.gz -C /tmp/ && \
             BIN=$(find /tmp -maxdepth 1 -name picoclaw -type f | head -1) && \
             [ -n \"$BIN\" ] || { echo 'ERROR: binary not found after extraction' >&2; exit 1; } && \
             mv \"$BIN\" /usr/local/bin/picoclaw && \
             chmod +x /usr/local/bin/picoclaw && \
             rm -f /tmp/picoclaw.tar.gz",
        )
    } else {
        let url = format!(
            "https://github.com/sipeed/picoclaw/releases/download/{version}/picoclaw_Linux_x86_64.tar.gz"
        );
        Cow::Owned(format!(
            "export DEBIAN_FRONTEND=noninteractive && \
             apt-get update -qq && \
             apt-get install -y --no-install-recommends curl ca-certificates >/dev/null 2>&1 && \
             curl -fsSL --retry 3 '{url}' -o /tmp/picoclaw.tar.gz && \
             tar -xzf /tmp/picoclaw.tar.gz -C /tmp/ && \
             BIN=$(find /tmp -maxdepth 1 -name picoclaw -type f | head -1) && \
             [ -n \"$BIN\" ] || {{ echo 'ERROR: binary not found after extraction' >&2; exit 1; }} && \
             mv \"$BIN\" /usr/local/bin/picoclaw && \
             chmod +x /usr/local/bin/picoclaw && \
             rm -f /tmp/picoclaw.tar.gz"
        ))
    };

    InstallerPlan {
        claw_type: "picoclaw",
        steps: vec![
            InstallerStep::new("download_binary", download_cmd)
                .with_check("test -x /usr/local/bin/picoclaw")
                .with_timeout(240)
                .with_retries(2),
            InstallerStep::new("create_config_dir", "mkdir -p /root/.picoclaw"),
            InstallerStep::new(
                "verify",
                "picoclaw --version 2>/dev/null || picoclaw --help 2>/dev/null | head -1 || true",
            ),
            shell_prompt_step("picoclaw"),
        ],
    }
}

/// Zeroclaw install plan (builds from source — Rust + cargo).
#[must_use]
pub fn zeroclaw_plan() -> InstallerPlan {
    let repo_url = std::env::var("ZEROCLAW_REPO_URL")
        .unwrap_or_else(|_| "https://github.com/openagen/zeroclaw".into());
    let repo_ref = std::env::var("ZEROCLAW_REPO_REF").unwrap_or_else(|_| "main".into());

    let clone_cmd = format!(
        "if [ -d /opt/claws/zeroclaw ]; then \
           cd /opt/claws/zeroclaw && git fetch origin && git checkout '{repo_ref}' && git pull origin '{repo_ref}' || true; \
         else \
           mkdir -p /opt/claws && \
           git clone --depth 1 --branch '{repo_ref}' '{repo_url}' /opt/claws/zeroclaw; \
         fi"
    );

    InstallerPlan {
        claw_type: "zeroclaw",
        steps: vec![
            InstallerStep::new(
                "install_deps",
                "export DEBIAN_FRONTEND=noninteractive && \
                 apt-get update -qq && \
                 apt-get install -y --no-install-recommends \
                   git build-essential pkg-config ca-certificates curl >/dev/null 2>&1",
            )
            .with_timeout(180),
            InstallerStep::new(
                "install_rust",
                "if ! command -v rustc >/dev/null 2>&1; then \
                   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
                     | sh -s -- -y --default-toolchain stable; \
                 fi",
            )
            .with_timeout(300)
            .with_retries(1),
            InstallerStep::new("clone_repo", clone_cmd)
                .with_timeout(180)
                .with_retries(2),
            InstallerStep::new(
                "build",
                "cd /opt/claws/zeroclaw && \
                 source $HOME/.cargo/env 2>/dev/null || true && \
                 cargo build --release --locked >/dev/null 2>&1 && \
                 cargo install --path . --force --locked >/dev/null 2>&1 && \
                 [ -f $HOME/.cargo/bin/zeroclaw ] && \
                   cp $HOME/.cargo/bin/zeroclaw /usr/local/bin/zeroclaw || true && \
                 chmod +x /usr/local/bin/zeroclaw 2>/dev/null || true",
            )
            .with_check("test -x /usr/local/bin/zeroclaw")
            .with_timeout(600)
            .with_retries(1),
            InstallerStep::new("create_config_dir", "mkdir -p /root/.zeroclaw"),
            InstallerStep::new(
                "verify",
                "zeroclaw --version 2>/dev/null || zeroclaw --help 2>/dev/null | head -1 || true",
            ),
            shell_prompt_step("zeroclaw"),
        ],
    }
}

/// Nanobot install plan (Python package from `PyPI`).
///
/// The `PyPI` package is `nanobot-ai` which provides the `nanobot` CLI entry point.
/// Steps: install deps → pip install nanobot-ai → link binary → create config dir → verify.
#[must_use]
pub fn nanobot_plan() -> InstallerPlan {
    let version = std::env::var("NANOBOT_VERSION").unwrap_or_default();

    let install_cmd = if version.is_empty() {
        "pip3 install --break-system-packages --ignore-installed nanobot-ai".to_string()
    } else {
        format!("pip3 install --break-system-packages --ignore-installed nanobot-ai=={version}")
    };

    InstallerPlan {
        claw_type: "nanobot",
        steps: vec![
            InstallerStep::new(
                "install_deps",
                "export DEBIAN_FRONTEND=noninteractive && \
                 apt-get update -qq && \
                 apt-get install -y --no-install-recommends \
                   python3 python3-pip ca-certificates >/dev/null 2>&1",
            )
            .with_timeout(180),
            InstallerStep::new("install_package", install_cmd)
                .with_check("test -x /usr/local/bin/nanobot")
                .with_timeout(300)
                .with_retries(1),
            // pip may install the entry point to /usr/local/bin or ~/.local/bin;
            // ensure it is reachable at /usr/local/bin/nanobot.
            InstallerStep::new(
                "link_binary",
                "if [ ! -x /usr/local/bin/nanobot ]; then \
                   for candidate in \
                     /usr/bin/nanobot \
                     \"$HOME/.local/bin/nanobot\" \
                     \"$(python3 -c 'import sys; print(sys.prefix)' 2>/dev/null)/bin/nanobot\"; do \
                     if [ -x \"$candidate\" ]; then \
                       ln -sf \"$candidate\" /usr/local/bin/nanobot; \
                       break; \
                     fi; \
                   done; \
                 fi",
            )
            .with_timeout(30),
            InstallerStep::new("create_config_dir", "mkdir -p /root/.nanobot"),
            InstallerStep::new(
                "verify",
                "nanobot --version 2>/dev/null || nanobot --help 2>/dev/null | head -1 || true",
            ),
            shell_prompt_step("nanobot"),
        ],
    }
}

/// Openclaw install plan (Node.js, build from source).
///
/// Mirrors `install-openclaw.sh`:
///   1. System deps (git, curl, ca-certificates)
///   2. Node.js 22+ via `NodeSource` (`MIN_NODE_VERSION=22`)
///   3. pnpm via npm, fallback to standalone script
///   4. Clone / update repo
///   5. pnpm install + build
///   6. Create wrapper at /usr/local/bin/openclaw pointing to built dist entry
///   7. Create config dir
///   8. Verify
#[must_use]
pub fn openclaw_plan() -> InstallerPlan {
    let repo_url = std::env::var("OPENCLAW_REPO_URL")
        .unwrap_or_else(|_| "https://github.com/openclaw/openclaw".into());
    let repo_ref = std::env::var("OPENCLAW_REPO_REF").unwrap_or_else(|_| "main".into());

    let clone_cmd = format!(
        "if [ -d /opt/claws/openclaw ]; then \
           cd /opt/claws/openclaw && git fetch origin && git checkout '{repo_ref}' && git pull origin '{repo_ref}' || true; \
         else \
           mkdir -p /opt/claws && \
           git clone --depth 1 --branch '{repo_ref}' '{repo_url}' /opt/claws/openclaw; \
         fi"
    );

    InstallerPlan {
        claw_type: "openclaw",
        steps: vec![
            InstallerStep::new(
                "install_deps",
                "export DEBIAN_FRONTEND=noninteractive && \
                 apt-get update -qq && \
                 apt-get install -y --no-install-recommends \
                   git curl ca-certificates >/dev/null 2>&1",
            )
            .with_timeout(120),
            // Install Node.js 22.12+ via NodeSource (matches engines.node in package.json).
            // Validates both node and npm are available and node >= 22.12.
            InstallerStep::new(
                "install_node",
                INSTALL_NODE_22_COMMAND.to_owned()
                    + " && \
                 NODE_VER=$(node --version | sed 's/v//') && \
                 NODE_MAJOR=$(echo \"$NODE_VER\" | cut -d. -f1) && \
                 NODE_MINOR=$(echo \"$NODE_VER\" | cut -d. -f2) && \
                 if [ \"$NODE_MAJOR\" -lt 22 ] || { [ \"$NODE_MAJOR\" -eq 22 ] && [ \"$NODE_MINOR\" -lt 12 ]; }; then \
                   echo \"ERROR: need node >= 22.12.0, got v${NODE_VER}\" >&2; exit 1; \
                 fi",
            )
            .with_check(NODE_22_12_CHECK)
            .with_timeout(240)
            .with_retries(2),
            // Clone before install_pnpm so corepack can read packageManager from package.json
            InstallerStep::new("clone_repo", clone_cmd)
                .with_timeout(180)
                .with_retries(2),
            // Install pnpm via corepack (Node 22+ built-in), fallback to npm install -g.
            // Runs inside cloned repo so corepack reads packageManager from package.json.
            InstallerStep::new(
                "install_pnpm",
                "cd /opt/claws/openclaw && \
                 corepack enable && \
                 corepack prepare --activate && \
                 pnpm --version || \
                 (npm install -g pnpm@10 && pnpm --version)",
            )
            .with_check("command -v pnpm >/dev/null 2>&1 && pnpm --version >/dev/null 2>&1")
            .with_timeout(180)
            .with_retries(1),
            // pnpm install + build; also attempt ui:build (non-fatal if absent)
            InstallerStep::new(
                "build",
                "cd /opt/claws/openclaw && \
                 pnpm install && \
                 (pnpm ui:build 2>&1 || true) && \
                 pnpm build",
            )
            .with_timeout(600)
            .with_retries(1),
            // Create wrapper at /usr/local/bin/openclaw pointing to the built entry point.
            // Priority: dist/openclaw.mjs > dist/index.js (shebang node) > dist/cli/index.js
            InstallerStep::new(
                "install_wrapper",
                concat!(
                    "cd /opt/claws/openclaw && ",
                    r#"ENTRY="" && "#,
                    "if [ -f dist/openclaw.mjs ]; then ",
                    r#"  ENTRY="dist/openclaw.mjs"; "#,
                    "elif [ -f dist/index.js ] && head -1 dist/index.js | grep -q node; then ",
                    r#"  ENTRY="dist/index.js"; "#,
                    "elif [ -f dist/cli/index.js ]; then ",
                    r#"  ENTRY="dist/cli/index.js"; "#,
                    "else ",
                    r#"  ENTRY=$(find dist -maxdepth 1 \( -name "*.js" -o -name "*.mjs" \) -exec grep -l '#!/usr/bin/env node' {} \; 2>/dev/null | head -1 | sed 's|/opt/claws/openclaw/||'); "#,
                    "fi && ",
                    r#"[ -n "$ENTRY" ] || { echo '[openclaw] ERROR: cannot find CLI entry in dist/' >&2; exit 1; } && "#,
                    "{ ",
                    r#"  echo '#!/bin/sh'; "#,
                    r#"  echo 'export OPENCLAW_HOME="/opt/claws/openclaw"'; "#,
                    r#"  echo 'cd "/opt/claws/openclaw" || exit 1'; "#,
                    r#"  echo "exec node $ENTRY \"\$@\""; "#,
                    "} > /usr/local/bin/openclaw && ",
                    "chmod +x /usr/local/bin/openclaw",
                ),
            )
            .with_check("test -x /usr/local/bin/openclaw")
            .with_timeout(30),
            InstallerStep::new("create_config_dir", "mkdir -p /root/.openclaw"),
            InstallerStep::new(
                "verify",
                "openclaw --version 2>/dev/null || openclaw --help 2>/dev/null | head -1 || \
                 /usr/local/bin/openclaw --help 2>/dev/null | head -1 || true",
            ),
            shell_prompt_step("openclaw"),
        ],
    }
}

/// Ironclaw install plan (pre-built binary from GitHub releases or local binary).
///
/// Priority order (matches install-ironclaw.sh):
///   1. If `IRONCLAW_BINARY` env var points to an existing file → install it directly.
///   2. Otherwise download the release tarball from GitHub, verify SHA-256, extract.
///
/// Env vars:
///   `IRONCLAW_VERSION`  — default: `0.12.0`
///   `IRONCLAW_BINARY`   — optional path to a pre-built binary on the host
#[must_use]
pub fn ironclaw_plan() -> InstallerPlan {
    let version = std::env::var("IRONCLAW_VERSION").unwrap_or_else(|_| "0.12.0".into());

    let install_cmd = format!(
        // Try local binary first (IRONCLAW_BINARY), fall back to GitHub download.
        "if [ -n \"${{IRONCLAW_BINARY:-}}\" ] && [ -f \"${{IRONCLAW_BINARY}}\" ]; then \
           install -m 755 \"${{IRONCLAW_BINARY}}\" /usr/local/bin/ironclaw; \
         else \
           export DEBIAN_FRONTEND=noninteractive && \
           apt-get update -qq && \
           apt-get install -y --no-install-recommends curl ca-certificates >/dev/null 2>&1 && \
           URL=\"https://github.com/nearai/ironclaw/releases/download/v{version}/ironclaw-x86_64-unknown-linux-gnu.tar.gz\" && \
           CSUM_URL=\"https://github.com/nearai/ironclaw/releases/download/v{version}/ironclaw-x86_64-unknown-linux-gnu.tar.gz.sha256\" && \
           curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 \
             -o /tmp/ironclaw.tar.gz \"$URL\" && \
           if command -v sha256sum >/dev/null 2>&1; then \
             EXPECTED=$(curl --proto '=https' --tlsv1.2 -fsSL --retry 3 \"$CSUM_URL\" | awk '{{print $1}}') && \
             echo \"$EXPECTED  /tmp/ironclaw.tar.gz\" | sha256sum -c - >/dev/null 2>&1 \
               || {{ echo '[ironclaw] ERROR: checksum verification failed' >&2; exit 1; }}; \
           fi && \
           tar -xzf /tmp/ironclaw.tar.gz -C /tmp/ && \
            BIN=$(find /tmp -maxdepth 2 -name ironclaw -type f | head -1) && \
           [ -n \"$BIN\" ] || {{ echo '[ironclaw] ERROR: binary not found after extraction' >&2; exit 1; }} && \
           mv \"$BIN\" /usr/local/bin/ironclaw && \
           chmod +x /usr/local/bin/ironclaw && \
           rm -f /tmp/ironclaw.tar.gz; \
         fi"
    );

    InstallerPlan {
        claw_type: "ironclaw",
        steps: vec![
            InstallerStep::new(
                "install_deps",
                "export DEBIAN_FRONTEND=noninteractive && \
                 apt-get update -qq && \
                 apt-get install -y --no-install-recommends \
                   curl ca-certificates >/dev/null 2>&1",
            )
            .with_timeout(120),
            InstallerStep::new("install_binary", install_cmd)
                .with_check("test -x /usr/local/bin/ironclaw")
                .with_timeout(180)
                .with_retries(2),
            InstallerStep::new("create_config_dir", "mkdir -p /root/.ironclaw"),
            InstallerStep::new(
                "verify",
                "ironclaw --version 2>/dev/null || ironclaw --help 2>/dev/null | head -1 || true",
            ),
            shell_prompt_step("ironclaw"),
        ],
    }
}

/// Hermes Agent install plan — self-improving AI assistant by Nous Research.
///
/// Requires both Python and Node.js runtimes. Installs from source via
/// `pip install -e ".[all]"` + `npm install`, plus Playwright/Chromium for
/// browser automation.
///
/// Env vars:
///   `HERMES_AGENT_REPO_URL` — default: `https://github.com/NousResearch/hermes-agent`
///   `HERMES_AGENT_REPO_REF` — default: `main`
#[must_use]
pub fn hermes_agent_plan() -> InstallerPlan {
    let repo_url = std::env::var("HERMES_AGENT_REPO_URL")
        .unwrap_or_else(|_| "https://github.com/NousResearch/hermes-agent".into());
    let repo_ref = std::env::var("HERMES_AGENT_REPO_REF").unwrap_or_else(|_| "main".into());

    let clone_cmd = format!(
        "if [ -d /opt/claws/hermes-agent ]; then \
           cd /opt/claws/hermes-agent && git fetch origin && git checkout '{repo_ref}' && git pull origin '{repo_ref}' || true; \
         else \
           mkdir -p /opt/claws && \
           git clone --depth 1 --branch '{repo_ref}' '{repo_url}' /opt/claws/hermes-agent; \
         fi"
    );

    InstallerPlan {
        claw_type: "hermes-agent",
        steps: vec![
            InstallerStep::new(
                "install_deps",
                "export DEBIAN_FRONTEND=noninteractive && \
                 apt-get update -qq && \
                 apt-get install -y --no-install-recommends \
                   build-essential python3 python3-pip python3-dev libffi-dev \
                   git curl ca-certificates ripgrep ffmpeg gcc >/dev/null 2>&1",
            )
            .with_timeout(240),
            InstallerStep::new(
                "install_node",
                INSTALL_NODE_22_COMMAND,
            )
            .with_check(
                NODE_22_CHECK,
            )
            .with_timeout(240)
            .with_retries(2),
            InstallerStep::new("clone_repo", clone_cmd)
                .with_timeout(180)
                .with_retries(2),
            InstallerStep::new(
                "pip_install",
                "cd /opt/claws/hermes-agent && \
                 pip3 install --break-system-packages --no-cache-dir --ignore-installed -e \".[all]\"",
            )
            .with_check("command -v hermes >/dev/null 2>&1")
            .with_timeout(600)
            .with_retries(1),
            InstallerStep::new(
                "npm_install",
                "cd /opt/claws/hermes-agent && \
                 npm install --prefer-offline --no-audit && \
                 if [ -d scripts/whatsapp-bridge ]; then \
                   cd scripts/whatsapp-bridge && npm install --prefer-offline --no-audit || true; \
                 fi && \
                 npm cache clean --force 2>/dev/null || true",
            )
            .with_check("test -d /opt/claws/hermes-agent/node_modules")
            .with_timeout(300)
            .with_retries(1),
            InstallerStep::new(
                "install_playwright",
                "cd /opt/claws/hermes-agent && \
                 npx playwright install --with-deps chromium --only-shell",
            )
            .with_check("npx playwright --version >/dev/null 2>&1")
            .with_timeout(600)
            .with_retries(1),
            // Wrapper at /usr/local/bin/hermes-agent that delegates to the real
            // `hermes` binary (installed by pip into PATH via editable install).
            InstallerStep::new(
                "install_wrapper",
                concat!(
                    "HERMES_BIN=$(command -v hermes 2>/dev/null || \
                       for p in /usr/local/bin/hermes /usr/bin/hermes \
                         \"$HOME/.local/bin/hermes\" \
                         \"$(python3 -c 'import sys; print(sys.prefix)' 2>/dev/null)/bin/hermes\"; do \
                         [ -x \"$p\" ] && echo \"$p\" && break; \
                       done) && ",
                    "{ ",
                    "echo '#!/bin/sh'; ",
                    "echo 'export HERMES_HOME=\"${HERMES_HOME:-/opt/data}\"'; ",
                    "echo 'cd \"/opt/claws/hermes-agent\" || exit 1'; ",
                    "echo \"exec $HERMES_BIN \\\"\\$@\\\"\"; ",
                    "} > /usr/local/bin/hermes-agent && ",
                    "chmod +x /usr/local/bin/hermes-agent",
                ),
            )
            .with_check("test -x /usr/local/bin/hermes-agent")
            .with_timeout(30),
            InstallerStep::new(
                "create_config_dir",
                "mkdir -p /root/.hermes /opt/data && \
                 grep -q HERMES_HOME /root/.bashrc 2>/dev/null || \
                   echo 'export HERMES_HOME=/opt/data' >> /root/.bashrc",
            ),
            InstallerStep::new(
                "verify",
                "hermes-agent --version 2>/dev/null || hermes-agent --help 2>/dev/null | head -1 || \
                 hermes --version 2>/dev/null || hermes --help 2>/dev/null | head -1 || true",
            ),
            shell_prompt_step("hermes-agent"),
        ],
    }
}

/// Noclaw install plan — bare AI coding environment.
///
/// Installs Claude Code, `OpenCode`, and Codex as npm global packages.
/// No daemon runs — the user SSH's in and uses whichever tool they want.
///
/// Env vars:
///   `NOCLAW_CLAUDE_CODE_VERSION` — pin Claude Code version (optional)
///   `NOCLAW_OPENCODE_VERSION`    — pin `OpenCode` version (optional)
///   `NOCLAW_CODEX_VERSION`       — pin Codex version (optional)
#[must_use]
pub fn noclaw_plan() -> InstallerPlan {
    let claude_code_version = std::env::var("NOCLAW_CLAUDE_CODE_VERSION").unwrap_or_default();
    let opencode_version = std::env::var("NOCLAW_OPENCODE_VERSION").unwrap_or_default();
    let codex_version = std::env::var("NOCLAW_CODEX_VERSION").unwrap_or_default();

    let claude_code_pkg = if claude_code_version.is_empty() {
        "@anthropic-ai/claude-code".to_string()
    } else {
        format!("@anthropic-ai/claude-code@{claude_code_version}")
    };
    let opencode_pkg = if opencode_version.is_empty() {
        "opencode-ai@latest".to_string()
    } else {
        format!("opencode-ai@{opencode_version}")
    };
    let codex_pkg = if codex_version.is_empty() {
        "@openai/codex".to_string()
    } else {
        format!("@openai/codex@{codex_version}")
    };

    let install_claude_cmd = format!("npm install -g {claude_code_pkg}");
    let install_opencode_cmd = format!("npm install -g {opencode_pkg}");
    let install_codex_cmd = format!("npm install -g {codex_pkg}");

    InstallerPlan {
        claw_type: "noclaw",
        steps: vec![
            InstallerStep::new(
                "install_deps",
                "export DEBIAN_FRONTEND=noninteractive && \
                 apt-get update -qq && \
                 apt-get install -y --no-install-recommends \
                   curl ca-certificates gnupg git >/dev/null 2>&1",
            )
            .with_timeout(180),
            InstallerStep::new("install_node", INSTALL_NODE_22_COMMAND)
                .with_check(NODE_22_CHECK)
                .with_timeout(240)
                .with_retries(2),
            InstallerStep::new("install_claude_code", install_claude_cmd)
                .with_check("command -v claude")
                .with_timeout(180)
                .with_retries(2),
            InstallerStep::new("install_opencode", install_opencode_cmd)
                .with_check("command -v opencode")
                .with_timeout(180)
                .with_retries(2),
            InstallerStep::new("install_codex", install_codex_cmd)
                .with_check("command -v codex")
                .with_timeout(180)
                .with_retries(2),
            InstallerStep::new(
                "install_wrapper",
                "cat > /usr/local/bin/noclaw << 'WRAPPER'\n\
                 #!/bin/sh\n\
                 echo \"noclaw - AI coding environment\"\n\
                 echo \"\"\n\
                 echo \"Available tools:\"\n\
                 if command -v claude >/dev/null 2>&1; then\n\
                   echo \"  claude  $(claude --version 2>/dev/null || echo '(installed)')\";\n\
                 else\n\
                   echo \"  claude: not installed\";\n\
                 fi\n\
                 if command -v opencode >/dev/null 2>&1; then\n\
                   echo \"  opencode  $(opencode --version 2>/dev/null || echo '(installed)')\";\n\
                 else\n\
                   echo \"  opencode: not installed\";\n\
                 fi\n\
                 if command -v codex >/dev/null 2>&1; then\n\
                   echo \"  codex  $(codex --version 2>/dev/null || echo '(installed)')\";\n\
                 else\n\
                   echo \"  codex: not installed\";\n\
                 fi\n\
                 WRAPPER\n\
                 chmod +x /usr/local/bin/noclaw",
            )
            .with_check("test -x /usr/local/bin/noclaw")
            .with_timeout(30),
            InstallerStep::new("create_config_dir", "mkdir -p /root/.noclaw"),
            InstallerStep::new(
                "verify",
                "noclaw 2>/dev/null || /usr/local/bin/noclaw 2>/dev/null || true",
            ),
            shell_prompt_step("noclaw"),
        ],
    }
}

/// Build an `InstallerPlan` from the `StepSpec`s produced by a `core-rs`
/// template (P-46 Phase B).
///
/// Reuses the existing `InstallerStep` builder API so template-rendered plans
/// and hand-written builtin plans share the exact same execution, retry, and
/// idempotency semantics. The `String` → `&'static str` conversion uses
/// `Box::leak`: template-rendered plans are built once at install time and
/// their lifetime is effectively the install worker's lifetime, so a bounded
/// leak is acceptable. If templates ever become hot-path we can revisit.
#[must_use]
pub fn from_spec(
    claw_type: &'static str,
    spec: Vec<core_rs::templates::StepSpec>,
) -> InstallerPlan {
    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    let steps: Vec<InstallerStep> = spec
        .into_iter()
        .map(|s| {
            let phase_static: &'static str = leak(s.phase);
            let mut step = InstallerStep::new(phase_static, s.command);
            if let Some(check) = s.idempotency_check {
                let check_static: &'static str = leak(check);
                step = step.with_check(check_static);
            }
            step = step
                .with_timeout(s.timeout_secs)
                .with_retries(s.max_retries);
            step
        })
        .collect();

    InstallerPlan { claw_type, steps }
}

/// Get the `InstallerPlan` for a claw type, if one is defined.
///
/// Lookup order (P-46 Phase B):
/// 1. Hand-written builtins (the 8 `Tier::Supported` claws).
/// 2. Template fallback: if the claw has a `ManifestEntry` with a non-empty
///    `install_template` and an `install:` config block, render that template
///    and wrap the result.
///
/// Returns `None` for unknown or untemplated claws. Callers must NOT fall
/// back to a legacy shell installer on `None` — that path is gone.
#[must_use]
pub fn get_plan(claw_type: &str) -> Option<InstallerPlan> {
    // 1. Builtins — fast path, hand-written and hashed by their own functions.
    match claw_type {
        "nullclaw" => return Some(nullclaw_plan()),
        "picoclaw" => return Some(picoclaw_plan()),
        "zeroclaw" => return Some(zeroclaw_plan()),
        "nanobot" => return Some(nanobot_plan()),
        "openclaw" => return Some(openclaw_plan()),
        "ironclaw" => return Some(ironclaw_plan()),
        "hermes-agent" => return Some(hermes_agent_plan()),
        "noclaw" => return Some(noclaw_plan()),
        _ => {}
    }

    // 2. Template fallback.
    let entry = core_rs::manifest::get(claw_type)?;
    let install = entry.install.as_ref()?;
    if entry.install_template.is_empty() {
        return None;
    }
    let spec = core_rs::templates::render(entry.install_template, install)?;
    // `entry.name` is a `&'static str` produced by the build script, so it's
    // safe to use directly without leaking.
    Some(from_spec(entry.name, spec))
}

/// Returns true if this claw has a hand-written builtin plan compiled into
/// `vmrunner-rs`, as opposed to a generic template plan (Phase B hybrid
/// lookup — see `install_template` in the manifest).
///
/// `soyeht claws-promote` uses this to gate the `tier: supported` transition:
/// a claw can only be promoted to `supported` once someone has written a
/// stable builtin plan in this file, so the upgrade path is audited.
#[must_use]
pub fn has_builtin(claw_type: &str) -> bool {
    matches!(
        claw_type,
        "nullclaw"
            | "picoclaw"
            | "zeroclaw"
            | "nanobot"
            | "openclaw"
            | "ironclaw"
            | "hermes-agent"
            | "noclaw"
    )
}

/// Return the environment variables that affect a claw's `InstallerPlan`.
///
/// These are the env vars that, when changed, should invalidate the golden
/// image for this claw.  Used by the artifact DAG fingerprint system to
/// decide whether a golden needs rebuilding.
///
/// Returns an empty slice for:
/// - unknown claw types, and
/// - template-rendered claws (P-46 Phase B): their install plans are
///   parameterized directly by the manifest's `install:` block, so there
///   are no env vars to watch. A change to the manifest already invalidates
///   the content hash via [`get_plan`].
#[must_use]
pub fn build_env_vars(claw_type: &str) -> &'static [&'static str] {
    match claw_type {
        "nullclaw" => &["NULLCLAW_VERSION"],
        "picoclaw" => &["PICOCLAW_VERSION"],
        "zeroclaw" => &["ZEROCLAW_REPO_URL", "ZEROCLAW_REPO_REF"],
        "nanobot" => &["NANOBOT_VERSION"],
        "openclaw" => &["OPENCLAW_REPO_URL", "OPENCLAW_REPO_REF"],
        "ironclaw" => &["IRONCLAW_VERSION", "IRONCLAW_BINARY"],
        "hermes-agent" => &["HERMES_AGENT_REPO_URL", "HERMES_AGENT_REPO_REF"],
        "noclaw" => &[
            "NOCLAW_CLAUDE_CODE_VERSION",
            "NOCLAW_OPENCODE_VERSION",
            "NOCLAW_CODEX_VERSION",
        ],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_client::test_utils::{MockSshSession, SshCall};

    #[test]
    fn nullclaw_plan_has_four_steps() {
        let plan = nullclaw_plan();
        assert_eq!(plan.claw_type, "nullclaw");
        assert_eq!(plan.steps.len(), 4);
        assert_eq!(plan.steps[0].phase, "download_binary");
        assert_eq!(plan.steps[1].phase, "create_config_dir");
        assert_eq!(plan.steps[2].phase, "verify");
        assert_eq!(plan.steps[3].phase, "setup_shell_prompt");
    }

    #[test]
    fn picoclaw_plan_has_four_steps() {
        let plan = picoclaw_plan();
        assert_eq!(plan.claw_type, "picoclaw");
        assert_eq!(plan.steps.len(), 4);
    }

    #[tokio::test]
    async fn plan_execute_skips_step_when_idempotency_check_passes() {
        // MockSshSession returns Ok for all exec calls (simulates "already installed")
        let ssh = MockSshSession::new();
        let plan = nullclaw_plan();

        let result = plan.execute(&ssh).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        // The idempotency check for download_binary passes → only 2 calls:
        // check (exec) + create_config_dir (exec_install) + verify (exec_install)
        let calls = ssh.recorded_calls().await;
        // At minimum: 1 idempotency check + 2 remaining steps
        assert!(
            calls.len() >= 2,
            "expected at least 2 calls, got {}: {:?}",
            calls.len(),
            calls
        );
        // First call must be the idempotency test
        if let SshCall::Exec(cmd) = &calls[0] {
            assert!(
                cmd.contains("test -x /usr/local/bin/nullclaw"),
                "expected idempotency check, got: {cmd}"
            );
        } else {
            panic!("expected Exec for idempotency check, got {:?}", calls[0]);
        }
    }

    #[tokio::test]
    async fn plan_execute_enriches_error_with_phase() {
        // Fail both exec (idempotency check) and exec_install so the plan errors
        // on the very first step and surfaces a structured ErrorContext.
        let ssh = crate::ssh_client::test_utils::MockSshSession::with_all_errors("fail all");
        let result = nullclaw_plan().execute(&ssh).await;
        assert!(result.is_err(), "expected error from failing mock");
        let err = result.unwrap_err();
        let ctx = err.context().expect("ErrorContext must be present");
        assert!(
            ctx.phase
                .as_deref()
                .unwrap_or("")
                .contains("installer.nullclaw"),
            "phase should contain installer.nullclaw, got: {:?}",
            ctx.phase
        );
    }

    /// P-46 Phase B regression guard: the builtin picoclaw plan MUST keep
    /// its exact `content_hash`, i.e. `get_plan("picoclaw")` must always hit
    /// the hand-written `picoclaw_plan()` branch and never fall through to
    /// the template fallback.
    ///
    /// If this test fails because the plan was legitimately changed, update
    /// the constant AND bump the artifact-DAG fingerprint expectations so
    /// stale goldens rebuild. Do **not** update it just to "make the test pass."
    #[test]
    fn picoclaw_builtin_hash_is_pinned() {
        const EXPECTED: &str = "20809d58a27e74f0a5225d880c6752de9731e3529fb5dde52316c1b6cf570886";
        let got = get_plan("picoclaw")
            .expect("picoclaw builtin must resolve")
            .content_hash();
        assert_eq!(
            got, EXPECTED,
            "picoclaw plan hash drifted — if this is intentional, update the \
             constant AND notify artifact-DAG owners. got={got}",
        );
    }

    #[test]
    fn get_plan_returns_some_for_all_known_claws() {
        for claw in &[
            "nullclaw",
            "picoclaw",
            "zeroclaw",
            "nanobot",
            "openclaw",
            "ironclaw",
            "hermes-agent",
            "noclaw",
        ] {
            assert!(get_plan(claw).is_some(), "expected plan for {claw}");
        }
    }

    /// P-46 Phase B: `from_spec` must faithfully lift the fields of a
    /// `core_rs::templates::StepSpec` into an `InstallerStep`, preserving
    /// phase, command, idempotency check, timeout, and retry count.
    #[test]
    fn from_spec_roundtrips_stepspec_fields() {
        use core_rs::templates::StepSpec;
        let spec = vec![
            StepSpec::new("install_deps", "apt-get install -y curl")
                .with_timeout(240)
                .with_retries(2),
            StepSpec::new("download", "curl -o /tmp/x https://example.com/x")
                .with_check("test -x /usr/local/bin/x")
                .with_timeout(300)
                .with_retries(1),
        ];
        let plan = from_spec("fakeclaw", spec);
        assert_eq!(plan.claw_type, "fakeclaw");
        assert_eq!(plan.steps.len(), 2);

        assert_eq!(plan.steps[0].phase, "install_deps");
        assert!(plan.steps[0].command.contains("apt-get install"));
        assert_eq!(plan.steps[0].idempotency_check, None);
        assert_eq!(plan.steps[0].timeout, std::time::Duration::from_secs(240));
        assert_eq!(plan.steps[0].max_retries, 2);

        assert_eq!(plan.steps[1].phase, "download");
        assert_eq!(
            plan.steps[1].idempotency_check,
            Some("test -x /usr/local/bin/x")
        );
        assert_eq!(plan.steps[1].max_retries, 1);
    }

    /// The template fallback should produce a deterministic content hash so
    /// the artifact DAG can decide whether to rebuild.
    #[test]
    fn from_spec_plan_has_stable_content_hash() {
        use core_rs::templates::StepSpec;
        let spec = || {
            vec![
                StepSpec::new("only_step", "echo hi")
                    .with_timeout(60)
                    .with_retries(0),
            ]
        };
        let a = from_spec("fakeclaw", spec()).content_hash();
        let b = from_spec("fakeclaw", spec()).content_hash();
        assert_eq!(a, b, "same spec must produce the same hash");
        assert_eq!(a.len(), 64, "sha-256 hex is 64 chars");
    }

    #[test]
    fn get_plan_returns_none_for_unknown() {
        assert!(get_plan("unknownclaw").is_none());
        assert!(get_plan("brokenclaw").is_none());
    }

    // ── Per-claw structural tests ──────────────────────────────────────────────

    #[test]
    fn nanobot_plan_structure() {
        let plan = nanobot_plan();
        assert_eq!(plan.claw_type, "nanobot");
        // install_deps, install_package, link_binary, create_config_dir, verify, setup_shell_prompt
        assert_eq!(plan.steps.len(), 6, "nanobot plan should have 6 steps");
        assert_eq!(plan.steps[0].phase, "install_deps");
        assert_eq!(plan.steps[1].phase, "install_package");
        assert_eq!(plan.steps[2].phase, "link_binary");
        assert_eq!(plan.steps[3].phase, "create_config_dir");
        assert_eq!(plan.steps[4].phase, "verify");
        // install_package should use --break-system-packages and nanobot-ai
        assert!(
            plan.steps[1].command.contains("break-system-packages"),
            "nanobot install should use --break-system-packages"
        );
        assert!(
            plan.steps[1].command.contains("nanobot-ai"),
            "nanobot install should use PyPI package nanobot-ai"
        );
    }

    #[test]
    fn openclaw_plan_structure() {
        let plan = openclaw_plan();
        assert_eq!(plan.claw_type, "openclaw");
        // install_deps, install_node, clone_repo, install_pnpm, build, install_wrapper,
        // create_config_dir, verify, setup_shell_prompt
        assert_eq!(plan.steps.len(), 9, "openclaw plan should have 9 steps");
        assert_eq!(plan.steps[0].phase, "install_deps");
        assert_eq!(plan.steps[1].phase, "install_node");
        assert_eq!(plan.steps[2].phase, "clone_repo");
        assert_eq!(plan.steps[3].phase, "install_pnpm");
        assert_eq!(plan.steps[4].phase, "build");
        assert_eq!(plan.steps[5].phase, "install_wrapper");
        assert_eq!(plan.steps[6].phase, "create_config_dir");
        assert_eq!(plan.steps[7].phase, "verify");

        // ── install_node assertions ──────────────────────────────────────
        let install_node = &plan.steps[1];
        // Must target Node 22 via the explicit NodeSource repo config.
        assert!(
            install_node.command.contains("nodesource.sources"),
            "install_node should configure nodesource.sources, got: {}",
            install_node.command
        );
        assert!(
            !install_node.command.contains("setup_22"),
            "install_node should not execute the remote setup script, got: {}",
            install_node.command
        );
        // Must validate npm is available (not just node)
        assert!(
            install_node.command.contains("npm --version"),
            "install_node should validate npm availability, got: {}",
            install_node.command
        );
        // Must NOT pipe remote setup scripts into a shell.
        assert!(
            !install_node.command.contains("| bash"),
            "install_node should not pipe to bash, got: {}",
            install_node.command
        );

        // ── install_pnpm assertions ──────────────────────────────────────
        let install_pnpm = &plan.steps[3];
        // Must use corepack as primary method
        assert!(
            install_pnpm.command.contains("corepack enable"),
            "install_pnpm should use corepack enable, got: {}",
            install_pnpm.command
        );
        assert!(
            install_pnpm.command.contains("corepack prepare"),
            "install_pnpm should use corepack prepare, got: {}",
            install_pnpm.command
        );
        // Must run inside the cloned repo so corepack reads packageManager
        assert!(
            install_pnpm.command.contains("/opt/claws/openclaw"),
            "install_pnpm should run inside cloned repo, got: {}",
            install_pnpm.command
        );

        // ── clone_repo comes before install_pnpm ─────────────────────────
        // (so corepack can read packageManager from package.json)
        let clone_idx = plan
            .steps
            .iter()
            .position(|s| s.phase == "clone_repo")
            .unwrap();
        let pnpm_idx = plan
            .steps
            .iter()
            .position(|s| s.phase == "install_pnpm")
            .unwrap();
        assert!(
            clone_idx < pnpm_idx,
            "clone_repo (idx={clone_idx}) must come before install_pnpm (idx={pnpm_idx})"
        );

        // ── build assertions ─────────────────────────────────────────────
        // Must use pnpm build, not npm install -g openclaw
        assert!(
            plan.steps[4].command.contains("pnpm build"),
            "openclaw build step should use pnpm build"
        );
        // install_wrapper should have idempotency check
        assert!(
            plan.steps[5].idempotency_check.is_some(),
            "install_wrapper should have idempotency check"
        );
    }

    #[test]
    fn zeroclaw_plan_structure() {
        let plan = zeroclaw_plan();
        assert_eq!(plan.claw_type, "zeroclaw");
        assert_eq!(plan.steps.len(), 7, "zeroclaw plan should have 7 steps");
        assert_eq!(plan.steps[0].phase, "install_deps");
        assert_eq!(plan.steps[1].phase, "install_rust");
        assert_eq!(plan.steps[2].phase, "clone_repo");
        assert_eq!(plan.steps[3].phase, "build");
        assert_eq!(plan.steps[4].phase, "create_config_dir");
        assert_eq!(plan.steps[5].phase, "verify");
        // build step should be idempotent
        assert!(
            plan.steps[3].idempotency_check.is_some(),
            "zeroclaw build step should have idempotency check"
        );
    }

    #[test]
    fn ironclaw_plan_structure() {
        let plan = ironclaw_plan();
        assert_eq!(plan.claw_type, "ironclaw");
        assert_eq!(plan.steps.len(), 5, "ironclaw plan should have 5 steps");
        assert_eq!(plan.steps[0].phase, "install_deps");
        assert_eq!(plan.steps[1].phase, "install_binary");
        assert_eq!(plan.steps[2].phase, "create_config_dir");
        assert_eq!(plan.steps[3].phase, "verify");
        // binary install should check sha256
        assert!(
            plan.steps[1].command.contains("sha256sum"),
            "ironclaw install_binary should verify sha256"
        );
    }

    #[test]
    fn hermes_agent_plan_structure() {
        let plan = hermes_agent_plan();
        assert_eq!(plan.claw_type, "hermes-agent");
        assert_eq!(
            plan.steps.len(),
            10,
            "hermes-agent plan should have 10 steps"
        );
        assert_eq!(plan.steps[0].phase, "install_deps");
        assert_eq!(plan.steps[1].phase, "install_node");
        assert_eq!(plan.steps[2].phase, "clone_repo");
        assert_eq!(plan.steps[3].phase, "pip_install");
        assert_eq!(plan.steps[4].phase, "npm_install");
        assert_eq!(plan.steps[5].phase, "install_playwright");
        assert_eq!(plan.steps[6].phase, "install_wrapper");
        assert_eq!(plan.steps[7].phase, "create_config_dir");
        assert_eq!(plan.steps[8].phase, "verify");
        assert_eq!(plan.steps[9].phase, "setup_shell_prompt");
        // pip_install should use --break-system-packages
        assert!(
            plan.steps[3].command.contains("break-system-packages"),
            "hermes-agent pip_install should use --break-system-packages"
        );
        // install_node should use the explicit NodeSource repo config.
        assert!(
            plan.steps[1].command.contains("nodesource.sources"),
            "hermes-agent install_node should configure nodesource.sources"
        );
        assert!(
            !plan.steps[1].command.contains("setup_22"),
            "hermes-agent install_node should not execute the remote setup script"
        );
        // clone_repo should have retries (network)
        assert!(
            plan.steps[2].max_retries >= 2,
            "hermes-agent clone_repo should have retries"
        );
        // install_wrapper should have idempotency check
        assert!(
            plan.steps[6].idempotency_check.is_some(),
            "hermes-agent install_wrapper should have idempotency check"
        );
    }

    #[test]
    fn noclaw_plan_structure() {
        let plan = noclaw_plan();
        assert_eq!(plan.claw_type, "noclaw");
        assert_eq!(plan.steps.len(), 9, "noclaw plan should have 9 steps");
        assert_eq!(plan.steps[0].phase, "install_deps");
        assert_eq!(plan.steps[1].phase, "install_node");
        assert_eq!(plan.steps[2].phase, "install_claude_code");
        assert_eq!(plan.steps[3].phase, "install_opencode");
        assert_eq!(plan.steps[4].phase, "install_codex");
        assert_eq!(plan.steps[5].phase, "install_wrapper");
        assert_eq!(plan.steps[6].phase, "create_config_dir");
        assert_eq!(plan.steps[7].phase, "verify");
        assert_eq!(plan.steps[8].phase, "setup_shell_prompt");
        // install_node should use the explicit NodeSource repo config.
        assert!(
            plan.steps[1].command.contains("nodesource.sources"),
            "noclaw install_node should configure nodesource.sources"
        );
        assert!(
            !plan.steps[1].command.contains("setup_22"),
            "noclaw install_node should not execute the remote setup script"
        );
        // Tool install steps reference correct npm packages
        assert!(
            plan.steps[2].command.contains("@anthropic-ai/claude-code"),
            "noclaw should install @anthropic-ai/claude-code"
        );
        assert!(
            plan.steps[3].command.contains("opencode-ai"),
            "noclaw should install opencode-ai"
        );
        assert!(
            plan.steps[4].command.contains("@openai/codex"),
            "noclaw should install @openai/codex"
        );
        // All tool installs should have idempotency checks
        for i in 2..=4 {
            assert!(
                plan.steps[i].idempotency_check.is_some(),
                "noclaw step '{}' should have idempotency check",
                plan.steps[i].phase,
            );
        }
        // install_wrapper should have idempotency check
        assert!(
            plan.steps[5].idempotency_check.is_some(),
            "noclaw install_wrapper should have idempotency check"
        );
    }

    #[test]
    fn all_plans_have_verify_before_shell_prompt() {
        for claw in &[
            "nullclaw",
            "picoclaw",
            "zeroclaw",
            "nanobot",
            "openclaw",
            "ironclaw",
            "hermes-agent",
            "noclaw",
        ] {
            let plan = get_plan(claw).unwrap();
            let steps = &plan.steps;
            let len = steps.len();
            assert!(len >= 2, "{claw} plan should have at least 2 steps");
            assert_eq!(
                steps[len - 2].phase,
                "verify",
                "{claw} second-to-last step should be verify, got: {}",
                steps[len - 2].phase
            );
            assert_eq!(
                steps[len - 1].phase,
                "setup_shell_prompt",
                "{claw} last step should be setup_shell_prompt, got: {}",
                steps[len - 1].phase
            );
        }
    }

    #[test]
    fn all_plans_have_shell_prompt_step() {
        for plan in [
            nullclaw_plan(),
            picoclaw_plan(),
            zeroclaw_plan(),
            nanobot_plan(),
            openclaw_plan(),
            ironclaw_plan(),
            hermes_agent_plan(),
            noclaw_plan(),
        ] {
            let last = plan.steps.last().unwrap();
            assert_eq!(
                last.phase, "setup_shell_prompt",
                "{} plan should end with setup_shell_prompt",
                plan.claw_type
            );
            assert!(
                last.command.contains("PROMPT_COMMAND="),
                "{} prompt step should set PROMPT_COMMAND",
                plan.claw_type
            );
            assert!(
                last.command.contains("1;38;2;0;217;163"),
                "{} prompt step should use bold #00D9A3 ok color",
                plan.claw_type
            );
            assert!(
                last.command.contains("1;38;2;245;158;11"),
                "{} prompt step should use bold #F59E0B warn color",
                plan.claw_type
            );
        }
    }

    #[test]
    fn all_plans_have_create_config_dir() {
        for claw in &[
            "nullclaw",
            "picoclaw",
            "zeroclaw",
            "nanobot",
            "openclaw",
            "ironclaw",
            "hermes-agent",
            "noclaw",
        ] {
            let plan = get_plan(claw).unwrap();
            let has_config = plan.steps.iter().any(|s| s.phase == "create_config_dir");
            assert!(has_config, "{claw} plan should have create_config_dir step");
        }
    }

    #[test]
    fn network_steps_have_retries() {
        // Steps that download from the network should have at least 1 retry
        let picoclaw = picoclaw_plan();
        let dl = picoclaw
            .steps
            .iter()
            .find(|s| s.phase == "download_binary")
            .unwrap();
        assert!(
            dl.max_retries >= 2,
            "picoclaw download_binary should have retries"
        );

        let nullclaw = nullclaw_plan();
        let dl = nullclaw
            .steps
            .iter()
            .find(|s| s.phase == "download_binary")
            .unwrap();
        assert!(
            dl.max_retries >= 2,
            "nullclaw download_binary should have retries"
        );

        let ironclaw = ironclaw_plan();
        let inst = ironclaw
            .steps
            .iter()
            .find(|s| s.phase == "install_binary")
            .unwrap();
        assert!(
            inst.max_retries >= 2,
            "ironclaw install_binary should have retries"
        );
    }

    // ── content_hash tests ─────────────────────────────────────────────

    #[test]
    fn content_hash_deterministic() {
        let plan1 = nullclaw_plan();
        let plan2 = nullclaw_plan();
        assert_eq!(
            plan1.content_hash(),
            plan2.content_hash(),
            "same plan must produce same hash"
        );
    }

    #[test]
    fn content_hash_is_64_hex_chars() {
        let hash = nullclaw_plan().content_hash();
        assert_eq!(hash.len(), 64, "SHA-256 hex digest is 64 chars");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "must be hex, got: {hash}"
        );
    }

    #[test]
    fn content_hash_differs_across_claws() {
        let null_hash = nullclaw_plan().content_hash();
        let pico_hash = picoclaw_plan().content_hash();
        let zero_hash = zeroclaw_plan().content_hash();
        assert_ne!(null_hash, pico_hash, "nullclaw vs picoclaw");
        assert_ne!(null_hash, zero_hash, "nullclaw vs zeroclaw");
        assert_ne!(pico_hash, zero_hash, "picoclaw vs zeroclaw");
    }

    #[test]
    fn content_hash_all_eight_unique() {
        let mut hashes = std::collections::HashSet::new();
        for claw in &[
            "nullclaw",
            "picoclaw",
            "zeroclaw",
            "nanobot",
            "openclaw",
            "ironclaw",
            "hermes-agent",
            "noclaw",
        ] {
            let plan = get_plan(claw).unwrap();
            let hash = plan.content_hash();
            assert!(
                hashes.insert(hash.clone()),
                "duplicate hash for {claw}: {hash}"
            );
        }
        assert_eq!(hashes.len(), 8);
    }

    #[test]
    fn content_hash_changes_when_command_changes() {
        // Build two plans with different commands
        let plan1 = InstallerPlan {
            claw_type: "test",
            steps: vec![InstallerStep::new("step1", "echo hello")],
        };
        let plan2 = InstallerPlan {
            claw_type: "test",
            steps: vec![InstallerStep::new("step1", "echo world")],
        };
        assert_ne!(
            plan1.content_hash(),
            plan2.content_hash(),
            "different commands must produce different hashes"
        );
    }

    #[test]
    fn content_hash_changes_when_timeout_changes() {
        let plan1 = InstallerPlan {
            claw_type: "test",
            steps: vec![InstallerStep::new("step1", "echo x").with_timeout(30)],
        };
        let plan2 = InstallerPlan {
            claw_type: "test",
            steps: vec![InstallerStep::new("step1", "echo x").with_timeout(60)],
        };
        assert_ne!(plan1.content_hash(), plan2.content_hash());
    }

    #[test]
    fn content_hash_changes_when_retries_change() {
        let plan1 = InstallerPlan {
            claw_type: "test",
            steps: vec![InstallerStep::new("step1", "echo x").with_retries(0)],
        };
        let plan2 = InstallerPlan {
            claw_type: "test",
            steps: vec![InstallerStep::new("step1", "echo x").with_retries(2)],
        };
        assert_ne!(plan1.content_hash(), plan2.content_hash());
    }

    #[test]
    fn content_hash_changes_when_step_added() {
        let plan1 = InstallerPlan {
            claw_type: "test",
            steps: vec![InstallerStep::new("step1", "echo x")],
        };
        let plan2 = InstallerPlan {
            claw_type: "test",
            steps: vec![
                InstallerStep::new("step1", "echo x"),
                InstallerStep::new("step2", "echo y"),
            ],
        };
        assert_ne!(plan1.content_hash(), plan2.content_hash());
    }

    #[test]
    fn content_hash_changes_when_idempotency_check_added() {
        let plan1 = InstallerPlan {
            claw_type: "test",
            steps: vec![InstallerStep::new("step1", "echo x")],
        };
        let plan2 = InstallerPlan {
            claw_type: "test",
            steps: vec![InstallerStep::new("step1", "echo x").with_check("test -f /foo")],
        };
        assert_ne!(plan1.content_hash(), plan2.content_hash());
    }

    // ── build_env_vars tests ───────────────────────────────────────────

    #[test]
    fn build_env_vars_known_claws() {
        assert_eq!(build_env_vars("nullclaw"), &["NULLCLAW_VERSION"]);
        assert_eq!(build_env_vars("picoclaw"), &["PICOCLAW_VERSION"]);
        assert_eq!(
            build_env_vars("zeroclaw"),
            &["ZEROCLAW_REPO_URL", "ZEROCLAW_REPO_REF"]
        );
        assert_eq!(build_env_vars("nanobot"), &["NANOBOT_VERSION"]);
        assert_eq!(
            build_env_vars("openclaw"),
            &["OPENCLAW_REPO_URL", "OPENCLAW_REPO_REF"]
        );
        assert_eq!(
            build_env_vars("ironclaw"),
            &["IRONCLAW_VERSION", "IRONCLAW_BINARY"]
        );
        assert_eq!(
            build_env_vars("hermes-agent"),
            &["HERMES_AGENT_REPO_URL", "HERMES_AGENT_REPO_REF"]
        );
        assert_eq!(
            build_env_vars("noclaw"),
            &[
                "NOCLAW_CLAUDE_CODE_VERSION",
                "NOCLAW_OPENCODE_VERSION",
                "NOCLAW_CODEX_VERSION",
            ]
        );
    }

    #[test]
    fn build_env_vars_unknown_returns_empty() {
        assert!(build_env_vars("unknown").is_empty());
    }

    #[test]
    fn build_env_vars_all_eight_have_at_least_one() {
        for claw in &[
            "nullclaw",
            "picoclaw",
            "zeroclaw",
            "nanobot",
            "openclaw",
            "ironclaw",
            "hermes-agent",
            "noclaw",
        ] {
            assert!(
                !build_env_vars(claw).is_empty(),
                "{claw} should have at least one build env var"
            );
        }
    }
}
