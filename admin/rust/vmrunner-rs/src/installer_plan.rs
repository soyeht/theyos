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

const DEFAULT_PNPM_VERSION: &str = "11.8.0";
const DEFAULT_ZEROCLAW_REPO_REF: &str = "a57ddd0ad257b3acc6351cb49b765e0e6f3f06e7";
const DEFAULT_OPENCLAW_REPO_REF: &str = "44422b2151916191c6dff5662e1f8a6f7e4675ca";
const DEFAULT_HERMES_AGENT_REPO_REF: &str = "b88d0007c9d0037a1ec3daa2477bd4f79eaf566b";
const DEFAULT_CLAUDE_CODE_VERSION: &str = "2.1.183";
const DEFAULT_OPENCODE_VERSION: &str = "1.17.8";
const DEFAULT_CODEX_VERSION: &str = "0.141.0";

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

fn fetch_reviewed_git_commit_command(path: &str, repo_url: &str, repo_ref: &str) -> String {
    format!(
        "mkdir -p {path} && \
         git -C {path} init && \
         (git -C {path} remote remove origin >/dev/null 2>&1 || true) && \
         git -C {path} remote add origin '{repo_url}' && \
         git -C {path} fetch --depth 1 origin '{repo_ref}' && \
         git -C {path} checkout --detach FETCH_HEAD && \
         test \"$(git -C {path} rev-parse HEAD)\" = \"{repo_ref}\""
    )
}

fn env_or_default(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.into())
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
        .unwrap_or_else(|_| "https://github.com/zeroclaw-labs/zeroclaw".into());
    let repo_ref = env_or_default("ZEROCLAW_REPO_REF", DEFAULT_ZEROCLAW_REPO_REF);

    let clone_cmd = fetch_reviewed_git_commit_command("/opt/claws/zeroclaw", &repo_url, &repo_ref);

    InstallerPlan {
        claw_type: "zeroclaw",
        steps: vec![
            InstallerStep::new(
                "install_deps",
                "export DEBIAN_FRONTEND=noninteractive && \
                 apt-get update -qq && \
                 apt-get install -y --no-install-recommends \
                   git build-essential pkg-config ca-certificates curl rustc cargo >/dev/null 2>&1",
            )
            .with_timeout(180),
            InstallerStep::new(
                "install_rust",
                "command -v rustc >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1",
            )
            .with_check("command -v cargo >/dev/null 2>&1")
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
/// Steps: install deps → pip install nanobot-ai==0.2.1 → link binary → create config dir → verify.
#[must_use]
pub fn nanobot_plan() -> InstallerPlan {
    let version = std::env::var("NANOBOT_VERSION").unwrap_or_default();

    let install_cmd = if version.is_empty() {
        "python3 -m venv /opt/nanobot-venv && \
         /opt/nanobot-venv/bin/pip install --quiet --upgrade pip && \
         /opt/nanobot-venv/bin/pip install --quiet --ignore-installed nanobot-ai==0.2.1 && \
         ln -sf /opt/nanobot-venv/bin/nanobot /usr/local/bin/nanobot"
            .to_string()
    } else {
        format!(
            "python3 -m venv /opt/nanobot-venv && \
             /opt/nanobot-venv/bin/pip install --quiet --upgrade pip && \
             /opt/nanobot-venv/bin/pip install --quiet --ignore-installed nanobot-ai=={version} && \
             ln -sf /opt/nanobot-venv/bin/nanobot /usr/local/bin/nanobot"
        )
    };

    InstallerPlan {
        claw_type: "nanobot",
        steps: vec![
            InstallerStep::new(
                "install_deps",
                "export DEBIAN_FRONTEND=noninteractive && \
                 apt-get update -qq && \
                 apt-get install -y --no-install-recommends \
                   python3 python3-pip python3-venv ca-certificates >/dev/null 2>&1",
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
    let repo_ref = env_or_default("OPENCLAW_REPO_REF", DEFAULT_OPENCLAW_REPO_REF);

    let clone_cmd = fetch_reviewed_git_commit_command("/opt/claws/openclaw", &repo_url, &repo_ref);

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
                 if [ \"$NODE_MAJOR\" -lt 22 ] || {{ [ \"$NODE_MAJOR\" -eq 22 ] && [ \"$NODE_MINOR\" -lt 12 ]; }}; then \
                   echo \"ERROR: need node >= 22.12.0, got v${{NODE_VER}}\" >&2; exit 1; \
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
                format!(
                    "cd /opt/claws/openclaw && \
                 corepack enable && \
                 corepack prepare pnpm@{DEFAULT_PNPM_VERSION} --activate && \
                 pnpm --version || \
                 (npm install -g pnpm@{DEFAULT_PNPM_VERSION} && pnpm --version)"
                ),
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
///   `HERMES_AGENT_REPO_REF` — default: reviewed commit
#[must_use]
pub fn hermes_agent_plan() -> InstallerPlan {
    let repo_url = std::env::var("HERMES_AGENT_REPO_URL")
        .unwrap_or_else(|_| "https://github.com/NousResearch/hermes-agent".into());
    let repo_ref = env_or_default("HERMES_AGENT_REPO_REF", DEFAULT_HERMES_AGENT_REPO_REF);

    let clone_cmd =
        fetch_reviewed_git_commit_command("/opt/claws/hermes-agent", &repo_url, &repo_ref);

    InstallerPlan {
        claw_type: "hermes-agent",
        steps: vec![
            InstallerStep::new(
                "install_deps",
                "export DEBIAN_FRONTEND=noninteractive && \
                 apt-get update -qq && \
                 apt-get install -y --no-install-recommends \
                   build-essential python3 python3-pip python3-venv python3-dev libffi-dev \
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
                 python3 -m venv /opt/hermes-agent-venv && \
                 /opt/hermes-agent-venv/bin/pip install --quiet --upgrade pip && \
                 /opt/hermes-agent-venv/bin/pip install --no-cache-dir --ignore-installed -e \".[all]\" && \
                 ln -sf /opt/hermes-agent-venv/bin/hermes /usr/local/bin/hermes",
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
    let claude_code_version =
        env_or_default("NOCLAW_CLAUDE_CODE_VERSION", DEFAULT_CLAUDE_CODE_VERSION);
    let opencode_version = env_or_default("NOCLAW_OPENCODE_VERSION", DEFAULT_OPENCODE_VERSION);
    let codex_version = env_or_default("NOCLAW_CODEX_VERSION", DEFAULT_CODEX_VERSION);

    let claude_code_pkg = format!("@anthropic-ai/claude-code@{claude_code_version}");
    let opencode_pkg = format!("opencode-ai@{opencode_version}");
    let codex_pkg = format!("@openai/codex@{codex_version}");

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
mod tests;
