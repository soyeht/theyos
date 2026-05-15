//! `tools_plan.rs` — Optional AI coding tool installation plans.
//!
//! Provides `InstallerPlan`s for optional AI coding tools (Codex, Claude Code,
//! `OpenCode`) that can be installed inside guest VMs at create/claim time.
//!
//! Installation is best-effort: failures are logged but do not abort the
//! instance creation flow.

use crate::installer_plan::{InstallerPlan, InstallerStep};
use crate::ssh_client::SshActions;

/// Canonical tool names accepted by the API.
pub const TOOL_CODEX: &str = "codex";
pub const TOOL_CLAUDE_CODE: &str = "claude-code";
pub const TOOL_OPENCODE: &str = "opencode";

/// All default tools (installed when no `tools` field is provided).
pub const DEFAULT_TOOLS: &[&str] = &[TOOL_CODEX, TOOL_CLAUDE_CODE, TOOL_OPENCODE];

/// Shared step: ensure Node.js + npm are available in the guest.
///
/// Idempotent — skips if `node` and `npm` are already on PATH.
///
/// Snapshot-restored VMs have two APT-breaking issues:
///
/// 1. **Stale clock** — the guest clock is frozen at snapshot time, so APT
///    rejects `InRelease` files as "not valid yet". We fix the clock via
///    an HTTP `Date` header from `archive.ubuntu.com` before touching APT.
///
/// 2. **Stale APT lists** — cached `InRelease` files have GPG signatures
///    that fail after snapshot restore. Clearing `/var/lib/apt/lists/*`
///    forces a clean re-download.
fn ensure_nodejs_step() -> InstallerStep {
    InstallerStep::new(
        "ensure_nodejs",
        "export DEBIAN_FRONTEND=noninteractive && \
         DATE=$(curl -sI http://archive.ubuntu.com/ubuntu/dists/noble/InRelease 2>/dev/null \
                | grep -i '^date:' | sed 's/^[Dd]ate: //') && \
         [ -n \"$DATE\" ] && date -s \"$DATE\" >/dev/null 2>&1 || true && \
         rm -rf /var/lib/apt/lists/* && \
         apt-get update -qq && \
         apt-get install -y --no-install-recommends curl ca-certificates gnupg >/dev/null 2>&1 && \
         curl -fsSL https://deb.nodesource.com/setup_22.x | sh - >/dev/null 2>&1 && \
         apt-get install -y --no-install-recommends nodejs >/dev/null 2>&1",
    )
    .with_check("command -v node && command -v npm")
    .with_timeout(240)
    .with_retries(2)
}

/// Install plan for Codex (`npm install -g @openai/codex`).
fn codex_plan() -> InstallerPlan {
    InstallerPlan {
        claw_type: "tool-codex",
        steps: vec![
            ensure_nodejs_step(),
            InstallerStep::new("install_codex", "npm install -g @openai/codex")
                .with_check("command -v codex")
                .with_timeout(180)
                .with_retries(2),
        ],
    }
}

/// Install plan for Claude Code (`npm install -g @anthropic-ai/claude-code`).
fn claude_code_plan() -> InstallerPlan {
    InstallerPlan {
        claw_type: "tool-claude-code",
        steps: vec![
            ensure_nodejs_step(),
            InstallerStep::new(
                "install_claude_code",
                "npm install -g @anthropic-ai/claude-code",
            )
            .with_check("command -v claude")
            .with_timeout(180)
            .with_retries(2),
        ],
    }
}

/// Install plan for `OpenCode` (`npm install -g opencode-ai`).
///
/// `OpenCode` moved from <https://github.com/opencode-ai/opencode> (archived Go
/// binary) to <https://github.com/anomalyco/opencode> (TypeScript, published
/// on npm as `opencode-ai`).
fn opencode_plan() -> InstallerPlan {
    InstallerPlan {
        claw_type: "tool-opencode",
        steps: vec![
            ensure_nodejs_step(),
            InstallerStep::new("install_opencode", "npm install -g opencode-ai@latest")
                .with_check("command -v opencode")
                .with_timeout(180)
                .with_retries(2),
        ],
    }
}

/// Get the install plan for a tool by canonical name.
fn get_tool_plan(tool: &str) -> Option<InstallerPlan> {
    match tool {
        TOOL_CODEX => Some(codex_plan()),
        TOOL_CLAUDE_CODE => Some(claude_code_plan()),
        TOOL_OPENCODE => Some(opencode_plan()),
        _ => None,
    }
}

/// Install the requested coding tools inside the guest VM.
///
/// Best-effort: each tool is installed independently. A failure in one tool
/// does not prevent the others from being installed, and does not fail the
/// overall instance creation.
///
/// Before installing any tool, the guest filesystem is grown online via
/// `resize2fs /dev/vda`. This is necessary because the host expands the
/// rootfs file offline, but snapshot-restored VMs still see the old
/// (small) filesystem size until the guest kernel is told to re-read the
/// partition geometry.
pub async fn install_coding_tools(ssh: &dyn SshActions, tools: &[String]) {
    if tools.is_empty() {
        return;
    }

    tracing::info!(
        "[tools] installing {} coding tool(s): {}",
        tools.len(),
        tools.join(", ")
    );

    // Grow the guest rootfs online so there is room for tool packages.
    // The host-side `expand_rootfs` extends the file + offline ext4, but
    // after a snapshot restore the guest kernel still sees the old size.
    match ssh.exec("resize2fs /dev/vda 2>/dev/null || true").await {
        Ok(out) => tracing::info!("[tools] guest rootfs grown: {}", out.trim()),
        Err(e) => tracing::warn!("[tools] guest resize2fs failed (non-fatal): {e}"),
    }

    for tool in tools {
        let Some(plan) = get_tool_plan(tool) else {
            tracing::warn!("[tools] unknown tool '{tool}', skipping");
            continue;
        };

        match plan.execute(ssh).await {
            Ok(()) => tracing::info!("[tools] {tool} installed successfully"),
            Err(e) => tracing::warn!("[tools] {tool} install failed (non-fatal): {e}"),
        }
    }
}

/// Normalize a tool name from various user-supplied variants to the canonical
/// form. Returns `None` if the name is not recognized.
#[must_use]
pub fn normalize_tool_name(name: &str) -> Option<&'static str> {
    match name {
        "codex" => Some(TOOL_CODEX),
        "claude-code" | "claudeCode" | "claude_code" => Some(TOOL_CLAUDE_CODE),
        "opencode" | "openCode" | "open_code" | "open-code" => Some(TOOL_OPENCODE),
        _ => None,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_canonical_names() {
        assert_eq!(normalize_tool_name("codex"), Some(TOOL_CODEX));
        assert_eq!(normalize_tool_name("claude-code"), Some(TOOL_CLAUDE_CODE));
        assert_eq!(normalize_tool_name("opencode"), Some(TOOL_OPENCODE));
    }

    #[test]
    fn normalize_variant_names() {
        assert_eq!(normalize_tool_name("claudeCode"), Some(TOOL_CLAUDE_CODE));
        assert_eq!(normalize_tool_name("claude_code"), Some(TOOL_CLAUDE_CODE));
        assert_eq!(normalize_tool_name("openCode"), Some(TOOL_OPENCODE));
        assert_eq!(normalize_tool_name("open_code"), Some(TOOL_OPENCODE));
        assert_eq!(normalize_tool_name("open-code"), Some(TOOL_OPENCODE));
    }

    #[test]
    fn normalize_unknown_returns_none() {
        assert_eq!(normalize_tool_name("unknown"), None);
        assert_eq!(normalize_tool_name(""), None);
    }

    #[test]
    fn default_tools_contains_all_three() {
        assert_eq!(DEFAULT_TOOLS.len(), 3);
        assert!(DEFAULT_TOOLS.contains(&TOOL_CODEX));
        assert!(DEFAULT_TOOLS.contains(&TOOL_CLAUDE_CODE));
        assert!(DEFAULT_TOOLS.contains(&TOOL_OPENCODE));
    }

    #[test]
    fn get_tool_plan_known_tools() {
        assert!(get_tool_plan(TOOL_CODEX).is_some());
        assert!(get_tool_plan(TOOL_CLAUDE_CODE).is_some());
        assert!(get_tool_plan(TOOL_OPENCODE).is_some());
    }

    #[test]
    fn get_tool_plan_unknown_returns_none() {
        assert!(get_tool_plan("unknown").is_none());
    }

    #[test]
    fn codex_plan_has_nodejs_step() {
        let plan = codex_plan();
        assert_eq!(plan.steps[0].phase, "ensure_nodejs");
        assert_eq!(plan.steps[1].phase, "install_codex");
    }

    #[test]
    fn claude_code_plan_has_nodejs_step() {
        let plan = claude_code_plan();
        assert_eq!(plan.steps[0].phase, "ensure_nodejs");
        assert_eq!(plan.steps[1].phase, "install_claude_code");
    }

    #[test]
    fn opencode_plan_has_nodejs_and_install_steps() {
        let plan = opencode_plan();
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].phase, "ensure_nodejs");
        assert_eq!(plan.steps[1].phase, "install_opencode");
    }

    #[test]
    fn install_commands_reference_correct_packages() {
        let codex = codex_plan();
        assert!(
            codex.steps[1].command.contains("@openai/codex"),
            "codex install must use @openai/codex npm package",
        );

        let claude = claude_code_plan();
        assert!(
            claude.steps[1]
                .command
                .contains("@anthropic-ai/claude-code"),
            "claude-code install must use @anthropic-ai/claude-code npm package",
        );

        let opencode = opencode_plan();
        assert!(
            opencode.steps[1].command.contains("opencode-ai"),
            "opencode install must use opencode-ai npm package",
        );
    }

    #[test]
    fn plans_have_idempotency_checks() {
        for tool in DEFAULT_TOOLS {
            let plan = get_tool_plan(tool).unwrap();
            for step in &plan.steps {
                assert!(
                    step.idempotency_check.is_some(),
                    "step '{}' in tool '{tool}' missing idempotency check",
                    step.phase,
                );
            }
        }
    }
}
