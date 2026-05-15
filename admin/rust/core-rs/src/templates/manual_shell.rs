//! manual-shell só pode ser usado em sandbox. Nunca promovido a `Tier::Supported` sem revisão humana.
//! Usado por propostas LLM (Fase H).
//!
//! `manual-shell` template — last-resort escape hatch that runs
//! `config.manual_script` verbatim under `bash -c`.
//!
//! By design this template produces exactly one step, with no idempotency
//! check, no retries, and a large timeout. It is intended for:
//!
//! - LLM-generated install proposals (Phase H of P-46) that haven't been
//!   converted into a typed template yet.
//! - Early experiments in the sandbox tier (`Tier::Detected` /
//!   `Tier::Catalog`) where we want to see whether a recipe even works before
//!   investing in a proper template.
//!
//! It MUST NOT be used for `Tier::Supported` entries. The build-time
//! invariants in `core-rs/build.rs` enforce this indirectly: Supported
//! entries must have `install_plan_source: "builtin"`, which means they
//! never reach `templates::render` at all.

use super::StepSpec;
use crate::manifest::InstallConfig;

/// Render a single step that execs `config.manual_script` as-is.
#[must_use]
pub fn render(config: &InstallConfig) -> Vec<StepSpec> {
    let script = config.manual_script;
    // `bash -c` with a single-quoted body, then shell-escape any embedded
    // single quotes so the caller's script can still contain them. The script
    // runs inside the guest VM, so this escaping is about producing valid
    // bash on the wire, not about sandbox security (there is no sandbox at
    // the template layer — trust comes from the Tier gate).
    let quoted = script.replace('\'', r"'\''");
    let command = format!("bash -c '{quoted}'");
    vec![
        StepSpec::new("manual_shell", command)
            .with_timeout(1800)
            .with_retries(0),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_shell_emits_exactly_one_step() {
        let cfg = InstallConfig {
            manual_script: "echo hello",
            ..Default::default()
        };
        let steps = render(&cfg);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].phase, "manual_shell");
        assert_eq!(steps[0].max_retries, 0);
        assert!(steps[0].idempotency_check.is_none());
    }

    #[test]
    fn manual_shell_wraps_script_in_bash_c() {
        let cfg = InstallConfig {
            manual_script: "echo hello",
            ..Default::default()
        };
        let step = &render(&cfg)[0];
        assert_eq!(step.command, "bash -c 'echo hello'");
    }

    #[test]
    fn manual_shell_escapes_embedded_single_quotes() {
        let cfg = InstallConfig {
            manual_script: "echo 'hi there'",
            ..Default::default()
        };
        let step = &render(&cfg)[0];
        // Single quotes inside the body close the outer quoted block and are
        // re-opened via '\''.
        assert!(
            step.command.contains(r"'\''hi there'\''"),
            "quote escape failed, got: {}",
            step.command,
        );
    }

    #[test]
    fn manual_shell_handles_empty_script() {
        // Empty script is still rendered as a valid (no-op) bash -c.
        let cfg = InstallConfig {
            manual_script: "",
            ..Default::default()
        };
        let step = &render(&cfg)[0];
        assert_eq!(step.command, "bash -c ''");
    }

    #[test]
    fn manual_shell_has_generous_timeout() {
        let cfg = InstallConfig {
            manual_script: "sleep 0",
            ..Default::default()
        };
        let step = &render(&cfg)[0];
        // Proposals may be arbitrarily slow; the scheduler owns the outer bound.
        assert!(step.timeout_secs >= 600);
    }

    #[test]
    fn manual_shell_multiline_script_round_trips() {
        let script = "set -e\napt-get update\napt-get install -y curl";
        let cfg = InstallConfig {
            manual_script: script,
            ..Default::default()
        };
        let step = &render(&cfg)[0];
        assert!(step.command.contains("apt-get update"));
        assert!(step.command.contains("apt-get install -y curl"));
    }
}
