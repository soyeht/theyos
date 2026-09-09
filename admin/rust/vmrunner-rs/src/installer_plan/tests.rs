#![cfg(test)]

use super::*;
use crate::ssh_client::test_utils::{MockSshSession, SshCall};
use core_rs::node_source::NODESOURCE_REPO_KEY_SHA256;

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
    // install_package should use an isolated venv and nanobot-ai
    assert!(
        plan.steps[1].command.contains("/opt/nanobot-venv"),
        "nanobot install should use an isolated venv"
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
    // Must target Node 22 via the explicit NodeSource repo config with
    // reviewed key material, and never execute the remote setup script.
    assert!(
        install_node.command.contains("nodesource.sources"),
        "install_node should configure nodesource.sources, got: {}",
        install_node.command
    );
    assert!(
        install_node.command.contains(NODESOURCE_REPO_KEY_SHA256),
        "install_node should verify the NodeSource key SHA-256, got: {}",
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
        !install_node.command.contains("setup_22"),
        "install_node should not execute the remote setup script, got: {}",
        install_node.command
    );
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
    assert!(
        install_pnpm
            .command
            .contains(&format!("pnpm@{DEFAULT_PNPM_VERSION}")),
        "install_pnpm should pin pnpm, got: {}",
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
    assert!(
        plan.steps[2].command.contains(DEFAULT_OPENCLAW_REPO_REF),
        "openclaw clone_repo should fetch the reviewed commit"
    );
    assert!(
        plan.steps[2].command.contains("rev-parse HEAD"),
        "openclaw clone_repo should verify checked-out HEAD"
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
    assert!(
        plan.steps[2].command.contains(DEFAULT_ZEROCLAW_REPO_REF),
        "zeroclaw clone_repo should fetch the reviewed commit"
    );
    assert!(
        plan.steps[2].command.contains("rev-parse HEAD"),
        "zeroclaw clone_repo should verify checked-out HEAD"
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
    // pip_install should use an isolated venv
    assert!(
        plan.steps[3].command.contains("/opt/hermes-agent-venv"),
        "hermes-agent pip_install should use an isolated venv"
    );
    // install_node should use the explicit NodeSource repo config with
    // reviewed key material.
    assert!(
        plan.steps[1].command.contains("nodesource.sources"),
        "hermes-agent install_node should configure nodesource.sources"
    );
    assert!(
        plan.steps[1].command.contains(NODESOURCE_REPO_KEY_SHA256),
        "hermes-agent install_node should verify NodeSource key SHA-256"
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
    assert!(
        plan.steps[2]
            .command
            .contains(DEFAULT_HERMES_AGENT_REPO_REF),
        "hermes-agent clone_repo should fetch the reviewed commit"
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
    // install_node should use the explicit NodeSource repo config with
    // reviewed key material.
    assert!(
        plan.steps[1].command.contains("nodesource.sources"),
        "noclaw install_node should configure nodesource.sources"
    );
    assert!(
        plan.steps[1].command.contains(NODESOURCE_REPO_KEY_SHA256),
        "noclaw install_node should verify NodeSource key SHA-256"
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
        plan.steps[2].command.contains(&format!(
            "@anthropic-ai/claude-code@{DEFAULT_CLAUDE_CODE_VERSION}"
        )),
        "noclaw should pin @anthropic-ai/claude-code"
    );
    assert!(
        plan.steps[3].command.contains("opencode-ai"),
        "noclaw should install opencode-ai"
    );
    assert!(
        plan.steps[3]
            .command
            .contains(&format!("opencode-ai@{DEFAULT_OPENCODE_VERSION}")),
        "noclaw should pin opencode-ai"
    );
    assert!(
        plan.steps[4].command.contains("@openai/codex"),
        "noclaw should install @openai/codex"
    );
    assert!(
        plan.steps[4]
            .command
            .contains(&format!("@openai/codex@{DEFAULT_CODEX_VERSION}")),
        "noclaw should pin @openai/codex"
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
