#![cfg(test)]

use super::*;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[allow(unsafe_code)]
fn set_test_env_var(key: &str, value: &str) {
    // SAFETY: test-only helper; callers restore previous values.
    unsafe { std::env::set_var(key, value) };
}

#[allow(unsafe_code)]
fn remove_test_env_var(key: &str) {
    // SAFETY: test-only helper; callers restore previous values.
    unsafe { std::env::remove_var(key) };
}

fn write_mock_bin(dir: &Path, name: &str, script: &str) {
    let path = dir.join(name);
    fs::write(&path, script).expect("write mock binary");
    let mut perms = fs::metadata(&path).expect("mock metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("chmod mock binary");
}

fn log_script(name: &str, log_path: &Path, extra: &str) -> String {
    format!(
        "#!/bin/sh\nprintf '{name} %s\\n' \"$*\" >> {}\n{extra}\nexit 0\n",
        shell_quote(log_path.to_str().expect("utf8 log path")),
    )
}

#[test]
fn infer_known_hyphenated_claw_type() {
    assert_eq!(
        infer_claw_type_from_container("hermes-agent-hermes-agent"),
        Some("hermes-agent".to_string())
    );
    assert_eq!(
        infer_claw_type_from_container("openclaw-openclaw"),
        Some("openclaw".to_string())
    );
}

#[test]
fn parse_helpers_handle_invalid_values() {
    assert_eq!(parse_port_value(Some("11435"), DEFAULT_LLM_PORT), 11_435);
    assert_eq!(
        parse_port_value(Some("0"), DEFAULT_LLM_PORT),
        DEFAULT_LLM_PORT
    );
    assert_eq!(
        parse_port_value(Some("not-a-port"), DEFAULT_LLM_PORT),
        DEFAULT_LLM_PORT
    );
    assert!(parse_flag_value("1", false));
    assert!(parse_flag_value("yes", false));
    assert!(!parse_flag_value("0", true));
    assert!(!parse_flag_value("off", true));
    assert!(parse_flag_value("unknown", true));
    assert!(!parse_flag_value("unknown", false));
}

#[test]
fn from_env_prefers_first_present_aliases() {
    let first_port_prev = std::env::var("THEYOS_TEST_FIRST_PORT").ok();
    let second_port_prev = std::env::var("THEYOS_TEST_SECOND_PORT").ok();
    let first_host_prev = std::env::var("THEYOS_TEST_FIRST_HOST").ok();
    let second_host_prev = std::env::var("THEYOS_TEST_SECOND_HOST").ok();

    set_test_env_var("THEYOS_TEST_FIRST_PORT", "12000");
    set_test_env_var("THEYOS_TEST_SECOND_PORT", "13000");
    assert_eq!(
        env_port_any(
            &["THEYOS_TEST_FIRST_PORT", "THEYOS_TEST_SECOND_PORT"],
            DEFAULT_LLM_PORT
        ),
        12_000
    );

    set_test_env_var("THEYOS_TEST_FIRST_HOST", "   ");
    set_test_env_var("THEYOS_TEST_SECOND_HOST", "bignix");
    assert_eq!(
        env_string_any(
            &["THEYOS_TEST_FIRST_HOST", "THEYOS_TEST_SECOND_HOST"],
            DEFAULT_LLM_HOST_ADDR
        ),
        "bignix"
    );

    match first_port_prev {
        Some(value) => set_test_env_var("THEYOS_TEST_FIRST_PORT", &value),
        None => remove_test_env_var("THEYOS_TEST_FIRST_PORT"),
    }
    match second_port_prev {
        Some(value) => set_test_env_var("THEYOS_TEST_SECOND_PORT", &value),
        None => remove_test_env_var("THEYOS_TEST_SECOND_PORT"),
    }
    match first_host_prev {
        Some(value) => set_test_env_var("THEYOS_TEST_FIRST_HOST", &value),
        None => remove_test_env_var("THEYOS_TEST_FIRST_HOST"),
    }
    match second_host_prev {
        Some(value) => set_test_env_var("THEYOS_TEST_SECOND_HOST", &value),
        None => remove_test_env_var("THEYOS_TEST_SECOND_HOST"),
    }
}

#[test]
fn from_env_uses_platform_defaults_and_chat_mode_overrides() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let temp = tempfile::tempdir().expect("tempdir");
    let hermes_prev = std::env::var("THEYOS_HERMES_CHAT_MODE").ok();
    let openclaw_prev = std::env::var("THEYOS_OPENCLAW_CHAT_MODE").ok();
    let autodetect_prev = std::env::var("THEYOS_LLM_CONTEXT_AUTO_DETECT").ok();
    let profile_prev = std::env::var("THEYOS_LLM_PROFILE_PATH").ok();

    remove_test_env_var("THEYOS_HERMES_CHAT_MODE");
    remove_test_env_var("THEYOS_OPENCLAW_CHAT_MODE");
    set_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT", "0");
    set_test_env_var(
        "THEYOS_LLM_PROFILE_PATH",
        temp.path()
            .join("missing-profile.env")
            .to_str()
            .expect("utf8 profile path"),
    );
    let mac = LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
    assert_eq!(mac.chat_modes().hermes(), "chat");
    assert_eq!(mac.chat_modes().openclaw(), "local");
    let linux = LlmContract::from_env(
        Some("openclaw".to_string()),
        LlmBootstrapTarget::LinuxFirecracker,
    );
    assert_eq!(linux.chat_modes().hermes(), "chat");
    assert_eq!(linux.chat_modes().openclaw(), "gateway");

    set_test_env_var("THEYOS_HERMES_CHAT_MODE", "tui");
    set_test_env_var("THEYOS_OPENCLAW_CHAT_MODE", "gateway");
    let overridden =
        LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
    assert_eq!(overridden.chat_modes().hermes(), "tui");
    assert_eq!(overridden.chat_modes().openclaw(), "gateway");

    match hermes_prev {
        Some(value) => set_test_env_var("THEYOS_HERMES_CHAT_MODE", &value),
        None => remove_test_env_var("THEYOS_HERMES_CHAT_MODE"),
    }
    match openclaw_prev {
        Some(value) => set_test_env_var("THEYOS_OPENCLAW_CHAT_MODE", &value),
        None => remove_test_env_var("THEYOS_OPENCLAW_CHAT_MODE"),
    }
    match autodetect_prev {
        Some(value) => set_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT", &value),
        None => remove_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT"),
    }
    match profile_prev {
        Some(value) => set_test_env_var("THEYOS_LLM_PROFILE_PATH", &value),
        None => remove_test_env_var("THEYOS_LLM_PROFILE_PATH"),
    }
}

#[test]
fn provider_profiles_pick_user_friendly_defaults() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let temp = tempfile::tempdir().expect("tempdir");
    let provider_prev = std::env::var("THEYOS_LLM_PROVIDER").ok();
    let autodetect_prev = std::env::var("THEYOS_LLM_CONTEXT_AUTO_DETECT").ok();
    let context_prev = std::env::var("THEYOS_LLM_CONTEXT_WINDOW").ok();
    let profile_prev = std::env::var("THEYOS_LLM_PROFILE_PATH").ok();

    set_test_env_var("THEYOS_LLM_PROVIDER", "llama.cpp");
    set_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT", "0");
    remove_test_env_var("THEYOS_LLM_CONTEXT_WINDOW");
    set_test_env_var(
        "THEYOS_LLM_PROFILE_PATH",
        temp.path()
            .join("missing-profile.env")
            .to_str()
            .expect("utf8 profile path"),
    );
    let llamacpp = LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
    assert_eq!(llamacpp.provider(), "llamacpp");
    assert_eq!(llamacpp.model(), "local");
    assert_eq!(llamacpp.host_port(), DEFAULT_OPENAI_COMPAT_PORT);
    assert_eq!(llamacpp.context_window(), SAFE_FALLBACK_CONTEXT_WINDOW);
    assert_eq!(llamacpp.context_source(), "safe-fallback");

    set_test_env_var("THEYOS_LLM_PROVIDER", "mlx-lm");
    let mlx = LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
    assert_eq!(mlx.provider(), "mlx");
    assert_eq!(mlx.model(), DEFAULT_MLX_MODEL);
    assert_eq!(mlx.host_port(), DEFAULT_OPENAI_COMPAT_PORT);
    assert_eq!(mlx.context_window(), 32_768);
    assert_eq!(mlx.context_source(), "model-profile");

    // The "proxy" sentinel routes through the host-side multiplexer.
    // Default port is the proxy port (NOT a runtime-native port), the
    // API key is a placeholder — real auth happens host-side — and
    // the OpenAI base URL is stamped with the claw type so the proxy
    // can apply per-claw overrides.
    set_test_env_var("THEYOS_LLM_PROVIDER", "proxy");
    let proxy = LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
    assert_eq!(proxy.provider(), PROXY_PROVIDER_ID);
    assert_eq!(proxy.host_port(), DEFAULT_LLM_PROXY_PORT);
    assert_eq!(proxy.api_key(), "theyos-proxy-placeholder");
    assert_eq!(
        proxy.openai_base_url(),
        "http://127.0.0.1:18900/v1/c/openclaw",
        "proxy openai base url should stamp claw type for per-claw routing",
    );

    // No claw type → no claw stamp; falls through to the global default.
    let proxy_no_claw = LlmContract::from_env(None, LlmBootstrapTarget::MacosVz);
    assert_eq!(proxy_no_claw.provider(), PROXY_PROVIDER_ID);
    assert_eq!(proxy_no_claw.openai_base_url(), "http://127.0.0.1:18900/v1");

    match provider_prev {
        Some(value) => set_test_env_var("THEYOS_LLM_PROVIDER", &value),
        None => remove_test_env_var("THEYOS_LLM_PROVIDER"),
    }
    match autodetect_prev {
        Some(value) => set_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT", &value),
        None => remove_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT"),
    }
    match context_prev {
        Some(value) => set_test_env_var("THEYOS_LLM_CONTEXT_WINDOW", &value),
        None => remove_test_env_var("THEYOS_LLM_CONTEXT_WINDOW"),
    }
    match profile_prev {
        Some(value) => set_test_env_var("THEYOS_LLM_PROFILE_PATH", &value),
        None => remove_test_env_var("THEYOS_LLM_PROFILE_PATH"),
    }
}

#[test]
fn from_env_reads_persisted_llm_profile_file() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let temp = tempfile::tempdir().expect("tempdir");
    let profile_path = temp.path().join("llm-profile.env");
    fs::write(
        &profile_path,
        "THEYOS_LLM_PROVIDER=llama.cpp\n\
             THEYOS_LLM_MODEL=local64\n\
             THEYOS_LLM_HOST_PORT=18082\n\
             THEYOS_LLM_GUEST_PORT=18082\n\
             THEYOS_LLM_CONTEXT_WINDOW=65536\n\
             THEYOS_OPENCLAW_MODEL_REF=llamacpp/local64\n",
    )
    .expect("write profile");

    let keys = [
        "THEYOS_LLM_PROFILE_PATH",
        "THEYOS_LLM_PROVIDER",
        "THEYOS_LLM_MODEL",
        "THEYOS_LLM_HOST_PORT",
        "THEYOS_LLM_GUEST_PORT",
        "THEYOS_LLM_CONTEXT_WINDOW",
        "THEYOS_OPENCLAW_MODEL_REF",
    ];
    let previous: Vec<_> = keys
        .iter()
        .map(|key| (*key, std::env::var(key).ok()))
        .collect();

    for key in keys {
        remove_test_env_var(key);
    }
    set_test_env_var(
        "THEYOS_LLM_PROFILE_PATH",
        profile_path.to_str().expect("utf8 profile path"),
    );

    let contract = LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
    assert_eq!(contract.provider(), "llamacpp");
    assert_eq!(contract.model(), "local64");
    assert_eq!(contract.host_port(), 18_082);
    assert_eq!(contract.guest_port(), 18_082);
    assert_eq!(contract.context_window(), 65_536);
    assert_eq!(contract.context_source(), "env");
    assert_eq!(contract.openclaw().model_ref(), "llamacpp/local64");

    for (key, value) in previous {
        match value {
            Some(value) => set_test_env_var(key, &value),
            None => remove_test_env_var(key),
        }
    }
}

#[test]
fn openclaw_uses_openai_compatible_api_for_llamacpp_and_mlx() {
    let llamacpp = LlmContract::for_tests("openclaw", LlmBootstrapTarget::MacosVz)
        .with_provider("llama.cpp")
        .with_model("local")
        .with_guest_port(DEFAULT_OPENAI_COMPAT_PORT);
    let shell = llamacpp.render_pty_shell(LlmBootstrapTarget::MacosVz);
    assert!(shell.contains("export THEYOS_LLM_PROVIDER='llamacpp';"));
    assert!(shell.contains("export THEYOS_LLM_BASE_URL='http://127.0.0.1:8080';"));
    assert!(shell.contains("export THEYOS_LLM_OPENAI_BASE_URL='http://127.0.0.1:8080/v1';"));
    assert!(shell.contains("export THEYOS_OPENCLAW_PROVIDER_KEY='models.providers.llamacpp';"));
    assert!(shell.contains("export THEYOS_OPENCLAW_MODEL_REF='llamacpp/local';"));
    assert!(shell.contains(r#""api":"openai-completions""#));
    assert!(shell.contains(r#""baseUrl":"http://127.0.0.1:8080/v1""#));
}

#[test]
fn proxy_render_pty_shell_stamps_per_claw_url_and_reverse_tunnel() {
    // Slice C regression guard: when provider=proxy, the rendered
    // shell that fc-ssh injects on PTY launch MUST set
    // THEYOS_LLM_OPENAI_BASE_URL to the per-claw routing URL, AND
    // ssh_reverse_forward MUST return a spec mapping guest:18900 →
    // host:18900. If either drifts, claws stop reaching the
    // host-side multiplexer and "production PTY path" validation
    // silently breaks.
    let _guard = ENV_LOCK.lock().expect("env lock");
    let provider_prev = std::env::var("THEYOS_LLM_PROVIDER").ok();
    let model_prev = std::env::var("THEYOS_LLM_MODEL").ok();
    set_test_env_var("THEYOS_LLM_PROVIDER", "proxy");
    set_test_env_var("THEYOS_LLM_MODEL", "glm-4.6");

    let contract = LlmContract::from_env(
        Some("hermes-agent".to_string()),
        LlmBootstrapTarget::LinuxFirecracker,
    );

    let shell = contract.render_pty_shell(LlmBootstrapTarget::LinuxFirecracker);
    assert!(
        shell.contains("export THEYOS_LLM_PROVIDER='proxy';"),
        "render_pty_shell must emit provider=proxy:\n{shell}",
    );
    assert!(
        shell.contains("export THEYOS_LLM_MODEL='glm-4.6';"),
        "render_pty_shell must emit model:\n{shell}",
    );
    assert!(
        shell.contains(
            "export THEYOS_LLM_OPENAI_BASE_URL='http://127.0.0.1:18900/v1/c/hermes-agent';"
        ),
        "render_pty_shell must stamp the per-claw routing URL for proxy provider:\n{shell}",
    );

    let forward = contract
        .ssh_reverse_forward()
        .expect("tunnel must be on by default");
    assert_eq!(
        forward, "127.0.0.1:18900:127.0.0.1:18900",
        "reverse tunnel must map guest:18900 → host loopback:18900",
    );

    match provider_prev {
        Some(v) => set_test_env_var("THEYOS_LLM_PROVIDER", &v),
        None => remove_test_env_var("THEYOS_LLM_PROVIDER"),
    }
    match model_prev {
        Some(v) => set_test_env_var("THEYOS_LLM_MODEL", &v),
        None => remove_test_env_var("THEYOS_LLM_MODEL"),
    }
}

#[test]
fn proxy_render_pty_shell_without_claw_falls_back_to_default_v1() {
    // Mirror of the openai_base_url default branch (no claw stamp):
    // /v1 only, no per-claw segment. Exercises the `else` branch in
    // claw_llm.rs around line 297-304.
    let _guard = ENV_LOCK.lock().expect("env lock");
    let provider_prev = std::env::var("THEYOS_LLM_PROVIDER").ok();
    set_test_env_var("THEYOS_LLM_PROVIDER", "proxy");

    let contract = LlmContract::from_env(None, LlmBootstrapTarget::LinuxFirecracker);
    let shell = contract.render_pty_shell(LlmBootstrapTarget::LinuxFirecracker);
    assert!(
        shell.contains("export THEYOS_LLM_OPENAI_BASE_URL='http://127.0.0.1:18900/v1';"),
        "no-claw render must fall back to /v1 (default route):\n{shell}",
    );

    match provider_prev {
        Some(v) => set_test_env_var("THEYOS_LLM_PROVIDER", &v),
        None => remove_test_env_var("THEYOS_LLM_PROVIDER"),
    }
}

#[test]
fn reverse_forward_respects_tunnel_flag() {
    let contract = LlmContract::for_tests("openclaw", LlmBootstrapTarget::LinuxFirecracker)
        .with_host_addr("bignix")
        .with_guest_port(11_435);
    assert_eq!(
        contract.ssh_reverse_forward(),
        Some("127.0.0.1:11435:bignix:11434".to_string())
    );
    assert_eq!(contract.with_tunnel(false).ssh_reverse_forward(), None);
}

#[test]
fn render_shell_uses_contract_chat_modes_not_platform_modes() {
    let contract = LlmContract::for_tests("openclaw", LlmBootstrapTarget::LinuxFirecracker)
        .with_model("qwen3.6:27b")
        .with_chat_modes(ClawChatModes::new("chat", "local"));

    let linux = contract.render_pty_shell(LlmBootstrapTarget::LinuxFirecracker);
    assert!(!linux.contains("export PATH=/opt/homebrew/bin"));
    assert!(linux.contains("export THEYOS_OPENCLAW_CHAT_MODE='local';"));
    assert!(linux.contains("export THEYOS_HERMES_CHAT_MODE='chat';"));
    assert!(linux.contains("theyos_openclaw_tui_local"));
    assert!(linux.contains(r#"hermes chat -m "$THEYOS_LLM_MODEL""#));
    assert!(linux.contains("export THEYOS_OPENCLAW_MODEL_REF='ollama/qwen3.6:27b';"));
    assert!(!linux.contains(r#"model_ref="ollama/$THEYOS_LLM_MODEL""#));

    let mac = contract.render_pty_shell(LlmBootstrapTarget::MacosVz);
    assert!(mac.contains("export PATH=/opt/homebrew/bin"));
}

#[test]
fn rendered_shell_is_posix_shell_parseable() {
    let command = LlmContract::for_tests("openclaw", LlmBootstrapTarget::MacosVz)
        .render_pty_shell(LlmBootstrapTarget::MacosVz);

    let mut child = Command::new("sh")
        .arg("-n")
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn sh -n");
    child
        .stdin
        .as_mut()
        .expect("sh stdin")
        .write_all(command.as_bytes())
        .expect("write generated shell command");
    let status = child.wait().expect("wait for sh -n");
    assert!(status.success(), "generated PTY shell command failed sh -n");
}

#[test]
fn rendered_bootstrap_executes_openclaw_with_mocked_cli() {
    let temp = tempfile::tempdir().expect("tempdir");
    let log = temp.path().join("calls.log");
    write_mock_bin(
        temp.path(),
        "openclaw",
        &log_script(
            "openclaw",
            &log,
            r#"if [ "$1" = "gateway" ] && [ "$2" = "health" ]; then exit 0; fi"#,
        ),
    );
    write_mock_bin(temp.path(), "bash", &log_script("bash", &log, ""));
    // Mock `nc` so the bootstrap's `theyos_openclaw_gateway_port_open`
    // sees the gateway as live. On dev hosts something is listening on
    // 18789 from prior sessions; CI runners are clean, so the real
    // `nc -z 127.0.0.1 18789` fails and the bootstrap drops into the
    // 60-iter wait loop — which never calls `openclaw gateway health`,
    // failing this test's argv assertion. A 1-line `exit 0` mock pins
    // the success path.
    write_mock_bin(temp.path(), "nc", "#!/bin/sh\nexit 0\n");

    let command = LlmContract::for_tests("openclaw", LlmBootstrapTarget::LinuxFirecracker)
        .with_model("qwen3.6:27b")
        .with_chat_modes(ClawChatModes::new("tui", "local"))
        .render_pty_shell(LlmBootstrapTarget::LinuxFirecracker);
    let path = format!("{}:/bin:/usr/bin", temp.path().display());

    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("PATH", path)
        .env("HOME", temp.path())
        .output()
        .expect("execute rendered shell");
    assert!(
        output.status.success(),
        "rendered shell failed: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let calls = fs::read_to_string(&log).expect("read mock log");
    assert!(calls.contains("openclaw config set models.mode merge"));
    assert!(calls.contains("openclaw config set models.providers.ollama"));
    assert!(calls.contains("openclaw config set agents.defaults.model.primary ollama/qwen3.6:27b"));
    assert!(calls.contains("openclaw tui --help"));
    assert!(
        calls.contains("openclaw gateway health --url ws://127.0.0.1:18789 --token theyos-local")
    );
    assert!(calls.contains(
        "openclaw tui --url ws://127.0.0.1:18789 --token theyos-local --timeout-ms 180000"
    ));
    assert!(calls.contains("bash -l -i"));
}

#[test]
fn rendered_bootstrap_executes_hermes_with_mocked_cli() {
    let temp = tempfile::tempdir().expect("tempdir");
    let log = temp.path().join("calls.log");
    write_mock_bin(temp.path(), "hermes", &log_script("hermes", &log, ""));
    write_mock_bin(temp.path(), "bash", &log_script("bash", &log, ""));

    let command = LlmContract::for_tests("hermes-agent", LlmBootstrapTarget::LinuxFirecracker)
        .with_chat_modes(ClawChatModes::new("tui", "gateway"))
        .render_pty_shell(LlmBootstrapTarget::LinuxFirecracker);
    let path = format!("{}:/bin:/usr/bin", temp.path().display());

    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("PATH", path)
        .env("HOME", temp.path())
        .output()
        .expect("execute rendered shell");
    assert!(
        output.status.success(),
        "rendered shell failed: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let calls = fs::read_to_string(&log).expect("read mock log");
    assert!(calls.contains("hermes config set model.provider custom"));
    assert!(calls.contains("hermes config set model.base_url http://127.0.0.1:11434/v1"));
    assert!(calls.contains("hermes --help"));
    assert!(calls.contains("hermes chat -m llama3.1"));
    assert!(calls.contains("bash -l -i"));
}
