//! Integration tests for [`ClaudeCliProvider`].
//!
//! These tests exercise the real subprocess path against a mock `claude`
//! binary written to a tempfile (POSIX shell script with `#!/bin/sh`).
//! That gives us:
//!
//! - Argument propagation (we can inspect what the wrapper script
//!   received via the binary writing its argv to a file).
//! - Stdout shape (whatever the mock writes is what the provider sees).
//! - Exit code handling (mock exits non-zero, we verify the error).
//! - Timeout handling (mock sleeps longer than the timeout, we verify the
//!   provider gives up).
//! - Binary-missing handling (point `cli_path` at a non-existent file).
//!
//! The pattern mirrors `core_rs::claw_llm::tests` which uses the same
//! tempfile-script approach to test the bootstrap shell rendering.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use llm_proxy::profile::ActiveProfile;
use llm_proxy::provider::{ChatResponse, ClaudeCliProvider};
use llm_proxy::{Provider, ServerState, router};
use serde_json::{Value, json};
use tempfile::TempDir;

/// Helper — write `body` as an executable POSIX script under `dir` and
/// return its absolute path. Tests use this to plant a mock `claude`
/// binary that the provider invokes.
fn install_mock_claude(dir: &TempDir, body: &str) -> std::path::PathBuf {
    let path = dir.path().join("claude");
    std::fs::write(&path, body).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

fn body(model: &str, content: &str, stream: bool) -> Value {
    json!({
        "model": model,
        "stream": stream,
        "messages": [{"role": "user", "content": content}],
    })
}

#[tokio::test]
async fn forwards_prompt_to_subprocess_and_returns_stdout_as_assistant_content() {
    let dir = tempfile::tempdir().unwrap();
    // Mock writes a fixed reply. Confirms stdout pass-through.
    let cli = install_mock_claude(
        &dir,
        "#!/bin/sh\nprintf 'Hello world from mock claude\\n'\n",
    );
    let provider = ClaudeCliProvider::new(
        "claude-cli",
        Some(&cli),
        Some(Duration::from_secs(5)),
        vec!["claude-sonnet-4-7".into()],
    );

    let req = body("claude-sonnet-4-7", "say hi", false);
    let response = provider.chat(&req, false).await.unwrap();
    let ChatResponse::Json(bytes) = response else {
        panic!("expected JSON response");
    };
    let payload: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(payload["object"], "chat.completion");
    assert_eq!(payload["model"], "claude-sonnet-4-7");
    assert_eq!(
        payload["choices"][0]["message"]["content"],
        "Hello world from mock claude"
    );
    assert_eq!(payload["choices"][0]["message"]["role"], "assistant");
    assert_eq!(payload["choices"][0]["finish_reason"], "stop");
}

#[tokio::test]
async fn passes_p_flag_and_model_alias_and_prompt_as_args() {
    let dir = tempfile::tempdir().unwrap();
    // Mock writes its argv (one per line) to a sibling file so the test
    // can verify what the wrapper actually received.
    let argv_log = dir.path().join("argv.log");
    let mock_body = format!(
        "#!/bin/sh\n: > {log}\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> {log}; done\nprintf 'ok\\n'\n",
        log = argv_log.display()
    );
    let cli = install_mock_claude(&dir, &mock_body);
    let provider = ClaudeCliProvider::new(
        "claude-cli",
        Some(&cli),
        Some(Duration::from_secs(5)),
        vec!["claude-opus-4-7".into()],
    );

    // Opus → "opus"
    let _ = provider
        .chat(&body("claude-opus-4-7", "marker-prompt", false), false)
        .await
        .unwrap();
    let argv = std::fs::read_to_string(&argv_log).unwrap();
    // The first three argv entries are single tokens (`-p`, `--model`,
    // `opus`). We can match them against the first lines of the log.
    let lines: Vec<&str> = argv.lines().collect();
    assert_eq!(lines.first().copied(), Some("-p"));
    assert_eq!(lines.get(1).copied(), Some("--model"));
    assert_eq!(lines.get(2).copied(), Some("opus"));
    // The fourth argv entry is the prompt — which itself contains a
    // newline between the role bracket and the body. Logged with
    // `printf '%s\n'`, that internal newline ends up as a line break in
    // the argv-log, so we check substring containment against the full
    // log content rather than a single line.
    assert!(
        argv.contains("[user]"),
        "prompt missing role tag in argv log: {argv}"
    );
    assert!(
        argv.contains("marker-prompt"),
        "prompt missing content in argv log: {argv}"
    );

    // Haiku → "haiku"
    std::fs::write(&argv_log, "").unwrap();
    let _ = provider
        .chat(&body("claude-haiku-4-5", "x", false), false)
        .await
        .unwrap();
    let argv = std::fs::read_to_string(&argv_log).unwrap();
    assert!(argv.lines().any(|l| l == "haiku"), "haiku flag missing: {argv}");
}

#[tokio::test]
async fn non_zero_exit_propagates_as_upstream_error_with_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let cli = install_mock_claude(
        &dir,
        "#!/bin/sh\nprintf 'not logged in\\n' >&2\nexit 1\n",
    );
    let provider = ClaudeCliProvider::new(
        "claude-cli",
        Some(&cli),
        Some(Duration::from_secs(5)),
        vec!["x".into()],
    );

    let result = provider
        .chat(&body("claude-sonnet", "hi", false), false)
        .await;


    let Err(err) = result else {


        panic!("expected Err, got Ok");


    };
    match err {
        llm_proxy::ProxyError::Upstream { provider, message } => {
            assert_eq!(provider, "claude-cli");
            assert!(
                message.contains("status 1"),
                "exit code missing from error: {message}"
            );
            assert!(
                message.contains("not logged in"),
                "stderr missing from error: {message}"
            );
        }
        other => panic!("expected Upstream, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_binary_reports_a_clear_install_hint() {
    let dir = tempfile::tempdir().unwrap();
    // Never write the binary — point at a path that doesn't exist.
    let phantom = dir.path().join("definitely-not-here");
    let provider = ClaudeCliProvider::new(
        "claude-cli",
        Some(&phantom),
        Some(Duration::from_secs(5)),
        vec!["x".into()],
    );
    let result = provider
        .chat(&body("claude-sonnet", "hi", false), false)
        .await;

    let Err(err) = result else {

        panic!("expected Err, got Ok");

    };
    match err {
        llm_proxy::ProxyError::Upstream { provider, message } => {
            assert_eq!(provider, "claude-cli");
            assert!(
                message.contains("not found"),
                "missing 'not found' in: {message}"
            );
            assert!(
                message.contains("install it on the host"),
                "missing install hint in: {message}"
            );
        }
        other => panic!("expected Upstream, got {other:?}"),
    }
}

#[tokio::test]
async fn subprocess_timeout_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    // Sleeps longer than the timeout we configure.
    let cli = install_mock_claude(&dir, "#!/bin/sh\nsleep 5\nprintf 'too slow\\n'\n");
    let provider = ClaudeCliProvider::new(
        "claude-cli",
        Some(&cli),
        Some(Duration::from_millis(200)),
        vec!["x".into()],
    );
    let start = std::time::Instant::now();
    let result = provider
        .chat(&body("claude-sonnet", "hi", false), false)
        .await;

    let Err(err) = result else {

        panic!("expected Err, got Ok");

    };
    let elapsed = start.elapsed();
    // kill_on_drop + tokio::time::timeout must bail well before the 5s
    // sleep — confirm we returned within a small multiple of the deadline.
    assert!(
        elapsed < Duration::from_secs(2),
        "timeout did not fire fast enough: elapsed={elapsed:?}"
    );
    match err {
        llm_proxy::ProxyError::Upstream { message, .. } => {
            assert!(
                message.contains("timed out"),
                "missing timeout marker: {message}"
            );
        }
        other => panic!("expected Upstream, got {other:?}"),
    }
}

#[tokio::test]
async fn streaming_response_emits_sse_chunks_with_role_then_content_then_stop_then_done() {
    let dir = tempfile::tempdir().unwrap();
    let cli = install_mock_claude(&dir, "#!/bin/sh\nprintf 'streamed reply\\n'\n");
    let provider = ClaudeCliProvider::new(
        "claude-cli",
        Some(&cli),
        Some(Duration::from_secs(5)),
        vec!["claude-sonnet-4-7".into()],
    );
    let response = provider
        .chat(&body("claude-sonnet-4-7", "anything", true), true)
        .await
        .unwrap();
    let ChatResponse::Stream(stream) = response else {
        panic!("expected stream response");
    };
    use futures_util::StreamExt;
    let collected: Vec<_> = stream.collect().await;
    // 4 frames: role, content, stop, [DONE].
    assert_eq!(collected.len(), 4, "expected 4 SSE frames, got {}", collected.len());
    let f0 = String::from_utf8(collected[0].as_ref().unwrap().to_vec()).unwrap();
    let f1 = String::from_utf8(collected[1].as_ref().unwrap().to_vec()).unwrap();
    let f2 = String::from_utf8(collected[2].as_ref().unwrap().to_vec()).unwrap();
    let f3 = String::from_utf8(collected[3].as_ref().unwrap().to_vec()).unwrap();
    assert!(f0.starts_with("data: ") && f0.ends_with("\n\n"));
    assert!(f0.contains("\"role\":\"assistant\""));
    assert!(f1.contains("\"content\":\"streamed reply\""));
    assert!(f2.contains("\"finish_reason\":\"stop\""));
    assert_eq!(f3, "data: [DONE]\n\n");
}

#[tokio::test]
async fn bad_request_when_messages_array_missing() {
    let dir = tempfile::tempdir().unwrap();
    let cli = install_mock_claude(&dir, "#!/bin/sh\nprintf 'unreachable\\n'\n");
    let provider = ClaudeCliProvider::new(
        "claude-cli",
        Some(&cli),
        Some(Duration::from_secs(5)),
        vec!["x".into()],
    );
    let result = provider
        .chat(&json!({"model": "claude-sonnet"}), false)
        .await;

    let Err(err) = result else {

        panic!("expected Err, got Ok");

    };
    match err {
        llm_proxy::ProxyError::BadRequest(msg) => {
            assert!(msg.contains("messages"), "missing field name: {msg}");
        }
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[tokio::test]
async fn bad_request_when_messages_yield_empty_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let cli = install_mock_claude(&dir, "#!/bin/sh\nprintf 'unreachable\\n'\n");
    let provider = ClaudeCliProvider::new(
        "claude-cli",
        Some(&cli),
        Some(Duration::from_secs(5)),
        vec!["x".into()],
    );
    // Messages array exists but all contents are empty/non-text.
    let result = provider
        .chat(
            &json!({
                "model": "claude-sonnet",
                "messages": [
                    {"role": "user", "content": ""},
                    {"role": "user", "content": [{"type": "image_url", "image_url": "data:..."}]},
                ],
            }),
            false,
        )
        .await;

    let Err(err) = result else {

        panic!("expected Err, got Ok");

    };
    match err {
        llm_proxy::ProxyError::BadRequest(_) => {}
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[tokio::test]
async fn proxy_router_serves_claude_via_default_active() {
    // Tests the wiring path from Slice 2: a provider in the registry,
    // active profile points at it, request through /v1/chat/completions
    // ends up at the subprocess.
    let dir = tempfile::tempdir().unwrap();
    let cli = install_mock_claude(
        &dir,
        "#!/bin/sh\nprintf 'reply from claude via proxy\\n'\n",
    );
    let provider = ClaudeCliProvider::new(
        "claude-cli",
        Some(&cli),
        Some(Duration::from_secs(5)),
        vec!["claude-sonnet-4-7".into()],
    );
    let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
    providers.insert("claude-cli".to_string(), Arc::new(provider));
    let state = ServerState::new(
        providers,
        ActiveProfile {
            provider: "claude-cli".into(),
            model: "claude-sonnet-4-7".into(),
        },
        HashMap::new(),
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let payload: Value = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .json(&body("claude-sonnet-4-7", "hi via proxy", false))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        payload["choices"][0]["message"]["content"],
        "reply from claude via proxy"
    );
    assert_eq!(payload["choices"][0]["finish_reason"], "stop");
}

#[tokio::test]
async fn proxy_router_serves_claude_via_per_claw_overlay() {
    // Same shape as the test above, but the overlay path. Hermes uses the
    // openai-compat default; openclaw overlays to the Claude CLI.
    let dir = tempfile::tempdir().unwrap();
    let cli = install_mock_claude(
        &dir,
        "#!/bin/sh\nprintf 'overlay reply\\n'\n",
    );
    let claude = ClaudeCliProvider::new(
        "claude-cli",
        Some(&cli),
        Some(Duration::from_secs(5)),
        vec!["claude-sonnet-4-7".into()],
    );
    // The default points at a fake openai-compat upstream that always
    // 404s — we want to be sure the overlay route never touches it.
    let openai = llm_proxy::OpenAiCompatProvider::new(
        "openai-default",
        "http://127.0.0.1:1", // unreachable — would error if hit
        None,
        vec!["any".into()],
    )
    .unwrap();

    let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
    providers.insert("openai-default".into(), Arc::new(openai));
    providers.insert("claude-cli".into(), Arc::new(claude));

    let mut overlays = HashMap::new();
    overlays.insert(
        "openclaw".to_string(),
        ActiveProfile {
            provider: "claude-cli".into(),
            model: "claude-sonnet-4-7".into(),
        },
    );

    let state = ServerState::new(
        providers,
        ActiveProfile {
            provider: "openai-default".into(),
            model: "any".into(),
        },
        overlays,
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let payload: Value = reqwest::Client::new()
        .post(format!("http://{addr}/v1/c/openclaw/chat/completions"))
        .json(&body("claude-sonnet-4-7", "hi", false))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(payload["choices"][0]["message"]["content"], "overlay reply");
}
