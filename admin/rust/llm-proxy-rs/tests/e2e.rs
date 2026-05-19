//! End-to-end test for Slice 1: HTTP client → axum proxy → mock upstream.
//!
//! Verifies the full path that a real claw would exercise once the reverse
//! SSH tunnel is wired up: a tokio `TcpListener` bound to a random port,
//! `axum::serve`, and a real reqwest client making both streaming and
//! non-streaming requests through the proxy.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use llm_proxy::profile::{ActiveProfile, CliFlavor, ProfileDoc, ProviderConfig, ProviderKind};
use llm_proxy::{OpenAiCompatProvider, Provider, ServerState, router};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn spawn_proxy_with_provider(
    upstream_url: String,
) -> (tokio::task::JoinHandle<()>, String) {
    spawn_proxy_with_overrides(upstream_url, HashMap::new()).await
}

async fn spawn_proxy_with_overrides(
    upstream_url: String,
    per_claw_active: HashMap<String, ActiveProfile>,
) -> (tokio::task::JoinHandle<()>, String) {
    let provider = OpenAiCompatProvider::new(
        "ollama-test",
        upstream_url,
        None,
        vec!["llama3.1".into()],
    )
    .unwrap();
    let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
    providers.insert("ollama-test".to_string(), Arc::new(provider));
    let default_active = ActiveProfile {
        provider: "ollama-test".into(),
        model: "llama3.1".into(),
    };
    let state = ServerState::new(providers, default_active, per_claw_active);
    let app = router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (handle, format!("http://{addr}"))
}

#[tokio::test]
async fn health_endpoint_reports_active_provider() {
    let upstream = MockServer::start().await;
    let (_handle, proxy) = spawn_proxy_with_provider(format!("{}/v1", upstream.uri())).await;

    let client = reqwest::Client::new();
    let body: serde_json::Value = client
        .get(format!("{proxy}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["default_provider"], "ollama-test");
    assert_eq!(body["default_model"], "llama3.1");
    assert!(body["per_claw_overrides"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn models_endpoint_lists_provider_models() {
    let upstream = MockServer::start().await;
    let (_handle, proxy) = spawn_proxy_with_provider(format!("{}/v1", upstream.uri())).await;

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy}/v1/models"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["object"], "list");
    assert_eq!(body["data"][0]["id"], "llama3.1");
    assert_eq!(body["data"][0]["object"], "model");
}

#[tokio::test]
async fn non_streaming_chat_completes() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-e2e",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "five words"},
                "finish_reason": "stop",
            }],
        })))
        .mount(&upstream)
        .await;
    let (_handle, proxy) = spawn_proxy_with_provider(format!("{}/v1", upstream.uri())).await;

    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("{proxy}/v1/chat/completions"))
        .json(&json!({
            "model": "llama3.1",
            "messages": [{"role": "user", "content": "say 5 words"}],
            "stream": false,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["id"], "chatcmpl-e2e");
    assert_eq!(body["choices"][0]["message"]["content"], "five words");
}

#[tokio::test]
async fn streaming_chat_yields_sse_chunks() {
    let upstream = MockServer::start().await;
    let sse_body =
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n";
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse_body),
        )
        .mount(&upstream)
        .await;
    let (_handle, proxy) = spawn_proxy_with_provider(format!("{}/v1", upstream.uri())).await;

    let response = reqwest::Client::new()
        .post(format!("{proxy}/v1/chat/completions"))
        .json(&json!({
            "model": "llama3.1",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
        }))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or("")),
        Some("text/event-stream"),
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("data: {"), "missing chunk: {body}");
    assert!(body.contains("[DONE]"), "missing terminator: {body}");
}

#[tokio::test]
async fn per_claw_route_falls_back_to_default_when_no_overlay() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-default-fallback",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }],
        })))
        .mount(&upstream)
        .await;
    let (_handle, proxy) = spawn_proxy_with_provider(format!("{}/v1", upstream.uri())).await;

    // Per-claw route with no matching overlay → falls back to default.
    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("{proxy}/v1/c/openclaw/chat/completions"))
        .json(&json!({"model": "any", "messages": [], "stream": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["id"], "chatcmpl-default-fallback");
}

#[tokio::test]
async fn per_claw_route_uses_overlay_provider_when_present() {
    let default_upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-from-default-upstream",
        })))
        .mount(&default_upstream)
        .await;

    let overlay_upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-from-overlay-upstream",
        })))
        .mount(&overlay_upstream)
        .await;

    // Two providers in the registry; openclaw is overridden to the second.
    let default_provider = OpenAiCompatProvider::new(
        "default-provider",
        format!("{}/v1", default_upstream.uri()),
        None,
        vec!["m".into()],
    )
    .unwrap();
    let overlay_provider = OpenAiCompatProvider::new(
        "overlay-provider",
        format!("{}/v1", overlay_upstream.uri()),
        None,
        vec!["m".into()],
    )
    .unwrap();
    let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
    providers.insert("default-provider".into(), Arc::new(default_provider));
    providers.insert("overlay-provider".into(), Arc::new(overlay_provider));

    let mut per_claw = HashMap::new();
    per_claw.insert(
        "openclaw".to_string(),
        ActiveProfile {
            provider: "overlay-provider".into(),
            model: "m".into(),
        },
    );

    let state = ServerState::new(
        providers,
        ActiveProfile {
            provider: "default-provider".into(),
            model: "m".into(),
        },
        per_claw,
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let proxy = format!("http://{addr}");

    // Hit default route → goes to default upstream.
    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("{proxy}/v1/chat/completions"))
        .json(&json!({"model": "m", "messages": []}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["id"], "chatcmpl-from-default-upstream");

    // Hit openclaw per-claw route → overlay upstream.
    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("{proxy}/v1/c/openclaw/chat/completions"))
        .json(&json!({"model": "m", "messages": []}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["id"], "chatcmpl-from-overlay-upstream");

    // Hit hermes per-claw route (no overlay) → still default.
    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("{proxy}/v1/c/hermes-agent/chat/completions"))
        .json(&json!({"model": "m", "messages": []}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["id"], "chatcmpl-from-default-upstream");

    // Health surfaces the override.
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{proxy}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["default_provider"], "default-provider");
    let overrides = body["per_claw_overrides"].as_array().unwrap();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0]["claw_type"], "openclaw");
    assert_eq!(overrides[0]["provider"], "overlay-provider");
    let _ = spawn_proxy_with_overrides; // suppress unused warning when this test runs alone
}

#[tokio::test]
async fn profile_round_trip_via_disk() {
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let mut providers = BTreeMap::new();
    providers.insert(
        "ollama".to_string(),
        ProviderConfig {
            kind: ProviderKind::OpenaiCompat,
            base_url: "http://127.0.0.1:11434/v1".into(),
            credential_account: None,
            models: vec!["llama3.1".into()],
            cli_binary_path: None,
            cli_timeout_secs: None,
        cli_flavor: CliFlavor::default(),
        },
    );
    let profile = ProfileDoc {
        active: Some(ActiveProfile {
            provider: "ollama".into(),
            model: "llama3.1".into(),
        }),
        providers,
    };
    profile.save_default(dir.path()).unwrap();

    let reloaded = ProfileDoc::load_default(dir.path()).unwrap();
    let (id, cfg, model) = reloaded.active_provider().unwrap();
    assert_eq!(id, "ollama");
    assert_eq!(model, "llama3.1");
    assert_eq!(cfg.kind, ProviderKind::OpenaiCompat);
    assert_eq!(cfg.models, vec!["llama3.1".to_string()]);
}
