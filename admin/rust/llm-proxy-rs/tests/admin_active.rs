//! Integration tests for the `/admin/llm/active*` endpoints.
//!
//! Covers Slice D part 1 of the v1 ship-readiness plan:
//! - GET  /admin/llm/active            → reads current default + per-claw
//! - PUT  /admin/llm/active            → swaps default, persists to disk
//! - PUT  /`admin/llm/active/:claw_type` → installs/updates overlay file
//! - DELETE /`admin/llm/active/:claw_type` → removes overlay file
//!
//! Each test starts a real axum server on a random port so the wire
//! contract (URL paths, JSON shapes, status codes) is exercised the way
//! `server-rs` will see it.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use llm_proxy::audit::AuditLogger;
use llm_proxy::profile::{ActiveProfile, CliFlavor, ProfileDoc, ProviderConfig, ProviderKind};
use llm_proxy::provider::{OpenAiCompatProvider, Provider};
use llm_proxy::server::ServerState;

fn fake_provider(id: &str) -> Arc<dyn Provider> {
    Arc::new(
        OpenAiCompatProvider::new(
            id,
            "http://127.0.0.1:1/v1",
            None,
            vec!["model-a".into(), "model-b".into()],
        )
        .expect("build OpenAiCompatProvider for tests"),
    )
}

/// Build a state with two providers (`prov-a`, `prov-b`) and active=prov-a
/// + model-a. Profile dir backed by the supplied temp path so writes land
/// on disk and we can verify them.
fn fixture_state(profile_dir: &std::path::Path) -> ServerState {
    let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
    providers.insert("prov-a".into(), fake_provider("prov-a"));
    providers.insert("prov-b".into(), fake_provider("prov-b"));

    // Seed default.toml so update_default_active has a doc to load + patch.
    let doc = ProfileDoc {
        active: Some(ActiveProfile {
            provider: "prov-a".into(),
            model: "model-a".into(),
        }),
        providers: {
            let mut m = BTreeMap::new();
            m.insert(
                "prov-a".into(),
                ProviderConfig {
                    kind: ProviderKind::OpenaiCompat,
                    base_url: "http://127.0.0.1:1/v1".into(),
                    credential_account: None,
                    models: vec!["model-a".into()],
                    cli_binary_path: None,
                    cli_timeout_secs: None,
                    cli_flavor: CliFlavor::default(),
                },
            );
            m.insert(
                "prov-b".into(),
                ProviderConfig {
                    kind: ProviderKind::OpenaiCompat,
                    base_url: "http://127.0.0.1:2/v1".into(),
                    credential_account: None,
                    models: vec!["model-b".into()],
                    cli_binary_path: None,
                    cli_timeout_secs: None,
                    cli_flavor: CliFlavor::default(),
                },
            );
            m
        },
    };
    doc.save_default(profile_dir).expect("save default.toml");

    ServerState::with_audit_and_profile_dir(
        providers,
        ActiveProfile {
            provider: "prov-a".into(),
            model: "model-a".into(),
        },
        HashMap::new(),
        AuditLogger::disabled(),
        Some(profile_dir.to_path_buf()),
    )
}

async fn spawn(state: ServerState) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = llm_proxy::server::router(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn get_active_returns_default_and_empty_per_claw_on_fresh_state() {
    let tmp = tempfile::tempdir().unwrap();
    let state = fixture_state(tmp.path());
    let (base, _h) = spawn(state).await;

    let v: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/admin/llm/active"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(v["default"]["provider"], "prov-a");
    assert_eq!(v["default"]["model"], "model-a");
    assert!(v["per_claw"].as_object().unwrap().is_empty());
}

#[tokio::test]
async fn put_active_swaps_default_and_persists_to_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let state = fixture_state(tmp.path());
    let (base, _h) = spawn(state.clone()).await;

    let body = serde_json::json!({"provider": "prov-b", "model": "model-b"});
    let resp = reqwest::Client::new()
        .put(format!("{base}/admin/llm/active"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "status={}", resp.status());

    // Hot-reload: state.default_active reflects the new value without restart.
    assert_eq!(state.default_active().provider, "prov-b");
    assert_eq!(state.default_active().model, "model-b");

    // Disk persistence: default.toml on disk has the new active.
    let on_disk = std::fs::read_to_string(tmp.path().join("default.toml")).unwrap();
    assert!(
        on_disk.contains("provider = \"prov-b\""),
        "default.toml should hold the new provider:\n{on_disk}"
    );
    assert!(on_disk.contains("model = \"model-b\""), "{on_disk}");
}

#[tokio::test]
async fn put_active_rejects_unknown_provider_with_422() {
    // 422 (Unprocessable Entity) reflects "client supplied a value the
    // server cannot use" — distinct from 503 (the server's own profile
    // is inconsistent and no request can be routed). The chat-completions
    // path retains 503 for the latter; the admin mutator gets 422 here.
    let tmp = tempfile::tempdir().unwrap();
    let state = fixture_state(tmp.path());
    let (base, _h) = spawn(state).await;

    let body = serde_json::json!({"provider": "ghost", "model": "model-a"});
    let resp = reqwest::Client::new()
        .put(format!("{base}/admin/llm/active"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["kind"], "proxy.invalid_provider");
}

#[tokio::test]
async fn put_active_per_claw_creates_overlay_file_and_in_memory_state() {
    let tmp = tempfile::tempdir().unwrap();
    let state = fixture_state(tmp.path());
    let (base, _h) = spawn(state).await;

    let body = serde_json::json!({"provider": "prov-b", "model": "model-b"});
    let resp = reqwest::Client::new()
        .put(format!("{base}/admin/llm/active/openclaw"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // GET reflects the per-claw entry.
    let v: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/admin/llm/active"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["per_claw"]["openclaw"]["provider"], "prov-b");
    assert_eq!(v["per_claw"]["openclaw"]["model"], "model-b");

    // Overlay file present on disk.
    let overlay = std::fs::read_to_string(tmp.path().join("openclaw.toml")).unwrap();
    assert!(overlay.contains("prov-b"), "{overlay}");
}

#[tokio::test]
async fn put_active_per_claw_rejects_path_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let state = fixture_state(tmp.path());
    let (base, _h) = spawn(state).await;

    let body = serde_json::json!({"provider": "prov-a", "model": "model-a"});
    let resp = reqwest::Client::new()
        .put(format!("{base}/admin/llm/active/..%2Fetc"))
        .json(&body)
        .send()
        .await
        .unwrap();
    // axum normalises the URL; either we get 400 from our validator or
    // 404 from the route. What we MUST NOT see is 200 + a file outside
    // the profile dir.
    assert!(
        !resp.status().is_success(),
        "path-traversal must be rejected, got {}",
        resp.status()
    );
    let outside = tmp.path().parent().unwrap().join("etc.toml");
    assert!(!outside.exists(), "no overlay file was written outside dir");
}

#[tokio::test]
async fn delete_active_claw_removes_overlay_and_in_memory_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let state = fixture_state(tmp.path());
    let (base, _h) = spawn(state).await;
    let client = reqwest::Client::new();

    // Install overlay first.
    client
        .put(format!("{base}/admin/llm/active/hermes-agent"))
        .json(&serde_json::json!({"provider": "prov-b", "model": "model-b"}))
        .send()
        .await
        .unwrap();
    assert!(tmp.path().join("hermes-agent.toml").exists());

    // Delete it.
    let resp = client
        .delete(format!("{base}/admin/llm/active/hermes-agent"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    assert!(!tmp.path().join("hermes-agent.toml").exists());

    let v: serde_json::Value = client
        .get(format!("{base}/admin/llm/active"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(v["per_claw"].as_object().unwrap().is_empty());
}
