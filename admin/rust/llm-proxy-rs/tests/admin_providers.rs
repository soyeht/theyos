//! Integration tests for the `/admin/llm/providers*` and
//! `/admin/llm/audit` endpoints (Slice D part 2).
//!
//! Each test spins up a real axum server backed by a tempdir-rooted
//! file keystore + profile dir so the production code paths
//! (`build_provider_registry`, `ProfileDoc::upsert_provider`, atomic
//! rename, etc.) all execute.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use keystore_rs::{FileKeystore, KeystoreBackend};
use llm_proxy::audit::{AuditLogger, AuditRecord, AuditStatus};
use llm_proxy::profile::{ActiveProfile, CliFlavor, ProfileDoc, ProviderConfig, ProviderKind};
use llm_proxy::provider::{OpenAiCompatProvider, Provider};
use llm_proxy::server::ServerState;

fn fake_provider(id: &str) -> Arc<dyn Provider> {
    Arc::new(
        OpenAiCompatProvider::new(
            id,
            "http://127.0.0.1:1/v1",
            None,
            vec!["model-a".into()],
        )
        .expect("build OpenAiCompatProvider for tests"),
    )
}

/// Build a state with one configured provider + a file-backed keystore.
/// Returns (state, `keystore_handle`) so tests can poke at the keystore
/// directly to assert credential side-effects.
fn fixture(
    profile_dir: &std::path::Path,
    keystore_dir: &std::path::Path,
) -> (ServerState, Arc<dyn KeystoreBackend>) {
    let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
    providers.insert("prov-a".into(), fake_provider("prov-a"));

    let mut doc = ProfileDoc {
        active: Some(ActiveProfile {
            provider: "prov-a".into(),
            model: "model-a".into(),
        }),
        providers: BTreeMap::default(),
    };
    doc.providers.insert(
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
    doc.save_default(profile_dir).expect("seed default.toml");

    let keystore: Arc<dyn KeystoreBackend> =
        Arc::new(FileKeystore::new(keystore_dir, keystore_rs::SERVICE));

    let state = ServerState::with_full_wiring(
        providers,
        ActiveProfile {
            provider: "prov-a".into(),
            model: "model-a".into(),
        },
        HashMap::new(),
        AuditLogger::disabled(),
        Some(profile_dir.to_path_buf()),
        Some(keystore.clone()),
    );
    (state, keystore)
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
async fn list_providers_reports_seeded_entry_with_in_use_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = tempfile::tempdir().unwrap();
    let (state, _ks) = fixture(tmp.path(), ks.path());
    let (base, _h) = spawn(state).await;

    let v: serde_json::Value = reqwest::get(format!("{base}/admin/llm/providers"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = v["providers"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"], "prov-a");
    assert_eq!(entries[0]["kind"], "openai-compat");
    assert_eq!(entries[0]["has_credential"], false);
    assert_eq!(entries[0]["in_use"], true);
}

#[tokio::test]
async fn upsert_provider_writes_credential_and_profile_and_hot_reloads() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = tempfile::tempdir().unwrap();
    let (state, keystore) = fixture(tmp.path(), ks.path());
    let (base, _h) = spawn(state.clone()).await;

    let body = serde_json::json!({
        "id": "prov-b",
        "kind": "openai-compat",
        "base_url": "http://127.0.0.1:2/v1",
        "credential_account": "llm.api_key.prov-b",
        "models": ["model-b"],
        "credential": "sk-test-1234"
    });
    let resp = reqwest::Client::new()
        .post(format!("{base}/admin/llm/providers"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "status={}", resp.status());

    // Keystore got the secret.
    let stored = keystore.get("llm.api_key.prov-b").unwrap();
    assert_eq!(stored, b"sk-test-1234");

    // default.toml got the provider entry.
    let on_disk = std::fs::read_to_string(tmp.path().join("default.toml")).unwrap();
    assert!(on_disk.contains("[providers.prov-b]"), "{on_disk}");
    assert!(on_disk.contains("base_url = \"http://127.0.0.1:2/v1\""), "{on_disk}");

    // Hot-reload: the runtime registry now has prov-b without restart.
    let v: serde_json::Value = reqwest::get(format!("{base}/admin/llm/providers"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = v["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"prov-b"));
}

#[tokio::test]
async fn upsert_provider_with_empty_credential_clears_existing_key() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = tempfile::tempdir().unwrap();
    let (state, keystore) = fixture(tmp.path(), ks.path());
    let (base, _h) = spawn(state).await;
    let client = reqwest::Client::new();

    // First write the credential.
    client
        .post(format!("{base}/admin/llm/providers"))
        .json(&serde_json::json!({
            "id": "prov-c",
            "kind": "openai-compat",
            "base_url": "http://127.0.0.1:3/v1",
            "credential_account": "llm.api_key.prov-c",
            "models": ["model-c"],
            "credential": "initial-secret"
        }))
        .send()
        .await
        .unwrap();
    assert!(keystore.get("llm.api_key.prov-c").is_ok());

    // Then upsert with empty credential — should delete.
    client
        .post(format!("{base}/admin/llm/providers"))
        .json(&serde_json::json!({
            "id": "prov-c",
            "kind": "openai-compat",
            "base_url": "http://127.0.0.1:3/v1",
            "credential_account": "llm.api_key.prov-c",
            "models": ["model-c"],
            "credential": ""
        }))
        .send()
        .await
        .unwrap();
    assert!(matches!(
        keystore.get("llm.api_key.prov-c"),
        Err(keystore_rs::KeystoreError::NotFound { .. })
    ));
}

#[tokio::test]
async fn delete_provider_rejected_when_active_uses_it() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = tempfile::tempdir().unwrap();
    let (state, _) = fixture(tmp.path(), ks.path());
    let (base, _h) = spawn(state).await;

    // prov-a is the seeded active.
    let resp = reqwest::Client::new()
        .delete(format!("{base}/admin/llm/providers/prov-a"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "must refuse delete of in-use provider");
}

#[tokio::test]
async fn delete_provider_succeeds_when_unused() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = tempfile::tempdir().unwrap();
    let (state, _) = fixture(tmp.path(), ks.path());
    let (base, _h) = spawn(state.clone()).await;
    let client = reqwest::Client::new();

    // Add a second provider that isn't referenced by any active.
    client
        .post(format!("{base}/admin/llm/providers"))
        .json(&serde_json::json!({
            "id": "prov-x",
            "kind": "openai-compat",
            "base_url": "http://127.0.0.1:9/v1",
            "credential_account": null,
            "models": ["model-x"],
            "credential": null
        }))
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!("{base}/admin/llm/providers/prov-x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // default.toml no longer has [providers.prov-x]
    let on_disk = std::fs::read_to_string(tmp.path().join("default.toml")).unwrap();
    assert!(!on_disk.contains("[providers.prov-x]"), "{on_disk}");
}

#[tokio::test]
async fn test_provider_returns_latency_and_ok_or_error() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = tempfile::tempdir().unwrap();
    let (state, _) = fixture(tmp.path(), ks.path());
    let (base, _h) = spawn(state).await;

    // prov-a points at a non-listening port (127.0.0.1:1), so the probe
    // will fail. We assert the response shape rather than a specific
    // success/failure mode — what matters is that the endpoint is well-
    // formed and reports both ok=bool and latency_ms.
    let resp = reqwest::Client::new()
        .post(format!("{base}/admin/llm/providers/prov-a/test"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert!(v["ok"].is_boolean());
    assert!(v["latency_ms"].is_number());
    // prov-a fails, so error should be set.
    assert_eq!(v["ok"], false);
    assert!(v["error"].is_string(), "expected error string on failure");
}

#[tokio::test]
async fn audit_endpoint_returns_records_newest_first() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = tempfile::tempdir().unwrap();
    let audit_path = tmp.path().join("audit.log");
    let audit = AuditLogger::open(Some(&audit_path)).unwrap();

    // Write three records with slightly different timestamps.
    for (i, model) in ["m-1", "m-2", "m-3"].iter().enumerate() {
        audit.write(&AuditRecord {
            ts: format!("2026-05-18T00:00:0{i}.000Z"),
            provider: "prov-a".into(),
            claw_type: None,
            model: (*model).into(),
            stream: false,
            status: AuditStatus::Ok,
            error_kind: None,
            latency_ms: 100 + i as u64,
            input_tokens: None,
            output_tokens: None,
        });
    }

    let state = ServerState::with_full_wiring(
        HashMap::new(),
        ActiveProfile {
            provider: "prov-a".into(),
            model: "m-1".into(),
        },
        HashMap::new(),
        audit,
        Some(tmp.path().to_path_buf()),
        Some(Arc::new(FileKeystore::new(ks.path(), keystore_rs::SERVICE))),
    );
    let (base, _h) = spawn(state).await;

    let v: serde_json::Value = reqwest::get(format!("{base}/admin/llm/audit?limit=10"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let recs = v["records"].as_array().unwrap();
    assert_eq!(recs.len(), 3);
    // Newest first: m-3 has ts ending in 02, m-1 in 00.
    assert_eq!(recs[0]["model"], "m-3");
    assert_eq!(recs[1]["model"], "m-2");
    assert_eq!(recs[2]["model"], "m-1");
}

#[tokio::test]
async fn audit_endpoint_filters_by_before_cutoff() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = tempfile::tempdir().unwrap();
    let audit_path = tmp.path().join("audit.log");
    let audit = AuditLogger::open(Some(&audit_path)).unwrap();
    for (i, model) in ["m-1", "m-2", "m-3"].iter().enumerate() {
        audit.write(&AuditRecord {
            ts: format!("2026-05-18T00:00:0{i}.000Z"),
            provider: "prov-a".into(),
            claw_type: None,
            model: (*model).into(),
            stream: false,
            status: AuditStatus::Ok,
            error_kind: None,
            latency_ms: 100,
            input_tokens: None,
            output_tokens: None,
        });
    }
    let state = ServerState::with_full_wiring(
        HashMap::new(),
        ActiveProfile {
            provider: "prov-a".into(),
            model: "m-1".into(),
        },
        HashMap::new(),
        audit,
        Some(tmp.path().to_path_buf()),
        Some(Arc::new(FileKeystore::new(ks.path(), keystore_rs::SERVICE))),
    );
    let (base, _h) = spawn(state).await;

    let v: serde_json::Value = reqwest::get(format!(
        "{base}/admin/llm/audit?limit=10&before=2026-05-18T00:00:02.000Z"
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let recs = v["records"].as_array().unwrap();
    // Strictly less than the cutoff: m-2 (00:00:01) and m-1 (00:00:00).
    assert_eq!(recs.len(), 2);
    let models: Vec<&str> = recs
        .iter()
        .map(|r| r["model"].as_str().unwrap())
        .collect();
    assert_eq!(models, vec!["m-2", "m-1"]);
}

/// Write-only contract: `GET /admin/llm/providers` must never return the
/// stored credential value. The response should expose presence (a
/// boolean) and the account label, but the secret itself stays in the
/// keystore. This is a regression guard — any future field that ends
/// up serialising the secret will trip this test.
///
/// Why this matters: the Apple-grade UX promise is "once stored, the
/// key is write-only from the admin surface". A reveal endpoint —
/// even an accidental one introduced by a future Serialize derive —
/// turns a cookie-theft incident into a credential-exfil incident.
#[tokio::test]
async fn list_providers_never_returns_credential_value() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = tempfile::tempdir().unwrap();
    let (state, _) = fixture(tmp.path(), ks.path());
    let (base, _h) = spawn(state.clone()).await;
    let client = reqwest::Client::new();

    // Plant a secret value via the upsert path — same path the admin
    // UI uses.
    let secret = "sk-must-never-leak-9c2e8b4a";
    client
        .post(format!("{base}/admin/llm/providers"))
        .json(&serde_json::json!({
            "id": "prov-leak-canary",
            "kind": "openai-compat",
            "base_url": "http://127.0.0.1:9/v1",
            "credential_account": "llm.api_key.prov-leak-canary",
            "models": ["model-x"],
            "credential": secret
        }))
        .send()
        .await
        .unwrap();

    // List endpoint — full response, parsed as raw text first so we
    // catch the secret regardless of where it lands in the JSON tree
    // (a future bug could surface it as a sibling field, a nested
    // object, an error message, anything).
    let body = reqwest::get(format!("{base}/admin/llm/providers"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !body.contains(secret),
        "secret value leaked in list response: {body}"
    );

    // Test endpoint — same canary check. The live probe receives the
    // credential server-side; the response must not echo it back.
    let probe = client
        .post(format!("{base}/admin/llm/providers/prov-leak-canary/test"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !probe.contains(secret),
        "secret value leaked in test response: {probe}"
    );

    // And as a structural assertion: `has_credential` exists, the
    // value field doesn't. Field names we expect to see; any future
    // serialisation that adds a `credential`/`api_key`/`secret` key
    // to a ProviderSummary will fail this list.
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let canary = parsed["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "prov-leak-canary")
        .expect("canary in providers list");
    let keys: Vec<&str> = canary.as_object().unwrap().keys().map(String::as_str).collect();
    assert!(keys.contains(&"has_credential"), "missing has_credential boolean");
    for forbidden in ["credential", "api_key", "secret", "password", "token"] {
        assert!(
            !keys.contains(&forbidden),
            "ProviderSummary must not expose field {forbidden:?} (got keys: {keys:?})"
        );
    }
}

/// Defensive: there is no `GET .../credential` endpoint anywhere on
/// the admin surface. If a future router edit accidentally wires one up,
/// this test fails before the change reaches the field.
#[tokio::test]
async fn no_credential_get_endpoint_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = tempfile::tempdir().unwrap();
    let (state, _) = fixture(tmp.path(), ks.path());
    let (base, _h) = spawn(state).await;

    for path in [
        "/admin/llm/providers/prov-a/credential",
        "/admin/llm/providers/prov-a/secret",
        "/admin/llm/providers/prov-a/api_key",
        "/admin/llm/credentials",
    ] {
        let resp = reqwest::get(format!("{base}{path}"))
            .await
            .expect("request");
        assert!(
            resp.status() == 404 || resp.status() == 405,
            "{path} must 404 / 405; got {} — the admin surface must not expose a credential read",
            resp.status(),
        );
    }
}
