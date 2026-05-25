//! End-to-end audit-log tests: the proxy must record a JSONL entry per
//! request flowing through `/v1/chat/completions`. These verify that:
//!
//! - successful requests produce a record with `status=ok` and a real
//!   latency value;
//! - upstream failures produce a record with `status=error` and the
//!   matching `error_kind`;
//! - the `claw_type` field surfaces per-claw routing in the log;
//! - the disabled-logger path doesn't crash and doesn't write anywhere.

use std::collections::HashMap;
use std::sync::Arc;

use llm_proxy::audit::{AuditLogger, AuditRecord, AuditStatus};
use llm_proxy::{ActiveProfile, OpenAiCompatProvider, Provider, ServerState, router};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn spawn_proxy(upstream_url: String, audit: AuditLogger) -> String {
    let provider =
        OpenAiCompatProvider::new("ollama-test", upstream_url, None, vec!["llama3.1".into()])
            .unwrap();
    let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
    providers.insert("ollama-test".into(), Arc::new(provider));
    let state = ServerState::with_audit(
        providers,
        ActiveProfile {
            provider: "ollama-test".into(),
            model: "llama3.1".into(),
        },
        HashMap::new(),
        audit,
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn read_records(path: &std::path::Path) -> Vec<AuditRecord> {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for line in raw.lines() {
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditRecord>(line) {
            Ok(rec) => out.push(rec),
            Err(e) => {
                let msg = format!("malformed audit line: {line}\nerror: {e}");
                panic!("{msg}");
            }
        }
    }
    out
}

#[tokio::test]
async fn ok_response_writes_one_record_with_status_ok_and_real_latency() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id": "x", "choices": []}))
                // Force some latency so we can assert > 0.
                .set_delay(std::time::Duration::from_millis(40)),
        )
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = AuditLogger::open(Some(&audit_path)).unwrap();
    let proxy = spawn_proxy(format!("{}/v1", upstream.uri()), audit).await;

    let _: Value = reqwest::Client::new()
        .post(format!("{proxy}/v1/c/openclaw/chat/completions"))
        .json(&json!({
            "model": "llama3.1",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": false,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let records = read_records(&audit_path);
    assert_eq!(records.len(), 1, "expected exactly one record");
    let r = &records[0];
    assert_eq!(r.provider, "ollama-test");
    assert_eq!(r.claw_type.as_deref(), Some("openclaw"));
    assert_eq!(r.model, "llama3.1");
    assert_eq!(r.status, AuditStatus::Ok);
    assert!(r.error_kind.is_none());
    assert!(!r.stream);
    assert!(
        r.latency_ms >= 40 && r.latency_ms < 10_000,
        "latency_ms looks fake: {}",
        r.latency_ms
    );
}

#[tokio::test]
async fn upstream_error_writes_record_with_status_error_and_kind() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(503).set_body_string("oops"))
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = AuditLogger::open(Some(&audit_path)).unwrap();
    let proxy = spawn_proxy(format!("{}/v1", upstream.uri()), audit).await;

    let status = reqwest::Client::new()
        .post(format!("{proxy}/v1/chat/completions"))
        .json(&json!({
            "model": "llama3.1",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .await
        .unwrap()
        .status();
    assert!(status.is_server_error(), "expected 5xx, got {status}");

    let records = read_records(&audit_path);
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.provider, "ollama-test");
    assert_eq!(r.claw_type, None, "default route → no claw_type");
    assert_eq!(r.status, AuditStatus::Error);
    assert_eq!(r.error_kind.as_deref(), Some("proxy.upstream"));
}

#[tokio::test]
async fn streaming_request_is_audited_with_stream_true() {
    let upstream = MockServer::start().await;
    let sse =
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n";
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = AuditLogger::open(Some(&audit_path)).unwrap();
    let proxy = spawn_proxy(format!("{}/v1", upstream.uri()), audit).await;

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
    // Drain the body so the proxy fully completes the request before we
    // check the audit log.
    let _ = response.text().await.unwrap();

    let records = read_records(&audit_path);
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert!(r.stream, "stream flag must round-trip into the audit log");
    assert_eq!(r.status, AuditStatus::Ok);
}

#[tokio::test]
async fn disabled_audit_logger_writes_no_file_and_does_not_crash() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "x"})))
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("nope.jsonl");
    // Explicitly disabled — pass AuditLogger::disabled(), NOT open().
    let audit = AuditLogger::disabled();
    let proxy = spawn_proxy(format!("{}/v1", upstream.uri()), audit).await;

    let _ = reqwest::Client::new()
        .post(format!("{proxy}/v1/chat/completions"))
        .json(&json!({"model": "x", "messages": []}))
        .send()
        .await
        .unwrap();

    assert!(
        !audit_path.exists(),
        "disabled logger must not create the file"
    );
}

#[tokio::test]
async fn multiple_requests_append_in_order() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "x"})))
        .mount(&upstream)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("multi.jsonl");
    let audit = AuditLogger::open(Some(&audit_path)).unwrap();
    let proxy = spawn_proxy(format!("{}/v1", upstream.uri()), audit).await;

    let client = reqwest::Client::new();
    for claw in ["openclaw", "hermes-agent", "openclaw"] {
        let _ = client
            .post(format!("{proxy}/v1/c/{claw}/chat/completions"))
            .json(&json!({"model": "m", "messages": []}))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
    }

    let records = read_records(&audit_path);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].claw_type.as_deref(), Some("openclaw"));
    assert_eq!(records[1].claw_type.as_deref(), Some("hermes-agent"));
    assert_eq!(records[2].claw_type.as_deref(), Some("openclaw"));
    // Timestamps are monotonically non-decreasing (millisecond resolution
    // could collide but never go backwards).
    let t0 = &records[0].ts;
    let t1 = &records[1].ts;
    let t2 = &records[2].ts;
    assert!(
        t0 <= t1 && t1 <= t2,
        "timestamps not monotonic: {t0} {t1} {t2}"
    );
}
