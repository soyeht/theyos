//! Integration tests for [`AnthropicApiProvider`].
//!
//! Verifies the HTTP behaviours the unit tests in
//! `translate::anthropic::tests` can't cover:
//!
//! - The provider POSTs to `/v1/messages` (NOT `/v1/chat/completions`).
//! - `x-api-key` and `anthropic-version` headers are present.
//! - Upstream 401 surfaces as `ProxyError::Upstream`.
//! - Streaming: an Anthropic SSE event stream from the mock is
//!   re-emitted as `OpenAI` `chat.completion.chunk` frames in the right
//!   shape and order.

use llm_proxy::provider::{AnthropicApiProvider, ChatResponse, Provider};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn req(model: &str, content: &str, stream: bool) -> Value {
    json!({
        "model": model,
        "stream": stream,
        "messages": [{"role": "user", "content": content}],
    })
}

#[tokio::test]
async fn posts_to_v1_messages_with_anthropic_version_and_x_api_key_headers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "sk-ant-test"))
        .and(header("anthropic-version", "2023-06-01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_unit_test",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4-7",
            "content": [{"type": "text", "text": "ok"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "output_tokens": 1}
        })))
        .mount(&server)
        .await;

    let provider = AnthropicApiProvider::new(
        "anthropic",
        Some(server.uri()),
        "sk-ant-test".into(),
        vec!["claude-opus-4-7".into()],
    )
    .unwrap();

    let response = provider
        .chat(&req("claude-opus-4-7", "hi", false), false)
        .await
        .unwrap();
    let ChatResponse::Json(bytes) = response else {
        panic!("expected JSON");
    };
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(body["choices"][0]["message"]["content"], "ok");
    // id translated from msg_ → chatcmpl-
    assert!(
        body["id"].as_str().unwrap().starts_with("chatcmpl-"),
        "id = {}",
        body["id"]
    );
}

#[tokio::test]
async fn translates_request_body_to_anthropic_shape_before_send() {
    // Mock asserts on the body — the assertion fails if the proxy sent
    // OpenAI-shape (system in messages, no max_tokens, etc.).
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(wiremock::matchers::body_partial_json(json!({
            "model": "claude-opus-4-7",
            "system": "be terse",
            "max_tokens": 4096,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_x", "model": "claude-opus-4-7",
            "content": [{"type": "text", "text": "ok"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        })))
        .mount(&server)
        .await;

    let provider = AnthropicApiProvider::new(
        "anthropic",
        Some(server.uri()),
        "sk-ant-test".into(),
        vec!["claude-opus-4-7".into()],
    )
    .unwrap();

    // OpenAI shape — system inside messages, no max_tokens.
    let body = json!({
        "model": "claude-opus-4-7",
        "messages": [
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "hi"}
        ],
    });
    let response = provider.chat(&body, false).await.unwrap();
    assert!(matches!(response, ChatResponse::Json(_)));
}

#[tokio::test]
async fn upstream_401_surfaces_as_typed_upstream_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "type": "error",
            "error": {"type": "authentication_error", "message": "invalid x-api-key"}
        })))
        .mount(&server)
        .await;

    let provider = AnthropicApiProvider::new(
        "anthropic",
        Some(server.uri()),
        "wrong-key".into(),
        vec!["m".into()],
    )
    .unwrap();

    let result = provider.chat(&req("m", "hi", false), false).await;
    let Err(err) = result else {
        panic!("expected Err")
    };
    match err {
        llm_proxy::ProxyError::Upstream { provider, message } => {
            assert_eq!(provider, "anthropic");
            assert!(message.contains("401"), "missing status: {message}");
            assert!(
                message.contains("invalid x-api-key"),
                "missing upstream body: {message}"
            );
        }
        other => panic!("expected Upstream, got {other:?}"),
    }
}

#[tokio::test]
async fn translates_streaming_response_into_openai_chunks() {
    let server = MockServer::start().await;
    // A realistic Anthropic SSE response. Each event carries an
    // `event:` line plus a `data:` line; the translator only consumes
    // the `data:` portion.
    let sse = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-opus-4-7\"}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello \"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"world\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;

    let provider = AnthropicApiProvider::new(
        "anthropic",
        Some(server.uri()),
        "sk-ant-test".into(),
        vec!["claude-opus-4-7".into()],
    )
    .unwrap();

    let response = provider
        .chat(&req("claude-opus-4-7", "hi", true), true)
        .await
        .unwrap();
    let ChatResponse::Stream(mut stream) = response else {
        panic!("expected stream");
    };
    use futures_util::StreamExt;
    let mut frames: Vec<String> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.unwrap();
        frames.push(String::from_utf8_lossy(&bytes).into_owned());
    }
    // Joined view because the upstream chunking is implementation-defined;
    // verify substrings rather than exact frame counts.
    let joined: String = frames.join("");
    assert!(
        joined.contains("\"role\":\"assistant\""),
        "missing role chunk: {joined}"
    );
    assert!(
        joined.contains("\"content\":\"hello \""),
        "missing first delta: {joined}"
    );
    assert!(
        joined.contains("\"content\":\"world\""),
        "missing second delta: {joined}"
    );
    assert!(
        joined.contains("\"finish_reason\":\"stop\""),
        "missing stop: {joined}"
    );
    assert!(
        joined.ends_with("data: [DONE]\n\n"),
        "missing trailer: {joined}"
    );
}

#[tokio::test]
async fn translates_streaming_tool_use_response_into_openai_tool_calls_deltas() {
    let server = MockServer::start().await;
    let sse = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_2\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-opus-4-7\"}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_xx\",\"name\":\"lookup\",\"input\":{}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"q\\\":\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"weather\\\"}\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":4}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;

    let provider = AnthropicApiProvider::new(
        "anthropic",
        Some(server.uri()),
        "sk-ant-test".into(),
        vec!["claude-opus-4-7".into()],
    )
    .unwrap();

    let response = provider
        .chat(&req("claude-opus-4-7", "use a tool", true), true)
        .await
        .unwrap();
    let ChatResponse::Stream(mut stream) = response else {
        panic!("expected stream");
    };
    use futures_util::StreamExt;
    let mut joined = String::new();
    while let Some(chunk) = stream.next().await {
        joined.push_str(std::str::from_utf8(&chunk.unwrap()).unwrap());
    }
    // The tool_call open frame carries id + name; subsequent deltas only
    // carry function.arguments fragments.
    assert!(
        joined.contains("\"id\":\"toolu_xx\""),
        "missing tool id: {joined}"
    );
    assert!(
        joined.contains("\"name\":\"lookup\""),
        "missing tool name: {joined}"
    );
    assert!(
        joined.contains("\"arguments\":\"{\\\"q\\\":\""),
        "missing first args delta: {joined}"
    );
    assert!(
        joined.contains("\"arguments\":\"\\\"weather\\\"}\""),
        "missing second args delta: {joined}"
    );
    assert!(
        joined.contains("\"finish_reason\":\"tool_calls\""),
        "missing tool_calls finish reason: {joined}"
    );
    assert!(joined.ends_with("data: [DONE]\n\n"));
}

#[tokio::test]
async fn streaming_translator_recovers_when_upstream_cuts_off_mid_response() {
    let server = MockServer::start().await;
    // Upstream sends a couple of deltas then ends WITHOUT message_stop.
    let sse = concat!(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"truncated\"}}\n\n",
    );
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;

    let provider = AnthropicApiProvider::new(
        "anthropic",
        Some(server.uri()),
        "sk-ant-test".into(),
        vec!["m".into()],
    )
    .unwrap();
    let response = provider.chat(&req("m", "hi", true), true).await.unwrap();
    let ChatResponse::Stream(mut stream) = response else {
        panic!("expected stream");
    };
    use futures_util::StreamExt;
    let mut joined = String::new();
    while let Some(chunk) = stream.next().await {
        joined.push_str(std::str::from_utf8(&chunk.unwrap()).unwrap());
    }
    // Even on an abrupt upstream cutoff, downstream clients get the
    // synthetic terminal chunk + [DONE] so they don't hang.
    assert!(joined.contains("\"content\":\"truncated\""));
    assert!(
        joined.contains("\"finish_reason\":\"stop\""),
        "translator must synthesise a stop frame on cutoff: {joined}"
    );
    assert!(joined.ends_with("data: [DONE]\n\n"));
}
