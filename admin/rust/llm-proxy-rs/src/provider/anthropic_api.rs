//! Anthropic `/v1/messages` provider with OpenAI↔Anthropic translation.
//!
//! The provider does three things:
//!
//! 1. **Auth**: injects `x-api-key: <key>` and
//!    `anthropic-version: 2023-06-01` on every request. The key is read
//!    once at construction time (from the keystore by `lib::lookup_credential`)
//!    and held in memory for the process lifetime.
//! 2. **Translation**: pure functions in [`crate::translate::anthropic`]
//!    convert the OpenAI request body to Anthropic shape on the way in,
//!    and the Anthropic response (or SSE stream) to OpenAI shape on the
//!    way out. All translation is tested in isolation in that module.
//! 3. **Streaming**: uses the stateful
//!    [`crate::translate::anthropic::SseTranslator`] to re-emit Anthropic
//!    event-stream payloads as OpenAI `chat.completion.chunk` SSE frames.
//!
//! Anthropic's CORS-friendly REST docs:
//! <https://docs.claude.com/api/messages>

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt, TryStreamExt};
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde_json::Value;

use crate::error::ProxyError;
use crate::provider::{ChatResponse, ModelInfo, Provider};
use crate::translate::anthropic::{
    ANTHROPIC_VERSION, SseTranslator, from_anthropic_response, to_anthropic_request,
};

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default base URL for the Anthropic Messages API. The path
/// `/v1/messages` is appended at request time.
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

pub struct AnthropicApiProvider {
    id: String,
    base_url: String,
    http: Client,
    api_key: String,
    models: Vec<ModelInfo>,
}

impl AnthropicApiProvider {
    /// Build a provider. `base_url` defaults to
    /// `https://api.anthropic.com` if `None` or empty — distinct
    /// upstreams (e.g. Anthropic-compatible proxies) override it.
    ///
    /// `api_key` is required; an Anthropic request without `x-api-key`
    /// returns 401 immediately, so we fail-fast here rather than wait
    /// for the first request.
    pub fn new(
        id: impl Into<String>,
        base_url: Option<impl Into<String>>,
        api_key: String,
        models: Vec<String>,
    ) -> Result<Self, ProxyError> {
        let id = id.into();
        if api_key.trim().is_empty() {
            return Err(ProxyError::Credential {
                provider: id,
                hint: "Anthropic requires an API key — add an `ANTHROPIC_API_KEY` to the host keystore".into(),
            });
        }

        let base_url = base_url
            .map(Into::into)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            "anthropic-version",
            HeaderValue::from_static(ANTHROPIC_VERSION),
        );

        let http = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .pool_max_idle_per_host(8)
            .default_headers(headers)
            .build()
            .map_err(|e| ProxyError::Upstream {
                provider: id.clone(),
                message: format!("http client build failed: {e}"),
            })?;

        let models = models
            .into_iter()
            .map(|id| ModelInfo {
                id,
                owned_by: "anthropic",
            })
            .collect();

        Ok(Self {
            id,
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
            api_key,
            models,
        })
    }

    fn endpoint(&self) -> String {
        format!("{}/v1/messages", self.base_url)
    }
}

#[async_trait]
impl Provider for AnthropicApiProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn models(&self) -> &[ModelInfo] {
        &self.models
    }

    async fn chat(&self, openai_body: &Value, stream: bool) -> Result<ChatResponse, ProxyError> {
        let request_model = openai_body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("(unknown)")
            .to_string();
        let anthropic_body = to_anthropic_request(openai_body);

        let url = self.endpoint();
        let response = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .json(&anthropic_body)
            .send()
            .await
            .map_err(|e| ProxyError::Upstream {
                provider: self.id.clone(),
                message: format!("{url}: {e}"),
            })?;

        let status = response.status();
        if !status.is_success() {
            let bytes = response.bytes().await.unwrap_or_default();
            let text = String::from_utf8_lossy(&bytes).into_owned();
            return Err(ProxyError::Upstream {
                provider: self.id.clone(),
                message: format!("HTTP {status}: {text}"),
            });
        }

        if stream {
            let provider_id = self.id.clone();
            let bytes_stream = response.bytes_stream();
            let openai_sse = translate_sse_stream(provider_id, request_model, bytes_stream);
            Ok(ChatResponse::Stream(openai_sse.boxed()))
        } else {
            let bytes = response.bytes().await.map_err(|e| ProxyError::Upstream {
                provider: self.id.clone(),
                message: format!("body read: {e}"),
            })?;
            let anthropic: Value =
                serde_json::from_slice(&bytes).map_err(|e| ProxyError::Upstream {
                    provider: self.id.clone(),
                    message: format!("parse upstream JSON: {e}"),
                })?;
            let openai = from_anthropic_response(&anthropic, &request_model);
            let out = serde_json::to_vec(&openai).map_err(|e| ProxyError::Upstream {
                provider: self.id.clone(),
                message: format!("serialize: {e}"),
            })?;
            Ok(ChatResponse::Json(Bytes::from(out)))
        }
    }
}

/// Drive the upstream SSE byte stream through [`SseTranslator`] and emit
/// OpenAI-shape SSE frames. Each frame is one full `data: {...}\n\n` (or
/// `data: [DONE]\n\n`) record.
fn translate_sse_stream<S>(
    provider_id: String,
    request_model: String,
    upstream: S,
) -> BoxStream<'static, Result<Bytes, ProxyError>>
where
    S: futures_util::Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
{
    let translator = SseTranslator::new(request_model);
    // reqwest's bytes_stream is `Send` but not `Unpin`. Box+pin first so
    // our SseTranslationStream (which needs `Unpin` for the inner stream)
    // accepts it.
    let upstream: BoxStream<'static, Result<Bytes, ProxyError>> = upstream
        .map_err(move |e| ProxyError::Stream(format!("{provider_id}: {e}")))
        .boxed();
    Box::pin(SseTranslationStream::new(upstream, translator))
}

/// Wraps an upstream byte stream + an [`SseTranslator`] into a downstream
/// `Stream<Item = Result<Bytes, ProxyError>>`.
///
/// Buffers bytes until it sees a full SSE record (terminator `\n\n`),
/// parses the JSON payload (the part after `data: `), feeds it to the
/// translator, and yields the resulting OpenAI frames one at a time.
///
/// On upstream end, calls `translator.finish()` so the downstream client
/// always sees a terminal chunk + `[DONE]`.
struct SseTranslationStream<S> {
    upstream: S,
    translator: SseTranslator,
    buffer: String,
    pending: std::collections::VecDeque<Bytes>,
    upstream_done: bool,
    sent_final: bool,
}

impl<S> SseTranslationStream<S>
where
    S: futures_util::Stream<Item = Result<Bytes, ProxyError>> + Unpin,
{
    fn new(upstream: S, translator: SseTranslator) -> Self {
        Self {
            upstream,
            translator,
            buffer: String::new(),
            pending: std::collections::VecDeque::new(),
            upstream_done: false,
            sent_final: false,
        }
    }

    fn drain_records(&mut self) {
        // Walk the buffer pulling out `\n\n`-terminated records.
        loop {
            let Some(idx) = self.buffer.find("\n\n") else {
                break;
            };
            let record = self.buffer[..idx].to_string();
            self.buffer.drain(..idx + 2);
            self.handle_record(&record);
        }
    }

    fn handle_record(&mut self, record: &str) {
        // Anthropic streams events with both `event:` and `data:` lines.
        // We only need the `data:` payload (it carries the full typed
        // event in its `type` field).
        let mut data_line: Option<&str> = None;
        for line in record.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                data_line = Some(rest.trim_start());
            }
        }
        let Some(payload) = data_line else { return };
        if payload == "[DONE]" {
            // Upstream's own DONE — let the translator's `finish()` close us.
            self.upstream_done = true;
            return;
        }
        let Ok(parsed) = serde_json::from_str::<Value>(payload) else {
            // Skip malformed events rather than failing the stream.
            return;
        };
        for frame in self.translator.translate_event(&parsed) {
            self.pending.push_back(Bytes::from(frame));
        }
    }

    fn flush_finish(&mut self) {
        if self.sent_final {
            return;
        }
        for frame in self.translator.finish() {
            self.pending.push_back(Bytes::from(frame));
        }
        self.sent_final = true;
    }
}

impl<S> futures_util::Stream for SseTranslationStream<S>
where
    S: futures_util::Stream<Item = Result<Bytes, ProxyError>> + Unpin,
{
    type Item = Result<Bytes, ProxyError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return std::task::Poll::Ready(Some(Ok(frame)));
            }
            if self.upstream_done {
                if !self.sent_final {
                    self.flush_finish();
                    continue;
                }
                return std::task::Poll::Ready(None);
            }
            match std::pin::Pin::new(&mut self.upstream).poll_next(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(None) => {
                    self.upstream_done = true;
                    // Process whatever's left in the buffer (in case the
                    // upstream cut off without a trailing \n\n).
                    if !self.buffer.is_empty() {
                        let trailing = std::mem::take(&mut self.buffer);
                        self.handle_record(&trailing);
                    }
                    self.flush_finish();
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    self.upstream_done = true;
                    self.flush_finish();
                    return std::task::Poll::Ready(Some(Err(e)));
                }
                std::task::Poll::Ready(Some(Ok(chunk))) => {
                    if let Ok(text) = std::str::from_utf8(&chunk) {
                        self.buffer.push_str(text);
                        self.drain_records();
                    } else {
                        // Anthropic SSE is ASCII/UTF-8; non-UTF-8 chunks
                        // are surface-level corruption — pass through as
                        // a stream error.
                        return std::task::Poll::Ready(Some(Err(ProxyError::Stream(
                            "non-UTF-8 bytes in upstream SSE".into(),
                        ))));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_api_key_fails_fast_at_construction() {
        let result = AnthropicApiProvider::new(
            "anthropic",
            None::<String>,
            String::new(),
            vec!["claude-opus-4-7".into()],
        );
        let Err(err) = result else {
            panic!("expected Err on empty API key");
        };
        match err {
            ProxyError::Credential { provider, hint } => {
                assert_eq!(provider, "anthropic");
                assert!(hint.contains("API key"), "hint missing API-key reference: {hint}");
            }
            other => panic!("expected Credential, got {other:?}"),
        }
    }

    #[test]
    fn endpoint_appends_v1_messages_to_base_url() {
        let p = AnthropicApiProvider::new(
            "anthropic",
            Some("https://api.anthropic.com/"),
            "sk-ant-fake".into(),
            vec!["claude".into()],
        )
        .unwrap();
        assert_eq!(p.endpoint(), "https://api.anthropic.com/v1/messages");

        let p = AnthropicApiProvider::new(
            "anthropic",
            None::<String>,
            "sk-ant-fake".into(),
            vec!["claude".into()],
        )
        .unwrap();
        assert_eq!(p.endpoint(), "https://api.anthropic.com/v1/messages");
    }
}

