//! OpenAI-compatible passthrough backend.
//!
//! Forwards `POST <base_url>/chat/completions` to the upstream and proxies
//! the response (JSON or SSE) back to the caller. For LLM providers that
//! expose an OpenAI-shape REST API natively — ollama, llama.cpp, mlx,
//! OpenAI itself, GLM, DeepSeek, Kimi (Kimi Code endpoint), Moonshot,
//! Groq, Mistral, Together, Cerebras, OpenRouter, Vercel AI Gateway,
//! Kilo Gateway, etc. — this is the entire backend.
//!
//! Auth injection: when [`OpenAiCompatProvider::new`] receives an API key,
//! every outbound request adds `Authorization: Bearer <key>`. The key is
//! never logged. The proxy reads it once from the keystore at provider
//! construction time and holds it in memory — there is no per-request
//! keystore round-trip.

use std::time::Duration;

use async_trait::async_trait;
use futures_util::{StreamExt, TryStreamExt};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::Client;
use serde_json::Value;

use crate::error::ProxyError;
use crate::provider::{ChatResponse, ModelInfo, Provider};

/// Default per-request timeout for upstream calls. Reasoning models can take
/// >60s, so this is intentionally generous.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(180);

/// Connect timeout — short, because we expect loopback or healthy WAN.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct OpenAiCompatProvider {
    id: String,
    base_url: String,
    http: Client,
    api_key: Option<String>,
    models: Vec<ModelInfo>,
}

impl OpenAiCompatProvider {
    /// Build a provider against `base_url` (must already include the OpenAI
    /// path root, e.g. `http://127.0.0.1:11434/v1` or
    /// `https://api.openai.com/v1`).
    pub fn new(
        id: impl Into<String>,
        base_url: impl Into<String>,
        api_key: Option<String>,
        models: Vec<String>,
    ) -> Result<Self, ProxyError> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let http = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .pool_max_idle_per_host(8)
            .default_headers(headers)
            .build()
            .map_err(|e| ProxyError::Upstream {
                provider: "openai-compat".into(),
                message: format!("http client build failed: {e}"),
            })?;

        let models = models
            .into_iter()
            .map(|id| ModelInfo {
                id,
                owned_by: "openai-compat",
            })
            .collect();

        Ok(Self {
            id: id.into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
            api_key,
            models,
        })
    }

    fn endpoint(&self, suffix: &str) -> String {
        format!("{}/{}", self.base_url, suffix.trim_start_matches('/'))
    }

    fn authed(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(key) = &self.api_key {
            builder.header(AUTHORIZATION, format!("Bearer {key}"))
        } else {
            builder
        }
    }
}

#[async_trait]
impl Provider for OpenAiCompatProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn models(&self) -> &[ModelInfo] {
        &self.models
    }

    async fn chat(&self, body: &Value, stream: bool) -> Result<ChatResponse, ProxyError> {
        let url = self.endpoint("chat/completions");

        let response = self
            .authed(self.http.post(&url).json(body))
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
            let chunks = response
                .bytes_stream()
                .map_err(move |e| ProxyError::Stream(format!("{provider_id}: {e}")));
            Ok(ChatResponse::Stream(chunks.boxed()))
        } else {
            let bytes = response.bytes().await.map_err(|e| ProxyError::Upstream {
                provider: self.id.clone(),
                message: format!("body read: {e}"),
            })?;
            Ok(ChatResponse::Json(bytes))
        }
    }
}
