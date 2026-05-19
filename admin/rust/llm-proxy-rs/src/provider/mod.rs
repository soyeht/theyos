//! Backend provider trait + concrete implementations.
//!
//! Every provider answers two questions for the proxy: "what models do you
//! expose?" and "given this OpenAI-shape chat request, respond". Streaming
//! vs non-streaming is the provider's call — it returns [`ChatResponse`]
//! tagged with the shape it produced, and the server forwards accordingly.

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use serde_json::Value;

use crate::error::ProxyError;

pub mod anthropic_api;
pub mod claude_cli;
pub mod cli_subprocess;
pub mod openai_compat;

pub use anthropic_api::AnthropicApiProvider;
pub use claude_cli::ClaudeCliProvider;
pub use cli_subprocess::CliSubprocessProvider;
pub use openai_compat::OpenAiCompatProvider;

/// Model metadata returned by `/v1/models`.
#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub id: String,
    pub owned_by: &'static str,
}

/// Response shape returned from a [`Provider::chat`] call. Matches what the
/// upstream produced — the server is responsible for shaping bytes back to
/// the client (SSE headers vs JSON content-type).
pub enum ChatResponse {
    /// Single non-streaming JSON document, ready to return as
    /// `Content-Type: application/json`.
    Json(Bytes),
    /// SSE event stream. Each `Bytes` chunk is one or more `data: ...\n\n`
    /// frames already formatted per OpenAI's streaming spec.
    Stream(BoxStream<'static, Result<Bytes, ProxyError>>),
}

#[async_trait]
pub trait Provider: Send + Sync {
    /// Stable id used in profile files and audit logs.
    fn id(&self) -> &str;

    /// Models the provider exposes for `/v1/models` enumeration.
    fn models(&self) -> &[ModelInfo];

    /// Handle a single chat request. The `body` is the raw OpenAI-shape JSON
    /// from the client (we parse `stream` and `model` out of it, but pass
    /// the rest through transparently).
    async fn chat(&self, body: &Value, stream: bool) -> Result<ChatResponse, ProxyError>;
}
