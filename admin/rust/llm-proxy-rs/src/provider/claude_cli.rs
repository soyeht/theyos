//! Claude CLI provider — runs the `claude` binary as a subprocess.
//!
//! Bridges OpenAI-shape `/v1/chat/completions` requests to the user's local
//! `claude` CLI install, which authenticates via the OAuth login bound to
//! the user's Claude Pro/Max/Team subscription. Credentials NEVER leave the
//! host — the proxy invokes the CLI; the OAuth token lives in
//! `~/.config/claude/` (or wherever the CLI keeps it), and the claw only
//! ever sees the proxy's loopback endpoint.
//!
//! This is the production version of the `/tmp/claude_cli_shim.py`
//! prototype I wrote during the architecture exploration.
//!
//! ## Subprocess contract
//!
//! - Invocation: `<cli_path> -p --model <opus|sonnet|haiku> <prompt>`
//! - stdin: not used (prompt is the final positional arg)
//! - stdout: the model's reply as plain text (no streaming)
//! - stderr: error messages on non-zero exit
//! - Exit 0: success
//! - Non-zero: error reported as [`ProxyError::Upstream`]
//!
//! ## Streaming
//!
//! The CLI is batch-only, but the proxy still synthesises OpenAI streaming
//! chunks (role chunk → content chunk → stop chunk → `[DONE]`) so clients
//! that send `"stream": true` (hermes, openclaw, the OpenAI SDK in stream
//! mode) get a well-formed SSE response.
//!
//! ## Model mapping
//!
//! The CLI accepts the short aliases `opus`, `sonnet`, `haiku` regardless
//! of version (it picks whichever the user's CLI install is currently
//! pointed at). The provider does substring matching on the OpenAI-shape
//! model id from the request:
//!
//! - contains "opus"  → `opus`
//! - contains "haiku" → `haiku`
//! - otherwise        → `sonnet` (safe default — the most commonly billed
//!                      Claude model)

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream;
use serde_json::{Value, json};
use tokio::process::Command;

use crate::error::ProxyError;
use crate::provider::{ChatResponse, ModelInfo, Provider};

/// Default per-request subprocess timeout. Reasoning models can take a
/// while; 180s is the same value used by the OpenAI-compat backend.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);

/// Default binary lookup. Resolved from `$PATH` at subprocess spawn time
/// when `cli_path` is not set; tests point at a tempfile script via
/// [`ClaudeCliProvider::with_cli_path`].
const DEFAULT_BINARY: &str = "claude";

pub struct ClaudeCliProvider {
    id: String,
    cli_path: PathBuf,
    timeout: Duration,
    models: Vec<ModelInfo>,
}

impl ClaudeCliProvider {
    /// Build a Claude CLI provider. `cli_path` defaults to `"claude"`
    /// (resolved via `$PATH`); override for tests or non-standard installs.
    pub fn new(
        id: impl Into<String>,
        cli_path: Option<impl Into<PathBuf>>,
        timeout: Option<Duration>,
        models: Vec<String>,
    ) -> Self {
        let models = models
            .into_iter()
            .map(|id| ModelInfo {
                id,
                owned_by: "anthropic-host-cli",
            })
            .collect();
        let cli_path = match cli_path {
            Some(p) => p.into(),
            None => PathBuf::from(DEFAULT_BINARY),
        };
        Self {
            id: id.into(),
            cli_path,
            timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
            models,
        }
    }

    /// Flatten an OpenAI-shape `messages` array into a single prompt the
    /// CLI accepts. Roles get bracketed so the model can distinguish
    /// system / user / assistant in the rendered transcript.
    pub fn flatten_messages(messages: &Value) -> String {
        let Some(arr) = messages.as_array() else {
            return String::new();
        };
        let mut parts: Vec<String> = Vec::with_capacity(arr.len());
        for msg in arr {
            let role = msg
                .get("role")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("user");
            let content = msg.get("content");
            let text = match content {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Array(parts_arr)) => parts_arr
                    .iter()
                    .filter_map(|p| {
                        // OpenAI content parts: { "type": "text", "text": "..." }
                        // or { "type": "image_url", ... } (we drop those).
                        if p.get("type").and_then(serde_json::Value::as_str) == Some("text") {
                            p.get("text")
                                .and_then(serde_json::Value::as_str)
                                .map(String::from)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => String::new(),
            };
            if text.is_empty() {
                continue;
            }
            parts.push(format!("[{role}]\n{text}"));
        }
        parts.join("\n\n")
    }

    /// Map an OpenAI-shape model id to the Claude CLI's short alias.
    /// Substring match — works across version strings like
    /// `claude-opus-4-7`, `anthropic/claude-opus-4-6`, or just `opus`.
    #[must_use]
    pub fn map_model_alias(model: &str) -> &'static str {
        let lower = model.to_ascii_lowercase();
        if lower.contains("opus") {
            "opus"
        } else if lower.contains("haiku") {
            "haiku"
        } else {
            "sonnet"
        }
    }

    async fn run_subprocess(&self, prompt: &str, model_alias: &str) -> Result<String, ProxyError> {
        let mut cmd = Command::new(&self.cli_path);
        cmd.arg("-p")
            .arg("--model")
            .arg(model_alias)
            .arg(prompt)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let proc = match cmd.spawn() {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProxyError::Upstream {
                    provider: self.id.clone(),
                    message: format!(
                        "claude CLI not found at {}; install it on the host then restart the proxy",
                        self.cli_path.display()
                    ),
                });
            }
            Err(e) => {
                return Err(ProxyError::Upstream {
                    provider: self.id.clone(),
                    message: format!("spawn {}: {e}", self.cli_path.display()),
                });
            }
        };

        let output_future = proc.wait_with_output();
        let output = match tokio::time::timeout(self.timeout, output_future).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                return Err(ProxyError::Upstream {
                    provider: self.id.clone(),
                    message: format!("wait: {e}"),
                });
            }
            Err(_) => {
                return Err(ProxyError::Upstream {
                    provider: self.id.clone(),
                    message: format!("subprocess timed out after {}s", self.timeout.as_secs()),
                });
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            // Prefer stderr; fall back to stdout in case the CLI logged its
            // error there. Truncate to avoid log spam.
            let mut msg = if stderr.trim().is_empty() {
                stdout
            } else {
                stderr
            };
            if msg.len() > 1024 {
                msg.truncate(1024);
                msg.push('…');
            }
            return Err(ProxyError::Upstream {
                provider: self.id.clone(),
                message: format!(
                    "claude exited with status {}: {}",
                    output
                        .status
                        .code()
                        .map_or_else(|| "?".to_string(), |c| c.to_string()),
                    msg.trim()
                ),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Build a complete OpenAI-shape chat.completion response for a
    /// non-streaming request, given the assistant's plain-text reply.
    fn build_completion_json(model: &str, text: &str) -> Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        json!({
            "id": format!("chatcmpl-claude-cli-{now}"),
            "object": "chat.completion",
            "created": now,
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            },
        })
    }

    /// Synthesise OpenAI SSE chunks for a non-streaming subprocess reply.
    /// Emits: role chunk, content chunk, stop chunk, `[DONE]`.
    fn build_streaming_chunks(model: &str, text: &str) -> Vec<Bytes> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let id = format!("chatcmpl-claude-cli-{now}");
        let mut frames = Vec::with_capacity(4);

        let chunk = |delta: Value, finish: Option<&str>| -> Value {
            json!({
                "id": id,
                "object": "chat.completion.chunk",
                "created": now,
                "model": model,
                "choices": [{
                    "index": 0,
                    "delta": delta,
                    "finish_reason": finish,
                }],
            })
        };

        let push = |frames: &mut Vec<Bytes>, payload: Value| {
            frames.push(Bytes::from(format!("data: {payload}\n\n")));
        };
        push(
            &mut frames,
            chunk(json!({"role": "assistant", "content": ""}), None),
        );
        push(&mut frames, chunk(json!({"content": text}), None));
        push(&mut frames, chunk(json!({}), Some("stop")));
        frames.push(Bytes::from_static(b"data: [DONE]\n\n"));
        frames
    }
}

#[async_trait]
impl Provider for ClaudeCliProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn models(&self) -> &[ModelInfo] {
        &self.models
    }

    async fn chat(&self, body: &Value, stream: bool) -> Result<ChatResponse, ProxyError> {
        let model = body
            .get("model")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("claude-sonnet");
        let messages = body
            .get("messages")
            .ok_or_else(|| ProxyError::BadRequest("missing `messages`".into()))?;
        let prompt = Self::flatten_messages(messages);
        if prompt.is_empty() {
            return Err(ProxyError::BadRequest(
                "`messages` did not contain any non-empty content".into(),
            ));
        }
        let alias = Self::map_model_alias(model);

        let text = self.run_subprocess(&prompt, alias).await?;

        if stream {
            let frames = Self::build_streaming_chunks(model, &text);
            let stream = stream::iter(frames.into_iter().map(Ok::<_, ProxyError>));
            Ok(ChatResponse::Stream(Box::pin(stream)))
        } else {
            let payload = Self::build_completion_json(model, &text);
            let bytes = serde_json::to_vec(&payload).map_err(|e| ProxyError::Upstream {
                provider: self.id.clone(),
                message: format!("serialize: {e}"),
            })?;
            Ok(ChatResponse::Json(Bytes::from(bytes)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_messages_joins_roles_with_bracket_tags() {
        let body = json!([
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
            {"role": "user", "content": "what's 2+2"},
        ]);
        let prompt = ClaudeCliProvider::flatten_messages(&body);
        assert!(prompt.contains("[system]\nbe terse"), "missing system");
        assert!(prompt.contains("[user]\nhi"), "missing first user");
        assert!(prompt.contains("[assistant]\nhello"), "missing assistant");
        assert!(prompt.contains("[user]\nwhat's 2+2"), "missing second user");
        // Sections are separated by blank line so the model can parse them.
        assert!(prompt.contains("\n\n"));
    }

    #[test]
    fn flatten_messages_drops_image_parts_keeps_text_parts() {
        let body = json!([
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe this"},
                    {"type": "image_url", "image_url": {"url": "data:..."}},
                    {"type": "text", "text": "in one word"},
                ]
            }
        ]);
        let prompt = ClaudeCliProvider::flatten_messages(&body);
        assert!(prompt.contains("describe this"));
        assert!(prompt.contains("in one word"));
        // Image parts are dropped, not stringified.
        assert!(!prompt.contains("data:"));
        assert!(!prompt.contains("image_url"));
    }

    #[test]
    fn flatten_messages_skips_messages_with_empty_content() {
        let body = json!([
            {"role": "system", "content": ""},
            {"role": "user", "content": "hi"},
        ]);
        let prompt = ClaudeCliProvider::flatten_messages(&body);
        // Empty system message dropped; only one section remains.
        assert!(!prompt.contains("[system]"));
        assert!(prompt.contains("[user]\nhi"));
    }

    #[test]
    fn flatten_messages_handles_empty_array() {
        let prompt = ClaudeCliProvider::flatten_messages(&json!([]));
        assert_eq!(prompt, "");
    }

    #[test]
    fn flatten_messages_handles_non_array_input() {
        // Defensive — body validation should catch this before we call,
        // but the function must not panic on malformed input.
        let prompt = ClaudeCliProvider::flatten_messages(&json!("not an array"));
        assert_eq!(prompt, "");
    }

    #[test]
    fn map_model_alias_routes_each_family() {
        assert_eq!(
            ClaudeCliProvider::map_model_alias("claude-opus-4-7"),
            "opus"
        );
        assert_eq!(
            ClaudeCliProvider::map_model_alias("claude-opus-4-6"),
            "opus"
        );
        assert_eq!(
            ClaudeCliProvider::map_model_alias("anthropic/claude-opus"),
            "opus"
        );

        assert_eq!(
            ClaudeCliProvider::map_model_alias("claude-haiku-4-5"),
            "haiku"
        );
        assert_eq!(
            ClaudeCliProvider::map_model_alias("anthropic/claude-haiku-3"),
            "haiku"
        );

        assert_eq!(
            ClaudeCliProvider::map_model_alias("claude-sonnet-4-7"),
            "sonnet"
        );
        // Unknown family falls back to sonnet.
        assert_eq!(
            ClaudeCliProvider::map_model_alias("mystery-model"),
            "sonnet"
        );
        assert_eq!(ClaudeCliProvider::map_model_alias(""), "sonnet");
    }

    #[test]
    fn map_model_alias_is_case_insensitive() {
        assert_eq!(
            ClaudeCliProvider::map_model_alias("CLAUDE-OPUS-4-7"),
            "opus"
        );
        assert_eq!(
            ClaudeCliProvider::map_model_alias("Claude-Haiku-4-5"),
            "haiku"
        );
    }

    #[test]
    fn build_streaming_chunks_has_role_content_stop_done() {
        let frames = ClaudeCliProvider::build_streaming_chunks("claude-opus-4-7", "hello");
        assert_eq!(frames.len(), 4);
        let f0 = std::str::from_utf8(&frames[0]).unwrap();
        let f1 = std::str::from_utf8(&frames[1]).unwrap();
        let f2 = std::str::from_utf8(&frames[2]).unwrap();
        let f3 = std::str::from_utf8(&frames[3]).unwrap();
        // Each data: chunk is followed by \n\n (SSE record terminator).
        assert!(f0.starts_with("data: ") && f0.ends_with("\n\n"));
        assert!(f0.contains("\"role\":\"assistant\""));
        assert!(f1.contains("\"content\":\"hello\""));
        assert!(f2.contains("\"finish_reason\":\"stop\""));
        assert_eq!(f3, "data: [DONE]\n\n");
    }

    #[test]
    fn build_completion_json_has_assistant_content_and_stop_finish() {
        let payload = ClaudeCliProvider::build_completion_json("claude-sonnet-4-7", "ok then");
        assert_eq!(payload["object"], "chat.completion");
        assert_eq!(payload["model"], "claude-sonnet-4-7");
        assert_eq!(payload["choices"][0]["index"], 0);
        assert_eq!(payload["choices"][0]["message"]["role"], "assistant");
        assert_eq!(payload["choices"][0]["message"]["content"], "ok then");
        assert_eq!(payload["choices"][0]["finish_reason"], "stop");
    }
}
