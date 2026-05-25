//! OpenAI `/v1/chat/completions` ↔ Anthropic `/v1/messages` translation.
//!
//! Anthropic's REST API differs from OpenAI's in five places that matter
//! for the proxy:
//!
//! 1. **System prompt** lives at the top level of the request body, not as
//!    a `messages[].role == "system"` entry.
//! 2. **`max_tokens` is required** on Anthropic — OpenAI treats it as
//!    optional. We default it from the request, otherwise pick a sane
//!    server-side default.
//! 3. **Tools** use `input_schema` (not `parameters`) and the request
//!    field is `tools[]` of `{name, description, input_schema}` plain
//!    objects (no nested `function` wrapper).
//! 4. **Tool calls** are content blocks of type `tool_use`, not a separate
//!    `tool_calls` field. Tool result messages come back from the client
//!    as `role: "user"` with `content: [{type: "tool_result", ...}]`.
//! 5. **Streaming** is a sequence of typed SSE events
//!    (`message_start`, `content_block_start`, `content_block_delta`,
//!    `content_block_stop`, `message_delta`, `message_stop`), not the
//!    single `chat.completion.chunk` shape OpenAI emits.
//!
//! All the heavy lifting is in this file; the HTTP provider is a thin
//! wrapper over `reqwest` that calls into [`to_anthropic_request`],
//! [`from_anthropic_response`], and [`SseTranslator`].

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Map, Value, json};

/// The Anthropic version pin matching openclaw's bundled plugin
/// (`src/agents/anthropic-transport-stream.ts`).
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Default `max_tokens` when the inbound OpenAI request omits the field.
/// Anthropic requires the field; 4096 matches what most well-behaved
/// clients pick for general chat.
pub const DEFAULT_MAX_TOKENS: u32 = 4096;

// ── Request translation ─────────────────────────────────────────────────────

/// Translate an OpenAI-shape `/v1/chat/completions` body into an
/// Anthropic-shape `/v1/messages` body.
///
/// Preserves: `model`, `stream`, `temperature`, `top_p`, `stop`,
/// `metadata`. Drops OpenAI-only fields (`presence_penalty`,
/// `frequency_penalty`, `logit_bias`, `n`, `service_tier`) — Anthropic
/// rejects unknown keys.
#[must_use]
pub fn to_anthropic_request(openai_body: &Value) -> Value {
    let mut anthropic = Map::new();

    if let Some(model) = openai_body.get("model").and_then(Value::as_str) {
        anthropic.insert("model".into(), Value::String(model.into()));
    }

    let messages = openai_body
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let (system_prompt, body_messages) = split_system_and_messages(&messages);

    if let Some(sys) = system_prompt {
        anthropic.insert("system".into(), Value::String(sys));
    }
    anthropic.insert("messages".into(), Value::Array(body_messages));

    let max_tokens = openai_body
        .get("max_tokens")
        .and_then(Value::as_u64)
        .or_else(|| {
            openai_body
                .get("max_completion_tokens")
                .and_then(Value::as_u64)
        })
        .map_or(DEFAULT_MAX_TOKENS, |n| {
            u32::try_from(n).unwrap_or(DEFAULT_MAX_TOKENS)
        });
    anthropic.insert("max_tokens".into(), json!(max_tokens));

    for key in ["temperature", "top_p", "metadata"] {
        if let Some(v) = openai_body.get(key) {
            anthropic.insert(key.into(), v.clone());
        }
    }

    // OpenAI's `stop` accepts a string or an array of strings. Anthropic's
    // `stop_sequences` is always an array.
    if let Some(stop) = openai_body.get("stop") {
        match stop {
            Value::String(s) => {
                anthropic.insert("stop_sequences".into(), json!([s]));
            }
            Value::Array(_) => {
                anthropic.insert("stop_sequences".into(), stop.clone());
            }
            _ => {}
        }
    }

    if let Some(stream) = openai_body.get("stream").and_then(Value::as_bool) {
        anthropic.insert("stream".into(), Value::Bool(stream));
    }

    if let Some(tools) = openai_body.get("tools").and_then(Value::as_array) {
        let translated: Vec<Value> = tools.iter().filter_map(translate_openai_tool).collect();
        if !translated.is_empty() {
            anthropic.insert("tools".into(), Value::Array(translated));
        }
    }

    if let Some(choice) = openai_body.get("tool_choice") {
        if let Some(translated) = translate_openai_tool_choice(choice) {
            anthropic.insert("tool_choice".into(), translated);
        }
    }

    Value::Object(anthropic)
}

/// Split out system messages from `messages[]` and return
/// `(concatenated_system, non_system_messages_in_anthropic_shape)`.
///
/// OpenAI allows multiple system messages anywhere in `messages[]`;
/// Anthropic's API takes one top-level `system` string. We concatenate
/// them in order with blank-line separators.
///
/// Non-system messages are translated:
/// - `role: "tool"` → `role: "user"` with a `tool_result` content block
/// - `role: "assistant"` with `tool_calls` → content blocks of `text` +
///   `tool_use`
/// - everything else passes through with `content` normalised to either
///   a string (when it's already a string) or an array of typed content
///   blocks.
fn split_system_and_messages(messages: &[Value]) -> (Option<String>, Vec<Value>) {
    let mut systems: Vec<String> = Vec::new();
    let mut out: Vec<Value> = Vec::with_capacity(messages.len());

    for msg in messages {
        let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
        match role {
            "system" => {
                if let Some(text) = extract_text_content(msg.get("content")) {
                    systems.push(text);
                }
            }
            "tool" => {
                // OpenAI tool result: {role:"tool", tool_call_id, content}
                let tool_call_id = msg
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let content = msg
                    .get("content")
                    .and_then(Value::as_str)
                    .map(String::from)
                    .unwrap_or_default();
                out.push(json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": tool_call_id,
                        "content": content,
                    }]
                }));
            }
            "assistant" => {
                let mut blocks: Vec<Value> = Vec::new();
                if let Some(text) = extract_text_content(msg.get("content")) {
                    if !text.is_empty() {
                        blocks.push(json!({"type": "text", "text": text}));
                    }
                }
                if let Some(tool_calls) = msg.get("tool_calls").and_then(Value::as_array) {
                    for tc in tool_calls {
                        let id = tc
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        let function = tc.get("function").cloned().unwrap_or(json!({}));
                        let name = function
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        // OpenAI sends arguments as a JSON-encoded string.
                        let args_raw = function
                            .get("arguments")
                            .and_then(Value::as_str)
                            .unwrap_or("{}");
                        let input: Value =
                            serde_json::from_str(args_raw).unwrap_or_else(|_| json!({}));
                        blocks.push(json!({
                            "type": "tool_use",
                            "id": id,
                            "name": name,
                            "input": input,
                        }));
                    }
                }
                let content = if blocks.is_empty() {
                    json!("")
                } else {
                    Value::Array(blocks)
                };
                out.push(json!({"role": "assistant", "content": content}));
            }
            _ => {
                // user (or unknown role coerced to user)
                let content = msg
                    .get("content")
                    .cloned()
                    .unwrap_or(Value::String(String::new()));
                out.push(json!({"role": "user", "content": content}));
            }
        }
    }

    let system = if systems.is_empty() {
        None
    } else {
        Some(systems.join("\n\n"))
    };
    (system, out)
}

/// Extract a plain-text representation from an OpenAI `content` field.
/// Accepts the string form, an array of content parts (where we keep only
/// `text` parts), or `None`.
fn extract_text_content(content: Option<&Value>) -> Option<String> {
    match content {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(parts)) => {
            let texts: Vec<&str> = parts
                .iter()
                .filter_map(|p| {
                    if p.get("type").and_then(Value::as_str) == Some("text") {
                        p.get("text").and_then(Value::as_str)
                    } else {
                        None
                    }
                })
                .collect();
            if texts.is_empty() {
                None
            } else {
                Some(texts.join("\n"))
            }
        }
        _ => None,
    }
}

fn translate_openai_tool(tool: &Value) -> Option<Value> {
    let function = tool.get("function")?;
    let name = function.get("name")?.as_str()?.to_string();
    let description = function
        .get("description")
        .and_then(Value::as_str)
        .map(String::from);
    let input_schema = function
        .get("parameters")
        .cloned()
        .unwrap_or(json!({"type": "object"}));
    let mut out = Map::new();
    out.insert("name".into(), Value::String(name));
    if let Some(d) = description {
        out.insert("description".into(), Value::String(d));
    }
    out.insert("input_schema".into(), input_schema);
    Some(Value::Object(out))
}

fn translate_openai_tool_choice(choice: &Value) -> Option<Value> {
    match choice {
        Value::String(s) => match s.as_str() {
            "auto" => Some(json!({"type": "auto"})),
            "required" => Some(json!({"type": "any"})),
            // "none" and any unknown string both disable tools.
            _ => None,
        },
        Value::Object(_) => {
            let name = choice
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)?;
            Some(json!({"type": "tool", "name": name}))
        }
        _ => None,
    }
}

// ── Response translation (non-streaming) ────────────────────────────────────

/// Translate an Anthropic `/v1/messages` response (non-streaming) into an
/// OpenAI-shape `chat.completion` object.
#[must_use]
pub fn from_anthropic_response(anthropic: &Value, request_model: &str) -> Value {
    let id = anthropic
        .get("id")
        .and_then(Value::as_str)
        .map_or_else(generate_chatcmpl_id, |s| s.replace("msg_", "chatcmpl-"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let content_blocks = anthropic
        .get("content")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let (text, tool_calls) = collect_assistant_output(&content_blocks);

    let mut message = Map::new();
    message.insert("role".into(), Value::String("assistant".into()));
    message.insert(
        "content".into(),
        if text.is_empty() && !tool_calls.is_empty() {
            Value::Null
        } else {
            Value::String(text)
        },
    );
    if !tool_calls.is_empty() {
        message.insert("tool_calls".into(), Value::Array(tool_calls));
    }

    let finish_reason = map_stop_reason(anthropic.get("stop_reason").and_then(Value::as_str));
    let usage = map_usage(anthropic.get("usage"));

    json!({
        "id": id,
        "object": "chat.completion",
        "created": now,
        "model": anthropic
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(request_model),
        "choices": [{
            "index": 0,
            "message": Value::Object(message),
            "finish_reason": finish_reason,
        }],
        "usage": usage,
    })
}

fn collect_assistant_output(blocks: &[Value]) -> (String, Vec<Value>) {
    let mut text_parts: Vec<String> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    for block in blocks {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(t) = block.get("text").and_then(Value::as_str) {
                    text_parts.push(t.to_string());
                }
            }
            Some("tool_use") => {
                let id = block.get("id").and_then(Value::as_str).unwrap_or("");
                let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                let input = block.get("input").cloned().unwrap_or(json!({}));
                let arguments =
                    serde_json::to_string(&input).unwrap_or_else(|_| String::from("{}"));
                tool_calls.push(json!({
                    "id": id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": arguments,
                    },
                }));
            }
            _ => {}
        }
    }
    (text_parts.join(""), tool_calls)
}

/// Map Anthropic `stop_reason` to OpenAI `finish_reason`.
#[must_use]
pub fn map_stop_reason(stop_reason: Option<&str>) -> &'static str {
    match stop_reason {
        Some("tool_use") => "tool_calls",
        Some("max_tokens") => "length",
        // "end_turn", "stop_sequence", absent, or unknown — all map to "stop".
        _ => "stop",
    }
}

fn map_usage(usage: Option<&Value>) -> Value {
    let Some(u) = usage else {
        return json!({"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0});
    };
    let input = u.get("input_tokens").and_then(Value::as_u64).unwrap_or(0);
    let output = u.get("output_tokens").and_then(Value::as_u64).unwrap_or(0);
    json!({
        "prompt_tokens": input,
        "completion_tokens": output,
        "total_tokens": input + output,
    })
}

static CHATCMPL_SEQ: AtomicU64 = AtomicU64::new(0);

fn generate_chatcmpl_id() -> String {
    let n = CHATCMPL_SEQ.fetch_add(1, Ordering::Relaxed);
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("chatcmpl-anthropic-{secs}-{n}")
}

// ── Streaming translator (Anthropic SSE → OpenAI SSE) ───────────────────────

/// Stateful translator that converts the Anthropic streaming event format
/// into OpenAI `chat.completion.chunk` SSE frames.
///
/// Usage:
///
/// ```ignore
/// let mut t = SseTranslator::new(request_model);
/// for event in upstream_events {
///     for openai_frame in t.translate_event(event) {
///         downstream.send(openai_frame);
///     }
/// }
/// for closing_frame in t.finish() {
///     downstream.send(closing_frame);
/// }
/// ```
///
/// The translator buffers per-content-block state (block kind, partial
/// tool_use `input_json_delta` fragments) so it can emit the OpenAI
/// `tool_calls[].function.arguments` deltas correctly.
pub struct SseTranslator {
    request_model: String,
    chatcmpl_id: String,
    created: u64,
    /// `content_blocks[i] = ContentBlock`. Index matches Anthropic's
    /// `content_block_start.index`.
    content_blocks: Vec<ContentBlock>,
    /// True once we've sent the initial role chunk. Anthropic doesn't
    /// emit a role event; we synthesise one from `message_start`.
    sent_role: bool,
    /// Stored from `message_delta.delta.stop_reason`, surfaced on the
    /// terminal chunk.
    finish_reason: Option<&'static str>,
    /// Set when we get `[DONE]` from the upstream — caller stops calling
    /// `translate_event` after.
    closed: bool,
}

#[derive(Clone)]
enum ContentBlock {
    Text,
    ToolUse {
        /// Stable openai-shape index — distinct from Anthropic's
        /// `content_block.index` because OpenAI counts only tool_calls.
        openai_index: u32,
        /// We accumulate input_json_delta partials to detect the empty-
        /// input case (no deltas), but we ALSO forward each delta in
        /// real time so streaming clients see progress.
        seen_any_arguments: bool,
    },
}

impl SseTranslator {
    #[must_use]
    pub fn new(request_model: impl Into<String>) -> Self {
        let request_model = request_model.into();
        let chatcmpl_id = generate_chatcmpl_id();
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            request_model,
            chatcmpl_id,
            created,
            content_blocks: Vec::new(),
            sent_role: false,
            finish_reason: None,
            closed: false,
        }
    }

    /// Parse one upstream Anthropic SSE event payload (the JSON `data:`
    /// portion, already de-prefixed) and return zero or more OpenAI SSE
    /// frames ready to send downstream. Each returned `String` is a
    /// complete `data: {...}\n\n` record.
    pub fn translate_event(&mut self, payload: &Value) -> Vec<String> {
        if self.closed {
            return Vec::new();
        }
        let mut out = Vec::new();
        let event_type = payload.get("type").and_then(Value::as_str).unwrap_or("");
        match event_type {
            "message_start" => {
                // Anthropic doesn't emit a role-only event; we synthesise
                // it now so OpenAI clients see the standard 3-chunk shape.
                if !self.sent_role {
                    out.push(self.format_chunk(&json!({"role": "assistant", "content": ""}), None));
                    self.sent_role = true;
                }
            }
            "content_block_start" => {
                let block = payload.get("content_block");
                let block_kind = block.and_then(|b| b.get("type")).and_then(Value::as_str);
                match block_kind {
                    Some("text") => {
                        self.content_blocks.push(ContentBlock::Text);
                    }
                    Some("tool_use") => {
                        let openai_index = u32::try_from(
                            self.content_blocks
                                .iter()
                                .filter(|b| matches!(b, ContentBlock::ToolUse { .. }))
                                .count(),
                        )
                        .unwrap_or(0);
                        self.content_blocks.push(ContentBlock::ToolUse {
                            openai_index,
                            seen_any_arguments: false,
                        });
                        let id = block
                            .and_then(|b| b.get("id"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let name = block
                            .and_then(|b| b.get("name"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        out.push(self.format_chunk(
                            &json!({
                                "tool_calls": [{
                                    "index": openai_index,
                                    "id": id,
                                    "type": "function",
                                    "function": {"name": name, "arguments": ""},
                                }]
                            }),
                            None,
                        ));
                    }
                    _ => {
                        // Unknown block kind — push a sentinel so indexes stay aligned.
                        self.content_blocks.push(ContentBlock::Text);
                    }
                }
            }
            "content_block_delta" => {
                let index = payload
                    .get("index")
                    .and_then(Value::as_u64)
                    .map_or(0, |n| usize::try_from(n).unwrap_or(0));
                let delta_type = payload
                    .get("delta")
                    .and_then(|d| d.get("type"))
                    .and_then(Value::as_str);
                match delta_type {
                    Some("text_delta") => {
                        let text = payload
                            .get("delta")
                            .and_then(|d| d.get("text"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if !text.is_empty() {
                            out.push(self.format_chunk(&json!({"content": text}), None));
                        }
                    }
                    Some("input_json_delta") => {
                        let partial = payload
                            .get("delta")
                            .and_then(|d| d.get("partial_json"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if let Some(ContentBlock::ToolUse {
                            openai_index,
                            seen_any_arguments,
                        }) = self.content_blocks.get_mut(index)
                        {
                            *seen_any_arguments = true;
                            let idx = *openai_index;
                            if !partial.is_empty() {
                                out.push(self.format_chunk(
                                    &json!({
                                        "tool_calls": [{
                                            "index": idx,
                                            "function": {"arguments": partial},
                                        }]
                                    }),
                                    None,
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }
            "message_delta" => {
                if let Some(stop) = payload
                    .get("delta")
                    .and_then(|d| d.get("stop_reason"))
                    .and_then(Value::as_str)
                {
                    self.finish_reason = Some(map_stop_reason(Some(stop)));
                }
            }
            "message_stop" => {
                let reason = self.finish_reason.unwrap_or("stop");
                out.push(self.format_chunk(&json!({}), Some(reason)));
                out.push("data: [DONE]\n\n".into());
                self.closed = true;
            }
            _ => {}
        }
        out
    }

    /// Emit any remaining frames the upstream skipped (e.g. when the
    /// upstream closed without a `message_stop`). Idempotent — safe to
    /// call after [`translate_event`] has already produced `[DONE]`.
    pub fn finish(&mut self) -> Vec<String> {
        if self.closed {
            return Vec::new();
        }
        let reason = self.finish_reason.unwrap_or("stop");
        let mut out = Vec::with_capacity(2);
        if !self.sent_role {
            out.push(self.format_chunk(&json!({"role": "assistant", "content": ""}), None));
            self.sent_role = true;
        }
        out.push(self.format_chunk(&json!({}), Some(reason)));
        out.push("data: [DONE]\n\n".into());
        self.closed = true;
        out
    }

    fn format_chunk(&self, delta: &Value, finish: Option<&str>) -> String {
        let payload = json!({
            "id": self.chatcmpl_id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.request_model,
            "choices": [{
                "index": 0,
                "delta": delta,
                "finish_reason": finish,
            }],
        });
        format!("data: {payload}\n\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Request translation tests ──────────────────────────────────────

    #[test]
    fn system_messages_extracted_to_top_level_and_concatenated() {
        let body = json!({
            "model": "claude-sonnet-4-7",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "system", "content": "no markdown"},
                {"role": "user", "content": "hi"}
            ]
        });
        let out = to_anthropic_request(&body);
        assert_eq!(out["system"], "be terse\n\nno markdown");
        assert_eq!(out["messages"].as_array().unwrap().len(), 1);
        assert_eq!(out["messages"][0]["role"], "user");
        assert_eq!(out["messages"][0]["content"], "hi");
    }

    #[test]
    fn max_tokens_required_field_defaulted_when_omitted() {
        let body = json!({"model": "x", "messages": [{"role": "user", "content": "hi"}]});
        let out = to_anthropic_request(&body);
        assert_eq!(out["max_tokens"], DEFAULT_MAX_TOKENS);
    }

    #[test]
    fn max_tokens_preserved_from_openai_request() {
        let body = json!({
            "model": "x",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 250
        });
        let out = to_anthropic_request(&body);
        assert_eq!(out["max_tokens"], 250);
    }

    #[test]
    fn max_completion_tokens_is_an_accepted_alias() {
        // OpenAI's newer "max_completion_tokens" alias should be picked
        // up too. (Many clients use one or the other interchangeably.)
        let body = json!({
            "model": "x",
            "messages": [{"role": "user", "content": "hi"}],
            "max_completion_tokens": 999
        });
        let out = to_anthropic_request(&body);
        assert_eq!(out["max_tokens"], 999);
    }

    #[test]
    fn stop_string_becomes_array_in_anthropic() {
        let body = json!({
            "model": "x",
            "messages": [{"role": "user", "content": "hi"}],
            "stop": "\n\n"
        });
        let out = to_anthropic_request(&body);
        assert_eq!(out["stop_sequences"], json!(["\n\n"]));
    }

    #[test]
    fn stop_array_passes_through() {
        let body = json!({
            "model": "x",
            "messages": [{"role": "user", "content": "hi"}],
            "stop": ["a", "b"]
        });
        let out = to_anthropic_request(&body);
        assert_eq!(out["stop_sequences"], json!(["a", "b"]));
    }

    #[test]
    fn openai_only_fields_dropped() {
        let body = json!({
            "model": "x",
            "messages": [{"role": "user", "content": "hi"}],
            "presence_penalty": 0.5,
            "frequency_penalty": 0.2,
            "n": 2,
            "service_tier": "priority"
        });
        let out = to_anthropic_request(&body);
        assert!(out.get("presence_penalty").is_none());
        assert!(out.get("frequency_penalty").is_none());
        assert!(out.get("n").is_none());
        assert!(out.get("service_tier").is_none());
    }

    #[test]
    fn tool_role_message_becomes_user_with_tool_result_block() {
        let body = json!({
            "model": "x",
            "messages": [
                {"role": "user", "content": "use a tool"},
                {"role": "assistant", "content": null, "tool_calls": [{
                    "id": "call_abc",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"loc\":\"SF\"}"}
                }]},
                {"role": "tool", "tool_call_id": "call_abc", "content": "sunny"}
            ]
        });
        let out = to_anthropic_request(&body);
        let messages = out["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);

        // Assistant message has the tool_use content block.
        assert_eq!(messages[1]["role"], "assistant");
        let asst_content = messages[1]["content"].as_array().unwrap();
        let tool_use = asst_content
            .iter()
            .find(|b| b["type"] == "tool_use")
            .unwrap();
        assert_eq!(tool_use["id"], "call_abc");
        assert_eq!(tool_use["name"], "get_weather");
        // Arguments string parsed back into a JSON object (Anthropic wants object).
        assert_eq!(tool_use["input"], json!({"loc": "SF"}));

        // Tool result becomes a user message with a tool_result block.
        assert_eq!(messages[2]["role"], "user");
        let res_content = messages[2]["content"].as_array().unwrap();
        assert_eq!(res_content[0]["type"], "tool_result");
        assert_eq!(res_content[0]["tool_use_id"], "call_abc");
        assert_eq!(res_content[0]["content"], "sunny");
    }

    #[test]
    fn tools_array_translated_function_to_anthropic_shape() {
        let body = json!({
            "model": "x",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "lookup",
                    "description": "look something up",
                    "parameters": {"type": "object", "properties": {"q": {"type": "string"}}}
                }
            }]
        });
        let out = to_anthropic_request(&body);
        let tools = out["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "lookup");
        assert_eq!(tools[0]["description"], "look something up");
        // Note: input_schema (Anthropic) vs parameters (OpenAI).
        assert_eq!(tools[0]["input_schema"]["type"], "object");
        assert!(tools[0].get("parameters").is_none());
        assert!(tools[0].get("function").is_none());
    }

    #[test]
    fn tool_choice_string_translates_to_anthropic_object() {
        let mut body = json!({
            "model": "x",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": "auto"
        });
        let out = to_anthropic_request(&body);
        assert_eq!(out["tool_choice"], json!({"type": "auto"}));

        body["tool_choice"] = json!("required");
        let out = to_anthropic_request(&body);
        assert_eq!(out["tool_choice"], json!({"type": "any"}));

        // "none" → no tool_choice field at all.
        body["tool_choice"] = json!("none");
        let out = to_anthropic_request(&body);
        assert!(out.get("tool_choice").is_none());
    }

    #[test]
    fn tool_choice_function_specifier_becomes_named_tool() {
        let body = json!({
            "model": "x",
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": {"type": "function", "function": {"name": "lookup"}}
        });
        let out = to_anthropic_request(&body);
        assert_eq!(
            out["tool_choice"],
            json!({"type": "tool", "name": "lookup"})
        );
    }

    #[test]
    fn user_content_parts_array_passes_through_as_anthropic_blocks() {
        // OpenAI sends content as array of {type:text, text:...} parts.
        // Anthropic also accepts an array of blocks; pass through verbatim
        // so vision/multimodal works (image blocks etc.).
        let body = json!({
            "model": "x",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe this"},
                    {"type": "image_url", "image_url": {"url": "data:..."}}
                ]
            }]
        });
        let out = to_anthropic_request(&body);
        let msg = &out["messages"][0];
        assert_eq!(msg["role"], "user");
        // We pass content through unchanged for user role — Anthropic
        // parses its own array form.
        assert!(msg["content"].is_array());
    }

    // ── Response translation tests ─────────────────────────────────────

    #[test]
    fn text_only_response_becomes_string_content_choice() {
        let resp = json!({
            "id": "msg_abc",
            "type": "message",
            "model": "claude-sonnet-4-7",
            "content": [{"type": "text", "text": "hello"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 12, "output_tokens": 7}
        });
        let out = from_anthropic_response(&resp, "claude-sonnet-4-7");
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["choices"][0]["message"]["role"], "assistant");
        assert_eq!(out["choices"][0]["message"]["content"], "hello");
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(out["usage"]["prompt_tokens"], 12);
        assert_eq!(out["usage"]["completion_tokens"], 7);
        assert_eq!(out["usage"]["total_tokens"], 19);
        // id contains chatcmpl- prefix (from msg_ prefix substitution).
        assert!(
            out["id"].as_str().unwrap().starts_with("chatcmpl-"),
            "id = {}",
            out["id"]
        );
    }

    #[test]
    fn tool_use_response_becomes_tool_calls_with_arguments_serialised() {
        let resp = json!({
            "id": "msg_xyz",
            "model": "claude-opus-4-7",
            "content": [{
                "type": "tool_use",
                "id": "toolu_1",
                "name": "lookup",
                "input": {"q": "weather", "limit": 5}
            }],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 30, "output_tokens": 18}
        });
        let out = from_anthropic_response(&resp, "claude-opus-4-7");
        let msg = &out["choices"][0]["message"];
        assert_eq!(msg["role"], "assistant");
        assert_eq!(
            msg["content"],
            Value::Null,
            "content should be null when only tool calls"
        );
        let tcs = msg["tool_calls"].as_array().unwrap();
        assert_eq!(tcs.len(), 1);
        assert_eq!(tcs[0]["id"], "toolu_1");
        assert_eq!(tcs[0]["type"], "function");
        assert_eq!(tcs[0]["function"]["name"], "lookup");
        // OpenAI requires arguments as a STRING (JSON-encoded), not an object.
        let args = tcs[0]["function"]["arguments"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(args).unwrap();
        assert_eq!(parsed, json!({"q": "weather", "limit": 5}));

        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
    }

    #[test]
    fn mixed_text_and_tool_use_keeps_both() {
        let resp = json!({
            "id": "msg_mixed",
            "model": "claude-opus-4-7",
            "content": [
                {"type": "text", "text": "Let me look that up. "},
                {"type": "tool_use", "id": "t1", "name": "lookup", "input": {}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        });
        let out = from_anthropic_response(&resp, "claude-opus-4-7");
        let msg = &out["choices"][0]["message"];
        assert_eq!(msg["content"], "Let me look that up. ");
        assert_eq!(msg["tool_calls"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn stop_reason_mapping_covers_all_variants() {
        assert_eq!(map_stop_reason(Some("end_turn")), "stop");
        assert_eq!(map_stop_reason(Some("stop_sequence")), "stop");
        assert_eq!(map_stop_reason(Some("max_tokens")), "length");
        assert_eq!(map_stop_reason(Some("tool_use")), "tool_calls");
        assert_eq!(map_stop_reason(None), "stop");
        // Unknown future reasons fall back to "stop" rather than failing.
        assert_eq!(map_stop_reason(Some("future_reason")), "stop");
    }

    #[test]
    fn usage_missing_yields_zero_counts_not_a_panic() {
        let resp = json!({"id": "msg_x", "model": "m", "content": []});
        let out = from_anthropic_response(&resp, "m");
        assert_eq!(out["usage"]["prompt_tokens"], 0);
        assert_eq!(out["usage"]["completion_tokens"], 0);
        assert_eq!(out["usage"]["total_tokens"], 0);
    }

    // ── Streaming translator tests ─────────────────────────────────────

    fn parse_data_frame(frame: &str) -> Value {
        let stripped = frame.trim_start_matches("data: ").trim_end_matches("\n\n");
        if stripped == "[DONE]" {
            return json!("[DONE]");
        }
        serde_json::from_str(stripped).unwrap()
    }

    #[test]
    fn streaming_text_only_emits_role_then_content_deltas_then_stop() {
        let mut t = SseTranslator::new("claude-sonnet-4-7");
        let mut out = Vec::new();
        out.extend(t.translate_event(&json!({"type": "message_start", "message": {}})));
        out.extend(t.translate_event(
            &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text"}}),
        ));
        out.extend(t.translate_event(&json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "hi "}
        })));
        out.extend(t.translate_event(&json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "there"}
        })));
        out.extend(t.translate_event(&json!({"type": "content_block_stop", "index": 0})));
        out.extend(t.translate_event(&json!({
            "type": "message_delta", "delta": {"stop_reason": "end_turn"}
        })));
        out.extend(t.translate_event(&json!({"type": "message_stop"})));

        // Frames: role + 2 content deltas + stop chunk + [DONE]
        assert_eq!(out.len(), 5, "got frames: {out:?}");
        let role = parse_data_frame(&out[0]);
        assert_eq!(role["choices"][0]["delta"]["role"], "assistant");
        let d0 = parse_data_frame(&out[1]);
        assert_eq!(d0["choices"][0]["delta"]["content"], "hi ");
        let d1 = parse_data_frame(&out[2]);
        assert_eq!(d1["choices"][0]["delta"]["content"], "there");
        let stop = parse_data_frame(&out[3]);
        assert_eq!(stop["choices"][0]["finish_reason"], "stop");
        assert_eq!(out[4], "data: [DONE]\n\n");
    }

    #[test]
    fn streaming_tool_use_emits_function_args_incrementally() {
        let mut t = SseTranslator::new("claude-opus-4-7");
        let mut out = Vec::new();
        out.extend(t.translate_event(&json!({"type": "message_start", "message": {}})));
        // Content block 0: tool_use.
        out.extend(t.translate_event(&json!({
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "tool_use", "id": "toolu_1", "name": "lookup", "input": {}}
        })));
        // Incremental JSON.
        out.extend(t.translate_event(&json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": "{\"q\":\"weath"}
        })));
        out.extend(t.translate_event(&json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": "er\"}"}
        })));
        out.extend(t.translate_event(&json!({"type": "content_block_stop", "index": 0})));
        out.extend(t.translate_event(&json!({
            "type": "message_delta", "delta": {"stop_reason": "tool_use"}
        })));
        out.extend(t.translate_event(&json!({"type": "message_stop"})));

        // Frames: role, tool_call start (id/name), 2 args deltas, stop, [DONE]
        assert_eq!(out.len(), 6, "got frames: {out:?}");
        let role = parse_data_frame(&out[0]);
        assert_eq!(role["choices"][0]["delta"]["role"], "assistant");

        let call_start = parse_data_frame(&out[1]);
        let tc = &call_start["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tc["index"], 0);
        assert_eq!(tc["id"], "toolu_1");
        assert_eq!(tc["type"], "function");
        assert_eq!(tc["function"]["name"], "lookup");
        assert_eq!(tc["function"]["arguments"], "");

        let args_a = parse_data_frame(&out[2]);
        assert_eq!(
            args_a["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            "{\"q\":\"weath"
        );
        let args_b = parse_data_frame(&out[3]);
        assert_eq!(
            args_b["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            "er\"}"
        );

        let stop = parse_data_frame(&out[4]);
        assert_eq!(stop["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(out[5], "data: [DONE]\n\n");
    }

    #[test]
    fn streaming_finish_synthesises_done_when_upstream_cuts_off() {
        let mut t = SseTranslator::new("m");
        // Start a stream but never get to message_stop.
        let _ = t.translate_event(&json!({"type": "message_start", "message": {}}));
        let _ = t.translate_event(&json!({
            "type": "content_block_start", "index": 0, "content_block": {"type": "text"}
        }));
        let _ = t.translate_event(&json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "partial"}
        }));
        let trailing = t.finish();
        // The translator must produce a terminal chunk + [DONE] so clients
        // don't hang waiting for end-of-stream.
        let last = parse_data_frame(trailing.last().unwrap());
        assert_eq!(last, json!("[DONE]"));
        let stop = parse_data_frame(&trailing[trailing.len() - 2]);
        assert_eq!(stop["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn streaming_translator_is_idempotent_after_done() {
        let mut t = SseTranslator::new("m");
        let _ = t.translate_event(&json!({"type": "message_start"}));
        let _ = t.translate_event(&json!({"type": "message_stop"}));
        // Further events after [DONE] are silently ignored — no extra
        // frames, no panic.
        let more = t.translate_event(&json!({"type": "content_block_delta"}));
        assert!(more.is_empty());
        let more = t.finish();
        assert!(more.is_empty());
    }
}
