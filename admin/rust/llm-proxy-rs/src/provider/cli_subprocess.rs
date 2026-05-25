//! Generic CLI-OAuth subprocess provider.
//!
//! One implementation, multiple "flavors" (`claude`, `codex`, `gemini`,
//! `opencode`). Each flavor encapsulates the per-binary differences that
//! showed up across the catalog:
//!
//! - Binary name (`claude` / `codex` / `gemini` / `opencode`)
//! - argv pattern (positional vs `--prompt`, `-m` vs `--model`, etc.)
//! - Model alias rules (Claude collapses to `opus`/`sonnet`/`haiku`;
//!   Codex passes the model id through verbatim; etc.)
//!
//! All flavors share the same OpenAI-shape request → text-on-stdout
//! reply contract and reuse the same flattening + streaming-synthesis
//! helpers. Adding a new CLI = one match arm in `CliFlavor::argv` plus
//! (optionally) one in `map_model`.
//!
//! Credentials never leave the host. The proxy spawns the CLI; whatever
//! OAuth state the user logged in with lives in their home (`~/.claude/`,
//! `~/.codex/`, `~/.config/gemini/`, etc.) and the claw never sees it.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::error::ProxyError;
use crate::profile::CliFlavor;
use crate::provider::{ChatResponse, ModelInfo, Provider};

/// Default per-request subprocess timeout. Reasoning models can take a
/// while; 180s matches the OpenAI-compat backend's default.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);

/// How a flavor consumes the prompt: argv argument vs. stdin.
#[derive(Debug, Clone, Copy)]
enum PromptDelivery {
    /// Pass the prompt as the final positional argv. `claude -p ... <prompt>`.
    Argv,
    /// Pipe the prompt over stdin. Used when the prompt may be longer
    /// than ARG_MAX or when the CLI prefers it (codex with `-`).
    Stdin,
}

impl CliFlavor {
    /// Default binary name when `cli_binary_path` is not configured.
    fn default_binary(self) -> &'static str {
        match self {
            CliFlavor::Claude => "claude",
            CliFlavor::Codex => "codex",
            CliFlavor::Gemini => "gemini",
            CliFlavor::Opencode => "opencode",
        }
    }

    /// Build the argv (excluding binary[0]) for a given prompt + model.
    /// Some flavors put the prompt on stdin, in which case the returned
    /// argv omits the prompt and the caller pipes it.
    fn argv(self, model: &str, prompt: Option<&str>) -> Vec<String> {
        match self {
            CliFlavor::Claude => {
                let alias = map_claude_alias(model);
                let mut a = vec!["-p".to_string(), "--model".into(), alias.into()];
                if let Some(p) = prompt {
                    a.push(p.to_string());
                }
                a
            }
            CliFlavor::Codex => {
                // `codex exec -m <model> -` reads prompt from stdin.
                vec!["exec".into(), "-m".into(), model.to_string(), "-".into()]
            }
            CliFlavor::Gemini => {
                // `gemini --model <model> --prompt <text>` — verified
                // against the published Gemini CLI 1.x contract. The
                // CLI also accepts stdin via `-` but argv is more
                // direct for the v1 case where prompts are small.
                let mut a = vec!["--model".to_string(), model.to_string(), "--prompt".into()];
                if let Some(p) = prompt {
                    a.push(p.to_string());
                }
                a
            }
            CliFlavor::Opencode => {
                // `opencode run <message>` — `run` is the non-interactive
                // subcommand (`opencode --help` lists it). Model is
                // selected via the user's opencode config; we don't
                // pass `-m`.
                let mut a = vec!["run".to_string()];
                if let Some(p) = prompt {
                    a.push(p.to_string());
                }
                let _ = model; // model is owned by opencode config
                a
            }
        }
    }

    fn prompt_delivery(self) -> PromptDelivery {
        match self {
            CliFlavor::Codex => PromptDelivery::Stdin,
            CliFlavor::Claude | CliFlavor::Gemini | CliFlavor::Opencode => PromptDelivery::Argv,
        }
    }

    /// `owned_by` string published in `/v1/models` for each model from
    /// this flavor. Lets clients distinguish e.g. "claude via CLI" from
    /// "claude via Anthropic API" when both are configured.
    fn owned_by(self) -> &'static str {
        match self {
            CliFlavor::Claude => "anthropic-host-cli",
            CliFlavor::Codex => "openai-host-cli",
            CliFlavor::Gemini => "google-host-cli",
            CliFlavor::Opencode => "opencode-host-cli",
        }
    }
}

/// Map an OpenAI-shape Claude model id to the CLI's short alias. The
/// `claude` CLI only accepts `opus`/`sonnet`/`haiku` regardless of
/// version; the version is determined by which build the user installed.
fn map_claude_alias(model: &str) -> &'static str {
    let lower = model.to_ascii_lowercase();
    if lower.contains("opus") {
        "opus"
    } else if lower.contains("haiku") {
        "haiku"
    } else {
        "sonnet"
    }
}

pub struct CliSubprocessProvider {
    id: String,
    flavor: CliFlavor,
    cli_path: PathBuf,
    timeout: Duration,
    models: Vec<ModelInfo>,
}

impl CliSubprocessProvider {
    /// Build a CLI subprocess provider for a given flavor. `cli_path`
    /// defaults to the flavor's conventional binary name when not set;
    /// resolution then goes through `$PATH` at spawn time.
    pub fn new(
        id: impl Into<String>,
        flavor: CliFlavor,
        cli_path: Option<impl Into<PathBuf>>,
        timeout: Option<Duration>,
        models: Vec<String>,
    ) -> Self {
        let owned_by = flavor.owned_by();
        let models = models
            .into_iter()
            .map(|id| ModelInfo { id, owned_by })
            .collect();
        let cli_path = match cli_path {
            Some(p) => p.into(),
            None => PathBuf::from(flavor.default_binary()),
        };
        Self {
            id: id.into(),
            flavor,
            cli_path,
            timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
            models,
        }
    }

    /// Flatten OpenAI-shape `messages` into a single prompt the CLI
    /// accepts. Roles get `[role]` tags so the model can distinguish
    /// system / user / assistant inside one rendered transcript.
    pub fn flatten_messages(messages: &Value) -> String {
        let Some(arr) = messages.as_array() else {
            return String::new();
        };
        let mut parts: Vec<String> = Vec::with_capacity(arr.len());
        for msg in arr {
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
            let content = msg.get("content");
            let text = match content {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Array(parts_arr)) => parts_arr
                    .iter()
                    .filter_map(|p| {
                        if p.get("type").and_then(Value::as_str) == Some("text") {
                            p.get("text").and_then(Value::as_str).map(String::from)
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

    async fn run_subprocess(&self, prompt: &str, model: &str) -> Result<String, ProxyError> {
        let delivery = self.flavor.prompt_delivery();
        let argv = match delivery {
            PromptDelivery::Argv => self.flavor.argv(model, Some(prompt)),
            PromptDelivery::Stdin => self.flavor.argv(model, None),
        };

        let mut cmd = Command::new(&self.cli_path);
        cmd.args(&argv);
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        match delivery {
            PromptDelivery::Argv => {
                cmd.stdin(Stdio::null());
            }
            PromptDelivery::Stdin => {
                cmd.stdin(Stdio::piped());
            }
        }

        let mut proc = match cmd.spawn() {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProxyError::Upstream {
                    provider: self.id.clone(),
                    message: format!(
                        "{} CLI not found at {}; install it on the host then restart the proxy",
                        self.flavor.default_binary(),
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

        if matches!(delivery, PromptDelivery::Stdin) {
            if let Some(mut stdin) = proc.stdin.take() {
                if let Err(e) = stdin.write_all(prompt.as_bytes()).await {
                    return Err(ProxyError::Upstream {
                        provider: self.id.clone(),
                        message: format!("write stdin: {e}"),
                    });
                }
                // Closing stdin (drop) signals EOF to the child.
                drop(stdin);
            }
        }

        let output = match tokio::time::timeout(self.timeout, proc.wait_with_output()).await {
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
                    "{} exited with status {}: {}",
                    self.flavor.default_binary(),
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

    fn build_completion_json(model: &str, text: &str, provider_id: &str) -> Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        json!({
            "id": format!("chatcmpl-{provider_id}-{now}"),
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

    fn build_streaming_chunks(model: &str, text: &str, provider_id: &str) -> Vec<Bytes> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let id = format!("chatcmpl-{provider_id}-{now}");
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
impl Provider for CliSubprocessProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn models(&self) -> &[ModelInfo] {
        &self.models
    }

    async fn chat(&self, body: &Value, stream: bool) -> Result<ChatResponse, ProxyError> {
        let model = body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("default");
        let messages = body
            .get("messages")
            .ok_or_else(|| ProxyError::BadRequest("missing `messages`".into()))?;
        let prompt = Self::flatten_messages(messages);
        if prompt.is_empty() {
            return Err(ProxyError::BadRequest(
                "`messages` did not contain any non-empty content".into(),
            ));
        }

        let text = self.run_subprocess(&prompt, model).await?;

        if stream {
            let frames = Self::build_streaming_chunks(model, &text, &self.id);
            let stream = stream::iter(frames.into_iter().map(Ok::<_, ProxyError>));
            Ok(ChatResponse::Stream(Box::pin(stream)))
        } else {
            let payload = Self::build_completion_json(model, &text, &self.id);
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
    fn claude_argv_uses_alias_and_positional_prompt() {
        let argv = CliFlavor::Claude.argv("claude-opus-4-7", Some("hi"));
        assert_eq!(argv, vec!["-p", "--model", "opus", "hi"]);
    }

    #[test]
    fn codex_argv_uses_dash_for_stdin_and_passes_model_through() {
        let argv = CliFlavor::Codex.argv("gpt-5", None);
        assert_eq!(argv, vec!["exec", "-m", "gpt-5", "-"]);
        assert!(matches!(
            CliFlavor::Codex.prompt_delivery(),
            PromptDelivery::Stdin
        ));
    }

    #[test]
    fn gemini_argv_uses_named_flags() {
        let argv = CliFlavor::Gemini.argv("gemini-2.0-pro", Some("hi"));
        assert_eq!(argv, vec!["--model", "gemini-2.0-pro", "--prompt", "hi"]);
    }

    #[test]
    fn opencode_argv_does_not_pass_model_uses_run_subcommand() {
        let argv = CliFlavor::Opencode.argv("anything", Some("hi"));
        // opencode reads model from its own config; we only pass the
        // message.
        assert_eq!(argv, vec!["run", "hi"]);
    }

    #[test]
    fn map_claude_alias_routes_each_family() {
        assert_eq!(map_claude_alias("claude-opus-4-7"), "opus");
        assert_eq!(map_claude_alias("claude-haiku-4-5"), "haiku");
        assert_eq!(map_claude_alias("claude-sonnet-4-7"), "sonnet");
        assert_eq!(map_claude_alias("mystery"), "sonnet");
        assert_eq!(map_claude_alias("CLAUDE-OPUS"), "opus");
    }

    #[test]
    fn each_flavor_has_distinct_default_binary() {
        let bins = [
            CliFlavor::Claude.default_binary(),
            CliFlavor::Codex.default_binary(),
            CliFlavor::Gemini.default_binary(),
            CliFlavor::Opencode.default_binary(),
        ];
        let mut sorted: Vec<&str> = bins.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), bins.len(), "binary names must be distinct");
    }

    #[test]
    fn flatten_messages_joins_roles_with_bracket_tags() {
        let body = json!([
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "hi"},
        ]);
        let prompt = CliSubprocessProvider::flatten_messages(&body);
        assert!(prompt.contains("[system]\nbe terse"));
        assert!(prompt.contains("[user]\nhi"));
    }
}
