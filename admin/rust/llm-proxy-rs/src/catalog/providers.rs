//! Builtin catalog of providers.
//!
//! Order matters — this is what the UI displays. Major labs first, then
//! Chinese labs, then aggregators, then specialised inference, then
//! subscription/OAuth.
//!
//! Each entry is curated against the openclaw provider-plugin docs
//! (`docs/concepts/model-providers.md`) so theyOS profiles using these
//! ids will work uniformly across the openclaw + hermes claws.

use crate::profile::{CliFlavor, ProviderKind};

use super::{
    CatalogEntry, CatalogModel, CredentialHint, PlanInfo, Region,
};

/// Construct the full catalog. Cheap — clones a few static strings into
/// owned Strings; called once at proxy startup by `CatalogDoc::builtin`.
#[must_use]
pub fn make_all() -> Vec<CatalogEntry> {
    vec![
        // ─────────────── Major labs ───────────────
        CatalogEntry {
            id: "openai".into(),
            display_name: "OpenAI".into(),
            tagline: "GPT-5 family. Direct API + ChatGPT/Codex OAuth supported separately.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "https://api.openai.com/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model("gpt-5", "GPT-5", Some(400_000)),
                model("gpt-5-mini", "GPT-5 mini", Some(128_000)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "OPENAI_API_KEY".into(),
            },
            docs_url: Some("https://platform.openai.com/docs".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "anthropic".into(),
            display_name: "Anthropic".into(),
            tagline: "Claude — deep reasoning, tool use, long context.".into(),
            kind: ProviderKind::AnthropicApi,
            default_base_url: "https://api.anthropic.com".into(),
            coding_plan_base_url: None,
            models: vec![
                model("claude-opus-4-7", "Claude Opus 4.7", Some(200_000)),
                model("claude-opus-4-6", "Claude Opus 4.6", Some(200_000)),
                model("claude-sonnet-4-7", "Claude Sonnet 4.7", Some(200_000)),
                model("claude-haiku-4-5", "Claude Haiku 4.5", Some(200_000)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "ANTHROPIC_API_KEY".into(),
            },
            docs_url: Some("https://docs.claude.com/api/messages".into()),
            plan: Some(PlanInfo {
                name: "Claude Pro / Max (Claude Code via CLI)".into(),
                signup_url: "https://claude.ai/upgrade".into(),
                plan_model_id: None,
            }),
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "google".into(),
            display_name: "Google Gemini".into(),
            tagline: "1M-token context, multimodal native (text/image/video/audio).".into(),
            kind: ProviderKind::OpenaiCompat,
            // Gemini exposes an OpenAI-compatible endpoint.
            default_base_url: "https://generativelanguage.googleapis.com/v1beta/openai".into(),
            coding_plan_base_url: None,
            models: vec![
                model("gemini-3.1-pro-preview", "Gemini 3.1 Pro", Some(1_000_000)),
                model("gemini-3-flash-preview", "Gemini 3 Flash", Some(1_000_000)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "GEMINI_API_KEY".into(),
            },
            docs_url: Some(
                "https://ai.google.dev/gemini-api/docs/openai".into(),
            ),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "xai".into(),
            display_name: "xAI (Grok)".into(),
            tagline: "Grok models with /fast variants for low latency.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "https://api.x.ai/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model("grok-4.3", "Grok 4.3", Some(256_000)),
                model("grok-4.3-fast", "Grok 4.3 Fast", Some(256_000)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "XAI_API_KEY".into(),
            },
            docs_url: Some("https://docs.x.ai/".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        // ─────────────── Chinese labs ───────────────
        CatalogEntry {
            id: "deepseek".into(),
            display_name: "DeepSeek".into(),
            tagline: "V4-Flash + V4-Pro reasoning. 1M context, very cheap per token.".into(),
            kind: ProviderKind::OpenaiCompat,
            // openclaw docs explicitly note: base URL is `https://api.deepseek.com` (no /v1).
            default_base_url: "https://api.deepseek.com".into(),
            coding_plan_base_url: None,
            models: vec![
                model("deepseek-v4-flash", "DeepSeek V4-Flash", Some(1_000_000)),
                model("deepseek-v4-pro", "DeepSeek V4-Pro (reasoning)", Some(1_000_000)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "DEEPSEEK_API_KEY".into(),
            },
            docs_url: Some("https://api-docs.deepseek.com/".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "zai".into(),
            display_name: "Z.AI (GLM)".into(),
            tagline: "GLM 5.x and 4.x — top-tier with affordable Coding Plan.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "https://api.z.ai/api/paas/v4".into(),
            coding_plan_base_url: Some("https://api.z.ai/api/coding/paas/v4".into()),
            models: vec![
                model("glm-5.1", "GLM 5.1", Some(202_000)),
                model("glm-5", "GLM 5", Some(202_000)),
                model("glm-4.7", "GLM 4.7", Some(204_000)),
                model("glm-4.6", "GLM 4.6", Some(200_000)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "ZAI_API_KEY".into(),
            },
            docs_url: Some("https://docs.z.ai/".into()),
            plan: Some(PlanInfo {
                name: "Z.AI Coding Plan".into(),
                signup_url: "https://z.ai/subscribe".into(),
                plan_model_id: None,
            }),
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "moonshot".into(),
            display_name: "Moonshot (Kimi)".into(),
            tagline: "Kimi K2 family — agentic, long context.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "https://api.moonshot.ai/v1".into(),
            coding_plan_base_url: Some("https://api.kimi.com/coding/v1".into()),
            models: vec![
                model("kimi-k2.6", "Kimi K2.6", Some(200_000)),
                model("kimi-k2.5", "Kimi K2.5", Some(200_000)),
                model("kimi-k2-thinking", "Kimi K2 Thinking", Some(200_000)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "MOONSHOT_API_KEY".into(),
            },
            docs_url: Some("https://platform.moonshot.ai/".into()),
            plan: Some(PlanInfo {
                name: "Kimi Membership (Kimi Code via kimi-for-coding)".into(),
                signup_url: "https://www.kimi.com/membership/pricing".into(),
                plan_model_id: Some("kimi-for-coding".into()),
            }),
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "qwen".into(),
            display_name: "Alibaba (Qwen)".into(),
            tagline: "Qwen family via DashScope. Coding Plan aggregates Qwen + Kimi + GLM + MiniMax.".into(),
            kind: ProviderKind::OpenaiCompat,
            // Alibaba DashScope international OpenAI-compat endpoint.
            default_base_url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model("qwen3-max", "Qwen3 Max", Some(262_144)),
                model("qwen3.5-plus", "Qwen3.5 Plus", Some(262_144)),
                model("qwen3-coder-plus", "Qwen3 Coder Plus", Some(262_144)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "DASHSCOPE_API_KEY".into(),
            },
            docs_url: Some(
                "https://www.alibabacloud.com/help/en/model-studio/developer-reference/openai-compatible-api".into(),
            ),
            plan: Some(PlanInfo {
                name: "Alibaba AI Coding Plan (Lite / Pro)".into(),
                signup_url: "https://www.alibabacloud.com/en/campaign/ai-scene-coding".into(),
                plan_model_id: None,
            }),
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "minimax".into(),
            display_name: "MiniMax".into(),
            tagline: "Long context (up to 1M), agentic. Anthropic-compat or OpenAI-compat.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "https://api.minimax.io/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model("MiniMax-M2.7", "MiniMax M2.7", Some(1_000_000)),
                model("MiniMax-M2.5", "MiniMax M2.5", Some(1_000_000)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "MINIMAX_API_KEY".into(),
            },
            docs_url: Some("https://www.minimax.io/platform_overview".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        // ─────────────── Aggregators / gateways ───────────────
        CatalogEntry {
            id: "openrouter".into(),
            display_name: "OpenRouter".into(),
            tagline: "Aggregator — one key, access to hundreds of models.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "https://openrouter.ai/api/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model("openrouter/auto", "Auto (router picks best)", None),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "OPENROUTER_API_KEY".into(),
            },
            docs_url: Some("https://openrouter.ai/docs".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        // ─────────────── Specialised inference ───────────────
        CatalogEntry {
            id: "groq".into(),
            display_name: "Groq".into(),
            tagline: "Wafer-scale inference, very high throughput.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "https://api.groq.com/openai/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model("llama-3.3-70b-versatile", "Llama 3.3 70B", Some(131_072)),
                model("mixtral-8x7b-32768", "Mixtral 8x7B", Some(32_768)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "GROQ_API_KEY".into(),
            },
            docs_url: Some("https://console.groq.com/docs".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "cerebras".into(),
            display_name: "Cerebras".into(),
            tagline: "Wafer-scale (WSE) inference — runs Llama / GLM at extreme speed.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "https://api.cerebras.ai/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model("llama-3.3-70b", "Llama 3.3 70B (Cerebras)", Some(8_192)),
                model("zai-glm-4.7", "GLM 4.7 (Cerebras)", Some(128_000)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "CEREBRAS_API_KEY".into(),
            },
            docs_url: Some("https://inference-docs.cerebras.ai/".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "together".into(),
            display_name: "Together AI".into(),
            tagline: "Hosted open-source models — Llama, Mixtral, DeepSeek, Qwen.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "https://api.together.xyz/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model(
                    "moonshotai/Kimi-K2.5",
                    "Kimi K2.5 (via Together)",
                    Some(200_000),
                ),
                model(
                    "deepseek-ai/DeepSeek-V3.2",
                    "DeepSeek V3.2 (via Together)",
                    Some(131_072),
                ),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "TOGETHER_API_KEY".into(),
            },
            docs_url: Some("https://docs.together.ai/".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "mistral".into(),
            display_name: "Mistral".into(),
            tagline: "European generalist — Mistral Large, Codestral.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "https://api.mistral.ai/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model("mistral-large-latest", "Mistral Large", Some(128_000)),
                model("codestral-latest", "Codestral", Some(256_000)),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "MISTRAL_API_KEY".into(),
            },
            docs_url: Some("https://docs.mistral.ai/".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "nvidia".into(),
            display_name: "NVIDIA NIM".into(),
            tagline: "NVIDIA-hosted Nemotron + community models on NIM.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "https://integrate.api.nvidia.com/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model(
                    "nvidia/nemotron-3-super-120b-a12b",
                    "Nemotron 3 Super 120B",
                    Some(128_000),
                ),
            ],
            credential: CredentialHint::ApiKey {
                env_hint: "NVIDIA_API_KEY".into(),
            },
            docs_url: Some("https://build.nvidia.com/".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::default(),
        },
        // ─────────────── Subscription / OAuth (CLI-bound) ───────────────
        CatalogEntry {
            id: "claude-cli".into(),
            display_name: "Claude Code (CLI OAuth)".into(),
            tagline: "Uses your Claude Pro / Max / Team subscription via the local Claude CLI.".into(),
            kind: ProviderKind::CliOauth,
            default_base_url: String::new(),
            coding_plan_base_url: None,
            models: vec![
                model("claude-sonnet-4-7", "Claude Sonnet 4.7 (via CLI)", Some(200_000)),
                model("claude-opus-4-7", "Claude Opus 4.7 (via CLI)", Some(200_000)),
                model("claude-haiku-4-5", "Claude Haiku 4.5 (via CLI)", Some(200_000)),
            ],
            credential: CredentialHint::CliOauth {
                cli_binary: "claude".into(),
            },
            docs_url: Some("https://code.claude.com/docs/en/cli-reference".into()),
            plan: Some(PlanInfo {
                name: "Claude Pro / Max — Claude Code included".into(),
                signup_url: "https://claude.ai/upgrade".into(),
                plan_model_id: None,
            }),
            region: Some(Region::Global),
            cli_flavor: CliFlavor::Claude,
        },
        CatalogEntry {
            id: "openai-codex".into(),
            display_name: "OpenAI Codex (CLI OAuth)".into(),
            tagline: "Uses your ChatGPT coding plan via the local `codex` CLI (`codex exec`).".into(),
            kind: ProviderKind::CliOauth,
            default_base_url: String::new(),
            coding_plan_base_url: None,
            models: vec![
                model("gpt-5", "GPT-5 (via Codex CLI)", None),
                model("gpt-5-codex", "GPT-5 Codex (via Codex CLI)", None),
                model("o3", "o3 (via Codex CLI)", None),
            ],
            credential: CredentialHint::CliOauth {
                cli_binary: "codex".into(),
            },
            docs_url: Some("https://platform.openai.com/docs/codex-cli".into()),
            plan: Some(PlanInfo {
                name: "ChatGPT Plus / Pro — Codex included".into(),
                signup_url: "https://chat.openai.com/codex".into(),
                plan_model_id: None,
            }),
            region: Some(Region::Global),
            cli_flavor: CliFlavor::Codex,
        },
        CatalogEntry {
            id: "google-gemini-cli".into(),
            display_name: "Google Gemini (CLI OAuth)".into(),
            tagline: "Uses your Google AI subscription via the local `gemini` CLI.".into(),
            kind: ProviderKind::CliOauth,
            default_base_url: String::new(),
            coding_plan_base_url: None,
            models: vec![
                model("gemini-2.0-pro", "Gemini 2.0 Pro (via CLI)", Some(2_097_152)),
                model("gemini-2.0-flash", "Gemini 2.0 Flash (via CLI)", Some(1_048_576)),
            ],
            credential: CredentialHint::CliOauth {
                cli_binary: "gemini".into(),
            },
            docs_url: Some("https://ai.google.dev/gemini-api/docs/cli".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::Gemini,
        },
        CatalogEntry {
            id: "opencode-cli".into(),
            display_name: "opencode (CLI OAuth)".into(),
            tagline: "Open-source agent runtime — `opencode run` for non-interactive calls.".into(),
            kind: ProviderKind::CliOauth,
            default_base_url: String::new(),
            coding_plan_base_url: None,
            models: vec![
                // opencode resolves the model itself from its own config;
                // exposed here so the UI can show "opencode" as a provider.
                model("default", "Default (opencode config)", None),
            ],
            credential: CredentialHint::CliOauth {
                cli_binary: "opencode".into(),
            },
            docs_url: Some("https://opencode.ai/docs".into()),
            plan: None,
            region: Some(Region::Global),
            cli_flavor: CliFlavor::Opencode,
        },
        // ─────────────── Local providers ───────────────
        CatalogEntry {
            id: "ollama".into(),
            display_name: "Ollama".into(),
            tagline: "Local model server (CPU/GPU). Best default for Mac and Linux.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "http://127.0.0.1:11434/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model("llama3.1", "Llama 3.1", Some(131_072)),
                model("qwen3:4b", "Qwen3 4B", Some(262_144)),
            ],
            credential: CredentialHint::None,
            docs_url: Some("https://ollama.com/".into()),
            plan: None,
            region: None,
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "llamacpp".into(),
            display_name: "llama.cpp".into(),
            tagline: "Local GGUF runtime. Great fit for Mac and Linux.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "http://127.0.0.1:8080/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model("local", "Local (whatever llama-server is hosting)", None),
            ],
            credential: CredentialHint::None,
            docs_url: Some("https://github.com/ggerganov/llama.cpp".into()),
            plan: None,
            region: None,
            cli_flavor: CliFlavor::default(),
        },
        CatalogEntry {
            id: "mlx".into(),
            display_name: "MLX (Apple Silicon)".into(),
            tagline: "Best fit for Apple Silicon Macs.".into(),
            kind: ProviderKind::OpenaiCompat,
            default_base_url: "http://127.0.0.1:8080/v1".into(),
            coding_plan_base_url: None,
            models: vec![
                model(
                    "mlx-community/Qwen3-4B-Instruct-2507-4bit",
                    "Qwen3 4B Instruct (4-bit MLX)",
                    Some(32_768),
                ),
                model(
                    "mlx-community/Qwen3-Coder-30B-A3B-Instruct-4bit",
                    "Qwen3 Coder 30B A3B (4-bit MLX)",
                    Some(262_144),
                ),
            ],
            credential: CredentialHint::None,
            docs_url: Some("https://github.com/ml-explore/mlx-lm".into()),
            plan: None,
            region: None,
            cli_flavor: CliFlavor::default(),
        },
    ]
}

fn model(id: &str, display_name: &str, context_window: Option<u32>) -> CatalogModel {
    CatalogModel {
        id: id.into(),
        display_name: display_name.into(),
        context_window,
    }
}
