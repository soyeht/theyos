//! Shared LLM contract bootstrap for theyOS claws.

use serde_json::{Value, json};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

pub const CONTRACT_VERSION: u8 = 1;
pub const DEFAULT_LLM_PORT: u16 = 11_434;
pub const DEFAULT_OPENAI_COMPAT_PORT: u16 = 8_080;
/// Port the host-side `theyos-llm-proxy` daemon listens on. Any provider
/// that is not one of the directly-served local runtimes
/// (`ollama`/`llamacpp`/`mlx`) gets routed through the proxy at this port,
/// where claw requests reach a unified OpenAI-compat surface and the host
/// switches upstream by active profile.
pub const DEFAULT_LLM_PROXY_PORT: u16 = 18_900;
pub const DEFAULT_LLM_HOST_ADDR: &str = "127.0.0.1";
pub const DEFAULT_LLM_MODEL: &str = "llama3.1";
pub const DEFAULT_LLM_PROVIDER: &str = "ollama";
pub const DEFAULT_LLAMACPP_MODEL: &str = "local";
pub const DEFAULT_MLX_MODEL: &str = "mlx-community/Qwen3-4B-Instruct-2507-4bit";
/// Sentinel provider id that means "route through the host-side proxy".
/// Set `THEYOS_LLM_PROVIDER=proxy` in the claw's profile to point it at the
/// proxy instead of a direct upstream. The proxy's active profile then
/// decides which real provider serves the request.
pub const PROXY_PROVIDER_ID: &str = "proxy";
pub const DEFAULT_OPENCLAW_CONTEXT_WINDOW: u32 = 32_768;
pub const SAFE_FALLBACK_CONTEXT_WINDOW: u32 = 8_192;
pub const DEFAULT_OPENCLAW_MAX_TOKENS: u32 = 4_096;
pub const DEFAULT_LLM_PROFILE_FILE: &str = ".run/llm-profile.env";

const BOOTSTRAP_SH: &str = include_str!("claw_llm_bootstrap.sh");

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LlmBootstrapTarget {
    LinuxFirecracker,
    MacosVz,
}

impl LlmBootstrapTarget {
    fn path_export(self) -> Option<&'static str> {
        match self {
            Self::LinuxFirecracker => None,
            Self::MacosVz => {
                Some("export PATH=/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH;\n")
            }
        }
    }

    const fn login_shell_trailer(self) -> &'static str {
        match self {
            Self::LinuxFirecracker => {
                "if command -v bash >/dev/null 2>&1; then exec bash -l -i;\nelse exec sh -l; fi"
            }
            Self::MacosVz => {
                "if command -v bash >/dev/null 2>&1; then exec bash -l -i;\nelif command -v zsh >/dev/null 2>&1; then exec zsh -l;\nelse exec sh -l; fi"
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClawChatModes {
    hermes: String,
    openclaw: String,
}

impl ClawChatModes {
    #[must_use]
    pub fn new(hermes: impl Into<String>, openclaw: impl Into<String>) -> Self {
        Self {
            hermes: hermes.into(),
            openclaw: openclaw.into(),
        }
    }

    #[must_use]
    pub fn defaults_for(target: LlmBootstrapTarget) -> Self {
        match target {
            LlmBootstrapTarget::LinuxFirecracker => Self::new("chat", "gateway"),
            LlmBootstrapTarget::MacosVz => Self::new("chat", "local"),
        }
    }

    #[must_use]
    pub fn from_env_for_target(target: LlmBootstrapTarget, profile: &LlmProfile) -> Self {
        let defaults = Self::defaults_for(target);
        Self {
            hermes: env_string_any_with_profile(
                &["THEYOS_HERMES_CHAT_MODE"],
                &defaults.hermes,
                profile,
            ),
            openclaw: env_string_any_with_profile(
                &["THEYOS_OPENCLAW_CHAT_MODE"],
                &defaults.openclaw,
                profile,
            ),
        }
    }

    #[must_use]
    pub fn hermes(&self) -> &str {
        &self.hermes
    }

    #[must_use]
    pub fn openclaw(&self) -> &str {
        &self.openclaw
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OpenclawSettings {
    provider_config_key: String,
    provider_api: String,
    api_key: String,
    model_ref: String,
    context_window: u32,
    max_tokens: u32,
}

impl OpenclawSettings {
    #[must_use]
    pub fn from_env(
        provider: &str,
        model: &str,
        context_window: u32,
        profile: &LlmProfile,
    ) -> Self {
        let default_model_ref = format!("{provider}/{model}");
        let default_config_key = format!("models.providers.{provider}");
        Self {
            provider_config_key: env_string_any_with_profile(
                &["THEYOS_OPENCLAW_PROVIDER_KEY"],
                &default_config_key,
                profile,
            ),
            provider_api: env_string_any_with_profile(
                &["THEYOS_OPENCLAW_PROVIDER_API"],
                default_openclaw_api(provider),
                profile,
            ),
            api_key: env_string_any_with_profile(
                &["THEYOS_LLM_API_KEY"],
                default_api_key(provider),
                profile,
            ),
            model_ref: env_string_any_with_profile(
                &["THEYOS_OPENCLAW_MODEL_REF"],
                &default_model_ref,
                profile,
            ),
            context_window,
            max_tokens: env_u32_any_with_profile(
                &["THEYOS_LLM_MAX_TOKENS", "THEYOS_OLLAMA_MAX_TOKENS"],
                default_max_tokens(context_window),
                profile,
            ),
        }
    }

    #[must_use]
    pub fn for_provider_model(provider: &str, model: &str) -> Self {
        Self {
            provider_config_key: format!("models.providers.{provider}"),
            provider_api: default_openclaw_api(provider).to_string(),
            api_key: default_api_key(provider).to_string(),
            model_ref: format!("{provider}/{model}"),
            context_window: DEFAULT_OPENCLAW_CONTEXT_WINDOW,
            max_tokens: DEFAULT_OPENCLAW_MAX_TOKENS,
        }
    }

    #[must_use]
    pub fn with_context_window(mut self, context_window: u32) -> Self {
        self.context_window = context_window;
        self.max_tokens = default_max_tokens(context_window);
        self
    }

    #[must_use]
    pub fn provider_config_key(&self) -> &str {
        &self.provider_config_key
    }

    #[must_use]
    pub fn provider_api(&self) -> &str {
        &self.provider_api
    }

    #[must_use]
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    #[must_use]
    pub fn model_ref(&self) -> &str {
        &self.model_ref
    }

    #[must_use]
    pub fn context_window(&self) -> u32 {
        self.context_window
    }

    #[must_use]
    pub fn max_tokens(&self) -> u32 {
        self.max_tokens
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct LlmProfile {
    values: HashMap<String, String>,
}

impl LlmProfile {
    #[must_use]
    pub fn load() -> Self {
        let Some(path) = llm_profile_path() else {
            return Self::default();
        };
        Self {
            values: crate::env::load_dotenv(&path),
        }
    }

    #[must_use]
    pub fn get_any(&self, keys: &[&str]) -> Option<String> {
        keys.iter()
            .filter_map(|key| self.values.get(*key))
            .map(|value| value.trim().to_string())
            .find(|value| !value.is_empty())
    }

    #[must_use]
    pub fn path() -> Option<PathBuf> {
        llm_profile_path()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LlmContract {
    claw_type: Option<String>,
    provider: String,
    model: String,
    api_key: String,
    host_addr: String,
    host_port: u16,
    guest_port: u16,
    tunnel: bool,
    context_window: u32,
    context_source: String,
    base_url: String,
    openai_base_url: String,
    openclaw: OpenclawSettings,
    chat_modes: ClawChatModes,
}

impl LlmContract {
    #[must_use]
    pub fn from_env(claw_type: Option<String>, target: LlmBootstrapTarget) -> Self {
        let profile = LlmProfile::load();
        let provider = normalize_provider_id(&env_string_any_with_profile(
            &["THEYOS_LLM_PROVIDER", "THEYOS_LLM_BACKEND"],
            DEFAULT_LLM_PROVIDER,
            &profile,
        ));
        let host_port = env_port_any_with_profile(
            host_port_env_keys(&provider),
            default_provider_port(&provider),
            &profile,
        );
        let host_addr = env_string_any_with_profile(
            &[
                "THEYOS_LLM_HOST_ADDR",
                "THEYOS_LLM_UPSTREAM_HOST",
                "THEYOS_OLLAMA_HOST_ADDR",
            ],
            DEFAULT_LLM_HOST_ADDR,
            &profile,
        );
        let guest_port =
            env_port_any_with_profile(guest_port_env_keys(&provider), host_port, &profile);
        let base_url = env_string_any_with_profile(
            &["THEYOS_LLM_BASE_URL"],
            &format!("http://127.0.0.1:{guest_port}"),
            &profile,
        );
        // When routing through the host-side proxy we stamp the claw type
        // into the URL path so the proxy can apply per-claw overrides
        // without relying on custom HTTP headers (not every client adapter
        // supports them). Format matches the proxy's router:
        // `POST /v1/c/<claw-type>/chat/completions`.
        let default_openai_base = if provider == PROXY_PROVIDER_ID {
            match claw_type.as_deref() {
                Some(ct) if !ct.is_empty() => format!("{base_url}/v1/c/{ct}"),
                _ => format!("{base_url}/v1"),
            }
        } else {
            format!("{base_url}/v1")
        };
        let openai_base_url = env_string_any_with_profile(
            &["THEYOS_LLM_OPENAI_BASE_URL"],
            &default_openai_base,
            &profile,
        );
        let model = env_string_any_with_profile(
            model_env_keys(&provider),
            default_provider_model(&provider),
            &profile,
        );
        let api_key = env_string_any_with_profile(
            &["THEYOS_LLM_API_KEY"],
            default_api_key(&provider),
            &profile,
        );
        let (context_window, context_source) =
            resolve_context_window(&provider, &model, &base_url, &profile);

        Self {
            openclaw: OpenclawSettings::from_env(&provider, &model, context_window, &profile),
            chat_modes: ClawChatModes::from_env_for_target(target, &profile),
            claw_type,
            provider,
            model,
            api_key,
            host_addr,
            host_port,
            guest_port,
            tunnel: env_flag_default_any_with_profile(
                &["THEYOS_LLM_SSH_TUNNEL", "THEYOS_OLLAMA_SSH_TUNNEL"],
                true,
                &profile,
            ),
            context_window,
            context_source,
            base_url,
            openai_base_url,
        }
    }

    #[must_use]
    pub fn for_tests(claw_type: &str, target: LlmBootstrapTarget) -> Self {
        Self {
            claw_type: Some(claw_type.to_string()),
            provider: DEFAULT_LLM_PROVIDER.to_string(),
            model: DEFAULT_LLM_MODEL.to_string(),
            api_key: default_api_key(DEFAULT_LLM_PROVIDER).to_string(),
            host_addr: DEFAULT_LLM_HOST_ADDR.to_string(),
            host_port: DEFAULT_LLM_PORT,
            guest_port: DEFAULT_LLM_PORT,
            tunnel: true,
            context_window: DEFAULT_OPENCLAW_CONTEXT_WINDOW,
            context_source: "test".to_string(),
            base_url: format!("http://127.0.0.1:{DEFAULT_LLM_PORT}"),
            openai_base_url: format!("http://127.0.0.1:{DEFAULT_LLM_PORT}/v1"),
            openclaw: OpenclawSettings::for_provider_model(DEFAULT_LLM_PROVIDER, DEFAULT_LLM_MODEL),
            chat_modes: ClawChatModes::defaults_for(target),
        }
    }

    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        if let Some(context_window) = known_model_context_window(&self.provider, &self.model) {
            self.context_window = context_window;
            self.context_source = "model-profile".to_string();
        }
        self.openclaw = OpenclawSettings::for_provider_model(&self.provider, &self.model)
            .with_context_window(self.context_window);
        self
    }

    #[must_use]
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = normalize_provider_id(&provider.into());
        self.api_key = default_api_key(&self.provider).to_string();
        self.context_window = known_model_context_window(&self.provider, &self.model)
            .unwrap_or(SAFE_FALLBACK_CONTEXT_WINDOW);
        self.context_source = "model-profile-or-safe-fallback".to_string();
        self.openclaw = OpenclawSettings::for_provider_model(&self.provider, &self.model)
            .with_context_window(self.context_window);
        self
    }

    #[must_use]
    pub fn with_host_addr(mut self, host_addr: impl Into<String>) -> Self {
        self.host_addr = host_addr.into();
        self
    }

    #[must_use]
    pub fn with_guest_port(mut self, guest_port: u16) -> Self {
        self.guest_port = guest_port;
        self.base_url = format!("http://127.0.0.1:{guest_port}");
        self.openai_base_url = format!("{}/v1", self.base_url);
        self
    }

    #[must_use]
    pub fn with_tunnel(mut self, tunnel: bool) -> Self {
        self.tunnel = tunnel;
        self
    }

    #[must_use]
    pub fn with_chat_modes(mut self, chat_modes: ClawChatModes) -> Self {
        self.chat_modes = chat_modes;
        self
    }

    #[must_use]
    pub fn claw_type(&self) -> Option<&str> {
        self.claw_type.as_deref()
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    #[must_use]
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    #[must_use]
    pub fn host_addr(&self) -> &str {
        &self.host_addr
    }

    #[must_use]
    pub fn host_port(&self) -> u16 {
        self.host_port
    }

    #[must_use]
    pub fn guest_port(&self) -> u16 {
        self.guest_port
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn context_window(&self) -> u32 {
        self.context_window
    }

    #[must_use]
    pub fn context_source(&self) -> &str {
        &self.context_source
    }

    #[must_use]
    pub fn openai_base_url(&self) -> &str {
        &self.openai_base_url
    }

    #[must_use]
    pub fn openclaw(&self) -> &OpenclawSettings {
        &self.openclaw
    }

    #[must_use]
    pub fn chat_modes(&self) -> &ClawChatModes {
        &self.chat_modes
    }

    #[must_use]
    pub fn ssh_reverse_forward(&self) -> Option<String> {
        self.tunnel.then(|| {
            format!(
                "127.0.0.1:{}:{}:{}",
                self.guest_port, self.host_addr, self.host_port
            )
        })
    }

    #[must_use]
    pub fn render_pty_shell(&self, target: LlmBootstrapTarget) -> String {
        let claw_type = shell_quote(self.claw_type.as_deref().unwrap_or(""));
        let provider = shell_quote(&self.provider);
        let model = shell_quote(&self.model);
        let api_key = shell_quote(&self.api_key);
        let context_source = shell_quote(&self.context_source);
        let host_addr = shell_quote(&self.host_addr);
        let base_url = shell_quote(&self.base_url);
        let openai_base_url = shell_quote(&self.openai_base_url);
        let openclaw_provider_key = shell_quote(self.openclaw.provider_config_key());
        let openclaw_provider_json = shell_quote(&self.openclaw_provider_json());
        let openclaw_model_ref = shell_quote(self.openclaw.model_ref());
        let hermes_chat_mode = shell_quote(self.chat_modes.hermes());
        let openclaw_chat_mode = shell_quote(self.chat_modes.openclaw());

        let mut shell = String::new();
        if let Some(path_export) = target.path_export() {
            shell.push_str(path_export);
        }

        macro_rules! line {
            ($($arg:tt)*) => {
                writeln!(&mut shell, $($arg)*).expect("writing to a String cannot fail");
            };
        }

        line!("export TERM=xterm-256color LANG=C.UTF-8 COLORTERM=truecolor;");
        line!("export THEYOS_CLAW_TYPE={claw_type};");
        line!("export THEYOS_LLM_CONTRACT_VERSION={CONTRACT_VERSION};");
        line!("export THEYOS_LLM_PROVIDER={provider};");
        line!("export THEYOS_LLM_API_KEY={api_key};");
        line!("export THEYOS_LLM_GUEST_PORT={};", self.guest_port);
        line!("export THEYOS_LLM_HOST_ADDR={host_addr};");
        line!("export THEYOS_LLM_HOST_PORT={};", self.host_port);
        line!("export THEYOS_LLM_MODEL={model};");
        line!("export THEYOS_LLM_CONTEXT_WINDOW={};", self.context_window);
        line!("export THEYOS_LLM_CONTEXT_SOURCE={context_source};");
        line!("export THEYOS_LLM_BASE_URL={base_url};");
        line!("export THEYOS_LLM_NATIVE_BASE_URL=\"$THEYOS_LLM_BASE_URL\";");
        line!("export THEYOS_LLM_OPENAI_BASE_URL={openai_base_url};");
        line!("export THEYOS_OPENCLAW_PROVIDER_KEY={openclaw_provider_key};");
        line!("export THEYOS_OPENCLAW_PROVIDER_JSON={openclaw_provider_json};");
        line!("export THEYOS_OPENCLAW_MODEL_REF={openclaw_model_ref};");
        line!("export THEYOS_HERMES_CHAT_MODE={hermes_chat_mode};");
        line!("export THEYOS_OPENCLAW_CHAT_MODE={openclaw_chat_mode};");

        shell.push_str(BOOTSTRAP_SH);
        shell.push_str(target.login_shell_trailer());
        shell
    }

    fn openclaw_provider_json(&self) -> String {
        let base_url = if self.openclaw.provider_api() == "ollama" {
            &self.base_url
        } else {
            &self.openai_base_url
        };

        json!({
            "baseUrl": base_url,
            "api": self.openclaw.provider_api(),
            "apiKey": self.openclaw.api_key(),
            "models": [{
                "id": self.model,
                "name": self.model,
                "contextWindow": self.openclaw.context_window(),
                "maxTokens": self.openclaw.max_tokens()
            }]
        })
        .to_string()
    }
}

#[must_use]
pub fn normalize_provider_id(provider: &str) -> String {
    match provider.trim().to_ascii_lowercase().as_str() {
        "" => DEFAULT_LLM_PROVIDER.to_string(),
        "ollama" => "ollama".to_string(),
        "llama.cpp" | "llama-cpp" | "llama_cpp" | "llamacpp" => "llamacpp".to_string(),
        "mlx" | "mlx-lm" | "mlx_lm" => "mlx".to_string(),
        // Route-through-the-proxy sentinel. Anything the host wants the
        // proxy to multiplex (cloud APIs, CLI-OAuth subscriptions, future
        // backends) sets provider=proxy on the claw side. The actual
        // upstream is decided by the proxy's active profile on the host.
        "proxy" | "theyos-proxy" => PROXY_PROVIDER_ID.to_string(),
        other => other
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                    ch
                } else {
                    '-'
                }
            })
            .collect(),
    }
}

fn default_provider_port(provider: &str) -> u16 {
    match provider {
        "ollama" => DEFAULT_LLM_PORT,
        "llamacpp" | "mlx" => DEFAULT_OPENAI_COMPAT_PORT,
        // The proxy listens on a dedicated port distinct from any
        // direct-served runtime.
        PROXY_PROVIDER_ID => DEFAULT_LLM_PROXY_PORT,
        _ => DEFAULT_OPENAI_COMPAT_PORT,
    }
}

fn default_provider_model(provider: &str) -> &'static str {
    match provider {
        "ollama" => DEFAULT_LLM_MODEL,
        "llamacpp" => DEFAULT_LLAMACPP_MODEL,
        "mlx" => DEFAULT_MLX_MODEL,
        // The proxy chooses the actual model from its profile; the claw
        // just identifies the endpoint. Use a stable placeholder.
        PROXY_PROVIDER_ID => "default",
        _ => DEFAULT_LLAMACPP_MODEL,
    }
}

fn default_api_key(provider: &str) -> &'static str {
    match provider {
        "ollama" => "ollama-local",
        "llamacpp" => "llamacpp-local",
        "mlx" => "mlx-local",
        // The proxy injects real credentials on the host side; the claw
        // sees a placeholder that satisfies clients which insist on a
        // non-empty key field.
        PROXY_PROVIDER_ID => "theyos-proxy-placeholder",
        _ => "local-llm",
    }
}

fn default_openclaw_api(provider: &str) -> &'static str {
    match provider {
        "ollama" => "ollama",
        _ => "openai-completions",
    }
}

fn host_port_env_keys(provider: &str) -> &'static [&'static str] {
    match provider {
        "ollama" => &["THEYOS_LLM_HOST_PORT", "THEYOS_OLLAMA_HOST_PORT"],
        "llamacpp" => &["THEYOS_LLM_HOST_PORT", "THEYOS_LLAMACPP_HOST_PORT"],
        "mlx" => &["THEYOS_LLM_HOST_PORT", "THEYOS_MLX_HOST_PORT"],
        _ => &["THEYOS_LLM_HOST_PORT"],
    }
}

fn guest_port_env_keys(provider: &str) -> &'static [&'static str] {
    match provider {
        "ollama" => &["THEYOS_LLM_GUEST_PORT", "THEYOS_OLLAMA_GUEST_PORT"],
        "llamacpp" => &["THEYOS_LLM_GUEST_PORT", "THEYOS_LLAMACPP_GUEST_PORT"],
        "mlx" => &["THEYOS_LLM_GUEST_PORT", "THEYOS_MLX_GUEST_PORT"],
        _ => &["THEYOS_LLM_GUEST_PORT"],
    }
}

fn model_env_keys(provider: &str) -> &'static [&'static str] {
    match provider {
        "ollama" => &["THEYOS_LLM_MODEL", "THEYOS_OLLAMA_MODEL"],
        "llamacpp" => &["THEYOS_LLM_MODEL", "THEYOS_LLAMACPP_MODEL"],
        "mlx" => &["THEYOS_LLM_MODEL", "THEYOS_MLX_MODEL"],
        _ => &["THEYOS_LLM_MODEL"],
    }
}

fn resolve_context_window(
    provider: &str,
    model: &str,
    base_url: &str,
    profile: &LlmProfile,
) -> (u32, String) {
    let context_keys = &["THEYOS_LLM_CONTEXT_WINDOW", "THEYOS_OLLAMA_CONTEXT_WINDOW"];
    if let Some(context_window) = env_u32_any_opt_with_profile(context_keys, profile) {
        return (context_window, "env".to_string());
    }

    if env_flag_default_any_with_profile(&["THEYOS_LLM_CONTEXT_AUTO_DETECT"], true, profile)
        && let Some(context_window) = detect_runtime_context_window(provider, model, base_url)
    {
        return (context_window, "runtime".to_string());
    }

    if let Some(context_window) = known_model_context_window(provider, model) {
        return (context_window, "model-profile".to_string());
    }

    (SAFE_FALLBACK_CONTEXT_WINDOW, "safe-fallback".to_string())
}

fn detect_runtime_context_window(provider: &str, model: &str, base_url: &str) -> Option<u32> {
    match provider {
        "ollama" => detect_ollama_context_window(model, base_url),
        "llamacpp" => detect_openai_compatible_context_window(base_url),
        _ => None,
    }
}

fn detect_ollama_context_window(model: &str, base_url: &str) -> Option<u32> {
    let url = format!("{}/api/show", base_url.trim_end_matches('/'));
    let response = ureq::post(&url)
        .timeout(Duration::from_millis(700))
        .send_json(json!({ "model": model }))
        .ok()?;
    let body = response.into_string().ok()?;
    let value: Value = serde_json::from_str(&body).ok()?;
    find_context_value(&value)
}

fn detect_openai_compatible_context_window(base_url: &str) -> Option<u32> {
    let base_url = base_url
        .trim_end_matches('/')
        .strip_suffix("/v1")
        .unwrap_or_else(|| base_url.trim_end_matches('/'));
    let url = format!("{base_url}/props");
    let response = ureq::get(&url)
        .timeout(Duration::from_millis(700))
        .call()
        .ok()?;
    let body = response.into_string().ok()?;
    let value: Value = serde_json::from_str(&body).ok()?;
    find_context_value(&value)
}

fn find_context_value(value: &Value) -> Option<u32> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let key = key.as_str();
                if (matches!(
                    key,
                    "context_length" | "contextWindow" | "context_window" | "n_ctx" | "ctx_size"
                ) || key.ends_with(".context_length"))
                    && let Some(context_window) = value_to_positive_u32(nested)
                {
                    return Some(context_window);
                }
            }
            map.values().find_map(find_context_value)
        }
        Value::Array(values) => values.iter().find_map(find_context_value),
        _ => None,
    }
}

fn value_to_positive_u32(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|raw| u32::try_from(raw).ok())
        .filter(|raw| *raw > 0)
        .or_else(|| {
            value
                .as_str()
                .and_then(|raw| raw.parse::<u32>().ok())
                .filter(|raw| *raw > 0)
        })
}

fn known_model_context_window(provider: &str, model: &str) -> Option<u32> {
    let normalized_model = model.trim().to_ascii_lowercase();
    match provider {
        "ollama" => match normalized_model.as_str() {
            "qwen3.6:35b-a3b-coding-mxfp8" | "qwen3.6:27b" | "qwen3:4b" => Some(262_144),
            "llama3.1" | "llama3.1:8b" | "llama3.1:70b" => Some(131_072),
            _ => None,
        },
        "llamacpp" => {
            if normalized_model.contains("qwen3-coder-30b-a3b-instruct-1m") {
                Some(1_000_000)
            } else if normalized_model.contains("qwen3-coder-30b-a3b-instruct") {
                Some(262_144)
            } else {
                None
            }
        }
        "mlx" => match normalized_model.as_str() {
            "mlx-community/qwen3-4b-instruct-2507-4bit"
            | "mlx-community/mistral-7b-instruct-v0.3-4bit" => Some(32_768),
            "nexveridian/qwen3-coder-30b-a3b-instruct-4bit"
            | "outlier-ai/qwen3-coder-30b-a3b-instruct-mlx-4bit" => Some(262_144),
            _ => None,
        },
        _ => None,
    }
}

fn default_max_tokens(context_window: u32) -> u32 {
    (context_window / 8).clamp(1_024, DEFAULT_OPENCLAW_MAX_TOKENS)
}

#[must_use]
pub fn env_claw_type() -> Option<String> {
    std::env::var("THEYOS_CLAW_TYPE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[must_use]
pub fn infer_claw_type_from_container(container: &str) -> Option<String> {
    const KNOWN_CLAW_TYPES: &[&str] = &[
        "hermes-agent",
        "openclaw",
        "picoclaw",
        "zeroclaw",
        "ironclaw",
        "nanobot",
        "noclaw",
        "nullclaw",
    ];
    KNOWN_CLAW_TYPES
        .iter()
        .find(|claw| container == **claw || container.starts_with(&format!("{claw}-")))
        .map(|claw| (*claw).to_string())
}

#[must_use]
pub fn resolve_macos_claw_type(container: &str) -> Option<String> {
    if container == "mac-host" {
        env_claw_type()
    } else {
        infer_claw_type_from_container(container)
    }
}

#[must_use]
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn llm_profile_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("THEYOS_LLM_PROFILE_PATH") {
        let path = path.trim();
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }

    if let Ok(dir) = std::env::var("THEYOS_DIR") {
        let dir = dir.trim();
        if !dir.is_empty() {
            return Some(PathBuf::from(dir).join(DEFAULT_LLM_PROFILE_FILE));
        }
    }

    std::env::var("HOME")
        .ok()
        .filter(|home| !home.trim().is_empty())
        .map(|home| PathBuf::from(home).join(".theyos/llm-profile.env"))
}

#[cfg(test)]
fn env_port_any(keys: &[&str], default: u16) -> u16 {
    env_port_any_with_profile(keys, default, &LlmProfile::default())
}

fn env_port_any_with_profile(keys: &[&str], default: u16, profile: &LlmProfile) -> u16 {
    let raw = env_raw_any_with_profile(keys, profile);
    parse_port_value(raw.as_deref(), default)
}

fn env_u32_any_with_profile(keys: &[&str], default: u32, profile: &LlmProfile) -> u32 {
    env_u32_any_opt_with_profile(keys, profile).unwrap_or(default)
}

fn env_u32_any_opt_with_profile(keys: &[&str], profile: &LlmProfile) -> Option<u32> {
    env_raw_any_with_profile(keys, profile)
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
}

#[cfg(test)]
fn env_string_any(keys: &[&str], default: &str) -> String {
    env_string_any_with_profile(keys, default, &LlmProfile::default())
}

fn env_string_any_with_profile(keys: &[&str], default: &str, profile: &LlmProfile) -> String {
    env_raw_any_with_profile(keys, profile).unwrap_or_else(|| default.to_string())
}

fn env_raw_any_with_profile(keys: &[&str], profile: &LlmProfile) -> Option<String> {
    keys.iter()
        .filter_map(|key| std::env::var(key).ok())
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
        .or_else(|| profile.get_any(keys))
}

fn parse_port_value(raw: Option<&str>, default: u16) -> u16 {
    raw.and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(default)
}

fn env_flag_default_any_with_profile(keys: &[&str], default: bool, profile: &LlmProfile) -> bool {
    let Some(raw) = env_raw_any_with_profile(keys, profile) else {
        return default;
    };
    parse_flag_value(&raw, default)
}

fn parse_flag_value(raw: &str, default: bool) -> bool {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[allow(unsafe_code)]
    fn set_test_env_var(key: &str, value: &str) {
        // SAFETY: test-only helper; callers restore previous values.
        unsafe { std::env::set_var(key, value) };
    }

    #[allow(unsafe_code)]
    fn remove_test_env_var(key: &str) {
        // SAFETY: test-only helper; callers restore previous values.
        unsafe { std::env::remove_var(key) };
    }

    fn write_mock_bin(dir: &Path, name: &str, script: &str) {
        let path = dir.join(name);
        fs::write(&path, script).expect("write mock binary");
        let mut perms = fs::metadata(&path).expect("mock metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("chmod mock binary");
    }

    fn log_script(name: &str, log_path: &Path, extra: &str) -> String {
        format!(
            "#!/bin/sh\nprintf '{name} %s\\n' \"$*\" >> {}\n{extra}\nexit 0\n",
            shell_quote(log_path.to_str().expect("utf8 log path")),
        )
    }

    #[test]
    fn infer_known_hyphenated_claw_type() {
        assert_eq!(
            infer_claw_type_from_container("hermes-agent-hermes-agent"),
            Some("hermes-agent".to_string())
        );
        assert_eq!(
            infer_claw_type_from_container("openclaw-openclaw"),
            Some("openclaw".to_string())
        );
    }

    #[test]
    fn parse_helpers_handle_invalid_values() {
        assert_eq!(parse_port_value(Some("11435"), DEFAULT_LLM_PORT), 11_435);
        assert_eq!(
            parse_port_value(Some("0"), DEFAULT_LLM_PORT),
            DEFAULT_LLM_PORT
        );
        assert_eq!(
            parse_port_value(Some("not-a-port"), DEFAULT_LLM_PORT),
            DEFAULT_LLM_PORT
        );
        assert!(parse_flag_value("1", false));
        assert!(parse_flag_value("yes", false));
        assert!(!parse_flag_value("0", true));
        assert!(!parse_flag_value("off", true));
        assert!(parse_flag_value("unknown", true));
        assert!(!parse_flag_value("unknown", false));
    }

    #[test]
    fn from_env_prefers_first_present_aliases() {
        let first_port_prev = std::env::var("THEYOS_TEST_FIRST_PORT").ok();
        let second_port_prev = std::env::var("THEYOS_TEST_SECOND_PORT").ok();
        let first_host_prev = std::env::var("THEYOS_TEST_FIRST_HOST").ok();
        let second_host_prev = std::env::var("THEYOS_TEST_SECOND_HOST").ok();

        set_test_env_var("THEYOS_TEST_FIRST_PORT", "12000");
        set_test_env_var("THEYOS_TEST_SECOND_PORT", "13000");
        assert_eq!(
            env_port_any(
                &["THEYOS_TEST_FIRST_PORT", "THEYOS_TEST_SECOND_PORT"],
                DEFAULT_LLM_PORT
            ),
            12_000
        );

        set_test_env_var("THEYOS_TEST_FIRST_HOST", "   ");
        set_test_env_var("THEYOS_TEST_SECOND_HOST", "bignix");
        assert_eq!(
            env_string_any(
                &["THEYOS_TEST_FIRST_HOST", "THEYOS_TEST_SECOND_HOST"],
                DEFAULT_LLM_HOST_ADDR
            ),
            "bignix"
        );

        match first_port_prev {
            Some(value) => set_test_env_var("THEYOS_TEST_FIRST_PORT", &value),
            None => remove_test_env_var("THEYOS_TEST_FIRST_PORT"),
        }
        match second_port_prev {
            Some(value) => set_test_env_var("THEYOS_TEST_SECOND_PORT", &value),
            None => remove_test_env_var("THEYOS_TEST_SECOND_PORT"),
        }
        match first_host_prev {
            Some(value) => set_test_env_var("THEYOS_TEST_FIRST_HOST", &value),
            None => remove_test_env_var("THEYOS_TEST_FIRST_HOST"),
        }
        match second_host_prev {
            Some(value) => set_test_env_var("THEYOS_TEST_SECOND_HOST", &value),
            None => remove_test_env_var("THEYOS_TEST_SECOND_HOST"),
        }
    }

    #[test]
    fn from_env_uses_platform_defaults_and_chat_mode_overrides() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let hermes_prev = std::env::var("THEYOS_HERMES_CHAT_MODE").ok();
        let openclaw_prev = std::env::var("THEYOS_OPENCLAW_CHAT_MODE").ok();
        let autodetect_prev = std::env::var("THEYOS_LLM_CONTEXT_AUTO_DETECT").ok();
        let profile_prev = std::env::var("THEYOS_LLM_PROFILE_PATH").ok();

        remove_test_env_var("THEYOS_HERMES_CHAT_MODE");
        remove_test_env_var("THEYOS_OPENCLAW_CHAT_MODE");
        set_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT", "0");
        set_test_env_var(
            "THEYOS_LLM_PROFILE_PATH",
            temp.path()
                .join("missing-profile.env")
                .to_str()
                .expect("utf8 profile path"),
        );
        let mac = LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
        assert_eq!(mac.chat_modes().hermes(), "chat");
        assert_eq!(mac.chat_modes().openclaw(), "local");
        let linux = LlmContract::from_env(
            Some("openclaw".to_string()),
            LlmBootstrapTarget::LinuxFirecracker,
        );
        assert_eq!(linux.chat_modes().hermes(), "chat");
        assert_eq!(linux.chat_modes().openclaw(), "gateway");

        set_test_env_var("THEYOS_HERMES_CHAT_MODE", "tui");
        set_test_env_var("THEYOS_OPENCLAW_CHAT_MODE", "gateway");
        let overridden =
            LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
        assert_eq!(overridden.chat_modes().hermes(), "tui");
        assert_eq!(overridden.chat_modes().openclaw(), "gateway");

        match hermes_prev {
            Some(value) => set_test_env_var("THEYOS_HERMES_CHAT_MODE", &value),
            None => remove_test_env_var("THEYOS_HERMES_CHAT_MODE"),
        }
        match openclaw_prev {
            Some(value) => set_test_env_var("THEYOS_OPENCLAW_CHAT_MODE", &value),
            None => remove_test_env_var("THEYOS_OPENCLAW_CHAT_MODE"),
        }
        match autodetect_prev {
            Some(value) => set_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT", &value),
            None => remove_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT"),
        }
        match profile_prev {
            Some(value) => set_test_env_var("THEYOS_LLM_PROFILE_PATH", &value),
            None => remove_test_env_var("THEYOS_LLM_PROFILE_PATH"),
        }
    }

    #[test]
    fn provider_profiles_pick_user_friendly_defaults() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let provider_prev = std::env::var("THEYOS_LLM_PROVIDER").ok();
        let autodetect_prev = std::env::var("THEYOS_LLM_CONTEXT_AUTO_DETECT").ok();
        let context_prev = std::env::var("THEYOS_LLM_CONTEXT_WINDOW").ok();
        let profile_prev = std::env::var("THEYOS_LLM_PROFILE_PATH").ok();

        set_test_env_var("THEYOS_LLM_PROVIDER", "llama.cpp");
        set_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT", "0");
        remove_test_env_var("THEYOS_LLM_CONTEXT_WINDOW");
        set_test_env_var(
            "THEYOS_LLM_PROFILE_PATH",
            temp.path()
                .join("missing-profile.env")
                .to_str()
                .expect("utf8 profile path"),
        );
        let llamacpp =
            LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
        assert_eq!(llamacpp.provider(), "llamacpp");
        assert_eq!(llamacpp.model(), "local");
        assert_eq!(llamacpp.host_port(), DEFAULT_OPENAI_COMPAT_PORT);
        assert_eq!(llamacpp.context_window(), SAFE_FALLBACK_CONTEXT_WINDOW);
        assert_eq!(llamacpp.context_source(), "safe-fallback");

        set_test_env_var("THEYOS_LLM_PROVIDER", "mlx-lm");
        let mlx = LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
        assert_eq!(mlx.provider(), "mlx");
        assert_eq!(mlx.model(), DEFAULT_MLX_MODEL);
        assert_eq!(mlx.host_port(), DEFAULT_OPENAI_COMPAT_PORT);
        assert_eq!(mlx.context_window(), 32_768);
        assert_eq!(mlx.context_source(), "model-profile");

        // The "proxy" sentinel routes through the host-side multiplexer.
        // Default port is the proxy port (NOT a runtime-native port), the
        // API key is a placeholder — real auth happens host-side — and
        // the OpenAI base URL is stamped with the claw type so the proxy
        // can apply per-claw overrides.
        set_test_env_var("THEYOS_LLM_PROVIDER", "proxy");
        let proxy =
            LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
        assert_eq!(proxy.provider(), PROXY_PROVIDER_ID);
        assert_eq!(proxy.host_port(), DEFAULT_LLM_PROXY_PORT);
        assert_eq!(proxy.api_key(), "theyos-proxy-placeholder");
        assert_eq!(
            proxy.openai_base_url(),
            "http://127.0.0.1:18900/v1/c/openclaw",
            "proxy openai base url should stamp claw type for per-claw routing",
        );

        // No claw type → no claw stamp; falls through to the global default.
        let proxy_no_claw = LlmContract::from_env(None, LlmBootstrapTarget::MacosVz);
        assert_eq!(proxy_no_claw.provider(), PROXY_PROVIDER_ID);
        assert_eq!(proxy_no_claw.openai_base_url(), "http://127.0.0.1:18900/v1");

        match provider_prev {
            Some(value) => set_test_env_var("THEYOS_LLM_PROVIDER", &value),
            None => remove_test_env_var("THEYOS_LLM_PROVIDER"),
        }
        match autodetect_prev {
            Some(value) => set_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT", &value),
            None => remove_test_env_var("THEYOS_LLM_CONTEXT_AUTO_DETECT"),
        }
        match context_prev {
            Some(value) => set_test_env_var("THEYOS_LLM_CONTEXT_WINDOW", &value),
            None => remove_test_env_var("THEYOS_LLM_CONTEXT_WINDOW"),
        }
        match profile_prev {
            Some(value) => set_test_env_var("THEYOS_LLM_PROFILE_PATH", &value),
            None => remove_test_env_var("THEYOS_LLM_PROFILE_PATH"),
        }
    }

    #[test]
    fn from_env_reads_persisted_llm_profile_file() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let profile_path = temp.path().join("llm-profile.env");
        fs::write(
            &profile_path,
            "THEYOS_LLM_PROVIDER=llama.cpp\n\
             THEYOS_LLM_MODEL=local64\n\
             THEYOS_LLM_HOST_PORT=18082\n\
             THEYOS_LLM_GUEST_PORT=18082\n\
             THEYOS_LLM_CONTEXT_WINDOW=65536\n\
             THEYOS_OPENCLAW_MODEL_REF=llamacpp/local64\n",
        )
        .expect("write profile");

        let keys = [
            "THEYOS_LLM_PROFILE_PATH",
            "THEYOS_LLM_PROVIDER",
            "THEYOS_LLM_MODEL",
            "THEYOS_LLM_HOST_PORT",
            "THEYOS_LLM_GUEST_PORT",
            "THEYOS_LLM_CONTEXT_WINDOW",
            "THEYOS_OPENCLAW_MODEL_REF",
        ];
        let previous: Vec<_> = keys
            .iter()
            .map(|key| (*key, std::env::var(key).ok()))
            .collect();

        for key in keys {
            remove_test_env_var(key);
        }
        set_test_env_var(
            "THEYOS_LLM_PROFILE_PATH",
            profile_path.to_str().expect("utf8 profile path"),
        );

        let contract =
            LlmContract::from_env(Some("openclaw".to_string()), LlmBootstrapTarget::MacosVz);
        assert_eq!(contract.provider(), "llamacpp");
        assert_eq!(contract.model(), "local64");
        assert_eq!(contract.host_port(), 18_082);
        assert_eq!(contract.guest_port(), 18_082);
        assert_eq!(contract.context_window(), 65_536);
        assert_eq!(contract.context_source(), "env");
        assert_eq!(contract.openclaw().model_ref(), "llamacpp/local64");

        for (key, value) in previous {
            match value {
                Some(value) => set_test_env_var(key, &value),
                None => remove_test_env_var(key),
            }
        }
    }

    #[test]
    fn openclaw_uses_openai_compatible_api_for_llamacpp_and_mlx() {
        let llamacpp = LlmContract::for_tests("openclaw", LlmBootstrapTarget::MacosVz)
            .with_provider("llama.cpp")
            .with_model("local")
            .with_guest_port(DEFAULT_OPENAI_COMPAT_PORT);
        let shell = llamacpp.render_pty_shell(LlmBootstrapTarget::MacosVz);
        assert!(shell.contains("export THEYOS_LLM_PROVIDER='llamacpp';"));
        assert!(shell.contains("export THEYOS_LLM_BASE_URL='http://127.0.0.1:8080';"));
        assert!(shell.contains("export THEYOS_LLM_OPENAI_BASE_URL='http://127.0.0.1:8080/v1';"));
        assert!(shell.contains("export THEYOS_OPENCLAW_PROVIDER_KEY='models.providers.llamacpp';"));
        assert!(shell.contains("export THEYOS_OPENCLAW_MODEL_REF='llamacpp/local';"));
        assert!(shell.contains(r#""api":"openai-completions""#));
        assert!(shell.contains(r#""baseUrl":"http://127.0.0.1:8080/v1""#));
    }

    #[test]
    fn proxy_render_pty_shell_stamps_per_claw_url_and_reverse_tunnel() {
        // Slice C regression guard: when provider=proxy, the rendered
        // shell that fc-ssh injects on PTY launch MUST set
        // THEYOS_LLM_OPENAI_BASE_URL to the per-claw routing URL, AND
        // ssh_reverse_forward MUST return a spec mapping guest:18900 →
        // host:18900. If either drifts, claws stop reaching the
        // host-side multiplexer and "production PTY path" validation
        // (docs/llm-proxy.md) silently breaks.
        let _guard = ENV_LOCK.lock().expect("env lock");
        let provider_prev = std::env::var("THEYOS_LLM_PROVIDER").ok();
        let model_prev = std::env::var("THEYOS_LLM_MODEL").ok();
        set_test_env_var("THEYOS_LLM_PROVIDER", "proxy");
        set_test_env_var("THEYOS_LLM_MODEL", "glm-4.6");

        let contract = LlmContract::from_env(
            Some("hermes-agent".to_string()),
            LlmBootstrapTarget::LinuxFirecracker,
        );

        let shell = contract.render_pty_shell(LlmBootstrapTarget::LinuxFirecracker);
        assert!(
            shell.contains("export THEYOS_LLM_PROVIDER='proxy';"),
            "render_pty_shell must emit provider=proxy:\n{shell}",
        );
        assert!(
            shell.contains("export THEYOS_LLM_MODEL='glm-4.6';"),
            "render_pty_shell must emit model:\n{shell}",
        );
        assert!(
            shell.contains(
                "export THEYOS_LLM_OPENAI_BASE_URL='http://127.0.0.1:18900/v1/c/hermes-agent';"
            ),
            "render_pty_shell must stamp the per-claw routing URL for proxy provider:\n{shell}",
        );

        let forward = contract
            .ssh_reverse_forward()
            .expect("tunnel must be on by default");
        assert_eq!(
            forward, "127.0.0.1:18900:127.0.0.1:18900",
            "reverse tunnel must map guest:18900 → host loopback:18900",
        );

        match provider_prev {
            Some(v) => set_test_env_var("THEYOS_LLM_PROVIDER", &v),
            None => remove_test_env_var("THEYOS_LLM_PROVIDER"),
        }
        match model_prev {
            Some(v) => set_test_env_var("THEYOS_LLM_MODEL", &v),
            None => remove_test_env_var("THEYOS_LLM_MODEL"),
        }
    }

    #[test]
    fn proxy_render_pty_shell_without_claw_falls_back_to_default_v1() {
        // Mirror of the openai_base_url default branch (no claw stamp):
        // /v1 only, no per-claw segment. Exercises the `else` branch in
        // claw_llm.rs around line 297-304.
        let _guard = ENV_LOCK.lock().expect("env lock");
        let provider_prev = std::env::var("THEYOS_LLM_PROVIDER").ok();
        set_test_env_var("THEYOS_LLM_PROVIDER", "proxy");

        let contract = LlmContract::from_env(None, LlmBootstrapTarget::LinuxFirecracker);
        let shell = contract.render_pty_shell(LlmBootstrapTarget::LinuxFirecracker);
        assert!(
            shell.contains("export THEYOS_LLM_OPENAI_BASE_URL='http://127.0.0.1:18900/v1';"),
            "no-claw render must fall back to /v1 (default route):\n{shell}",
        );

        match provider_prev {
            Some(v) => set_test_env_var("THEYOS_LLM_PROVIDER", &v),
            None => remove_test_env_var("THEYOS_LLM_PROVIDER"),
        }
    }

    #[test]
    fn reverse_forward_respects_tunnel_flag() {
        let contract = LlmContract::for_tests("openclaw", LlmBootstrapTarget::LinuxFirecracker)
            .with_host_addr("bignix")
            .with_guest_port(11_435);
        assert_eq!(
            contract.ssh_reverse_forward(),
            Some("127.0.0.1:11435:bignix:11434".to_string())
        );
        assert_eq!(contract.with_tunnel(false).ssh_reverse_forward(), None);
    }

    #[test]
    fn render_shell_uses_contract_chat_modes_not_platform_modes() {
        let contract = LlmContract::for_tests("openclaw", LlmBootstrapTarget::LinuxFirecracker)
            .with_model("qwen3.6:27b")
            .with_chat_modes(ClawChatModes::new("chat", "local"));

        let linux = contract.render_pty_shell(LlmBootstrapTarget::LinuxFirecracker);
        assert!(!linux.contains("export PATH=/opt/homebrew/bin"));
        assert!(linux.contains("export THEYOS_OPENCLAW_CHAT_MODE='local';"));
        assert!(linux.contains("export THEYOS_HERMES_CHAT_MODE='chat';"));
        assert!(linux.contains("theyos_openclaw_tui_local"));
        assert!(linux.contains(r#"hermes chat -m "$THEYOS_LLM_MODEL""#));
        assert!(linux.contains("export THEYOS_OPENCLAW_MODEL_REF='ollama/qwen3.6:27b';"));
        assert!(!linux.contains(r#"model_ref="ollama/$THEYOS_LLM_MODEL""#));

        let mac = contract.render_pty_shell(LlmBootstrapTarget::MacosVz);
        assert!(mac.contains("export PATH=/opt/homebrew/bin"));
    }

    #[test]
    fn rendered_shell_is_posix_shell_parseable() {
        let command = LlmContract::for_tests("openclaw", LlmBootstrapTarget::MacosVz)
            .render_pty_shell(LlmBootstrapTarget::MacosVz);

        let mut child = Command::new("sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn sh -n");
        child
            .stdin
            .as_mut()
            .expect("sh stdin")
            .write_all(command.as_bytes())
            .expect("write generated shell command");
        let status = child.wait().expect("wait for sh -n");
        assert!(status.success(), "generated PTY shell command failed sh -n");
    }

    #[test]
    fn rendered_bootstrap_executes_openclaw_with_mocked_cli() {
        let temp = tempfile::tempdir().expect("tempdir");
        let log = temp.path().join("calls.log");
        write_mock_bin(
            temp.path(),
            "openclaw",
            &log_script(
                "openclaw",
                &log,
                r#"if [ "$1" = "gateway" ] && [ "$2" = "health" ]; then exit 0; fi"#,
            ),
        );
        write_mock_bin(temp.path(), "bash", &log_script("bash", &log, ""));
        // Mock `nc` so the bootstrap's `theyos_openclaw_gateway_port_open`
        // sees the gateway as live. On dev hosts something is listening on
        // 18789 from prior sessions; CI runners are clean, so the real
        // `nc -z 127.0.0.1 18789` fails and the bootstrap drops into the
        // 60-iter wait loop — which never calls `openclaw gateway health`,
        // failing this test's argv assertion. A 1-line `exit 0` mock pins
        // the success path.
        write_mock_bin(temp.path(), "nc", "#!/bin/sh\nexit 0\n");

        let command = LlmContract::for_tests("openclaw", LlmBootstrapTarget::LinuxFirecracker)
            .with_model("qwen3.6:27b")
            .with_chat_modes(ClawChatModes::new("tui", "local"))
            .render_pty_shell(LlmBootstrapTarget::LinuxFirecracker);
        let path = format!("{}:/bin:/usr/bin", temp.path().display());

        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("PATH", path)
            .env("HOME", temp.path())
            .output()
            .expect("execute rendered shell");
        assert!(
            output.status.success(),
            "rendered shell failed: status={:?}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        let calls = fs::read_to_string(&log).expect("read mock log");
        assert!(calls.contains("openclaw config set models.mode merge"));
        assert!(calls.contains("openclaw config set models.providers.ollama"));
        assert!(
            calls.contains("openclaw config set agents.defaults.model.primary ollama/qwen3.6:27b")
        );
        assert!(calls.contains("openclaw tui --help"));
        assert!(
            calls.contains(
                "openclaw gateway health --url ws://127.0.0.1:18789 --token theyos-local"
            )
        );
        assert!(calls.contains(
            "openclaw tui --url ws://127.0.0.1:18789 --token theyos-local --timeout-ms 180000"
        ));
        assert!(calls.contains("bash -l -i"));
    }

    #[test]
    fn rendered_bootstrap_executes_hermes_with_mocked_cli() {
        let temp = tempfile::tempdir().expect("tempdir");
        let log = temp.path().join("calls.log");
        write_mock_bin(temp.path(), "hermes", &log_script("hermes", &log, ""));
        write_mock_bin(temp.path(), "bash", &log_script("bash", &log, ""));

        let command = LlmContract::for_tests("hermes-agent", LlmBootstrapTarget::LinuxFirecracker)
            .with_chat_modes(ClawChatModes::new("tui", "gateway"))
            .render_pty_shell(LlmBootstrapTarget::LinuxFirecracker);
        let path = format!("{}:/bin:/usr/bin", temp.path().display());

        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("PATH", path)
            .env("HOME", temp.path())
            .output()
            .expect("execute rendered shell");
        assert!(
            output.status.success(),
            "rendered shell failed: status={:?}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        let calls = fs::read_to_string(&log).expect("read mock log");
        assert!(calls.contains("hermes config set model.provider custom"));
        assert!(calls.contains("hermes config set model.base_url http://127.0.0.1:11434/v1"));
        assert!(calls.contains("hermes --help"));
        assert!(calls.contains("hermes chat -m llama3.1"));
        assert!(calls.contains("bash -l -i"));
    }
}
