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
mod tests;
