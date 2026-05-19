//! Profile schema + TOML storage for the LLM proxy.
//!
//! A profile file describes:
//!
//! 1. **Which providers exist** (`[providers.<id>]` tables) — their base URL,
//!    upstream kind, optional credential handle.
//! 2. **Which provider+model is active** (`[active]` table) — the default
//!    that incoming requests resolve to when no per-claw override applies.
//!
//! Layout on disk:
//!
//! - `$THEYOS_LLM_PROFILE_DIR/default.toml` — the global profile
//! - `$THEYOS_LLM_PROFILE_DIR/<claw-type>.toml` — per-claw override
//!
//! A per-claw file only needs to set `[active]`; the `[providers.*]` tables
//! are inherited from `default.toml`. This is the slice that lets one host
//! point `openclaw` at Anthropic while `hermes-agent` uses GLM, etc.
//!
//! Slice 1 ships only `default.toml` loading; per-claw merge lands in Slice 2.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::ProxyError;

/// Top-level profile document. See module-level docs for the on-disk layout.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileDoc {
    /// Currently selected provider+model. Absent on first-run profiles.
    #[serde(default)]
    pub active: Option<ActiveProfile>,

    /// Configured providers keyed by id.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProfile {
    /// Provider id that must exist in `providers`.
    pub provider: String,
    /// Model identifier the provider understands (e.g. `qwen3:4b`,
    /// `claude-opus-4-7`, `glm-5.1`).
    pub model: String,
}

/// Provider-specific config. The `kind` field decides which backend
/// implementation handles requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Backend kind. See [`ProviderKind`].
    pub kind: ProviderKind,
    /// Upstream base URL. For `openai-compat` it's the root that ends right
    /// before `/chat/completions` (the proxy appends that path itself).
    /// For `cli-oauth` backends this is empty — the CLI binary is the
    /// upstream, see `cli_binary_path`.
    #[serde(default)]
    pub base_url: String,
    /// Optional keystore account label holding the API key. When unset, the
    /// proxy forwards without an Authorization header (local providers).
    #[serde(default)]
    pub credential_account: Option<String>,
    /// Catalog of models the provider exposes. Used by `/v1/models`.
    #[serde(default)]
    pub models: Vec<String>,
    /// For `cli-oauth` backends: absolute path to the CLI binary
    /// (`/usr/local/bin/claude`, etc.). When unset, the backend looks up
    /// the binary by its conventional name in `$PATH`.
    #[serde(default)]
    pub cli_binary_path: Option<String>,
    /// For `cli-oauth` backends: per-request subprocess timeout in
    /// seconds. Defaults to 180s (long enough for reasoning models).
    #[serde(default)]
    pub cli_timeout_secs: Option<u64>,
    /// For `cli-oauth` backends: which CLI's invocation contract to use.
    /// Defaults to [`CliFlavor::Claude`] (preserves the v1.0 behaviour
    /// where only `claude-cli` existed). When the operator adds a new
    /// CLI provider via the admin API, the catalog's `cli_flavor` field
    /// populates this so the proxy knows how to spawn the right binary
    /// with the right argv shape.
    #[serde(default)]
    pub cli_flavor: CliFlavor,
}

/// Which CLI subprocess flavor a provider uses. Each variant maps to a
/// specific binary + argv pattern + model alias rules. New CLIs land
/// here as additional variants once we've verified their non-
/// interactive invocation contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CliFlavor {
    /// `claude -p --model <alias> <prompt>`. The default for back-compat
    /// with the v1.0 `ClaudeCliProvider`.
    #[default]
    Claude,
    /// `codex exec -m <model> <prompt>`. OpenAI's Codex CLI (used with a
    /// ChatGPT coding plan or API key).
    Codex,
    /// `gemini --model <model> --prompt <prompt>`. Google's Gemini CLI.
    /// The binary is `gemini` (not yet packaged in nixpkgs as of
    /// 2026-05; operators install it manually).
    Gemini,
    /// `opencode run <message>`. The opencode TUI also has a
    /// non-interactive `run` subcommand.
    Opencode,
}

/// Backend implementation that handles a provider. Slice 1 ships only
/// [`ProviderKind::OpenaiCompat`]; the others slot in later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKind {
    /// Forward `POST /v1/chat/completions` to an OpenAI-compatible base URL.
    /// Covers `ollama`, `llama.cpp`, `mlx`, OpenAI itself, GLM, DeepSeek, Kimi
    /// coding, Groq, Mistral, Together, OpenRouter, etc.
    OpenaiCompat,

    /// Anthropic-shape `/v1/messages` upstream. Translation lives in
    /// `provider::anthropic_api` (Slice 4).
    AnthropicApi,

    /// Subprocess-invoked CLI tool (`claude -p`, `codex chat`, `gemini chat`).
    /// Slice 3-6.
    CliOauth,
}

impl ProfileDoc {
    /// Load `default.toml` from `profile_dir`. Returns `Default::default()`
    /// when the file is missing — first boot is a non-error.
    pub fn load_default(profile_dir: &Path) -> Result<Self, ProxyError> {
        let path = profile_dir.join("default.toml");
        match fs::read_to_string(&path) {
            Ok(raw) => toml::from_str(&raw).map_err(|e| ProxyError::Profile {
                path: path.display().to_string(),
                kind: format!("parse: {e}"),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(ProxyError::Profile {
                path: path.display().to_string(),
                kind: format!("read: {e}"),
            }),
        }
    }

    /// Scan `profile_dir` for `<claw-type>.toml` overlay files and return
    /// a map of `claw_type → ActiveProfile`. Each overlay file is read for
    /// its `[active]` section only — providers stay defined in
    /// `default.toml`.
    ///
    /// Files without `[active]` are ignored (logged at debug). Filenames
    /// that collide with reserved names (`default`) are ignored to avoid
    /// surprising behaviour.
    pub fn load_per_claw_overlays(
        profile_dir: &Path,
    ) -> Result<std::collections::HashMap<String, ActiveProfile>, ProxyError> {
        let mut out = std::collections::HashMap::new();
        let entries = match fs::read_dir(profile_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => {
                return Err(ProxyError::Profile {
                    path: profile_dir.display().to_string(),
                    kind: format!("readdir: {e}"),
                });
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if stem == "default" {
                continue;
            }
            let raw = match fs::read_to_string(&path) {
                Ok(r) => r,
                Err(e) => {
                    return Err(ProxyError::Profile {
                        path: path.display().to_string(),
                        kind: format!("read: {e}"),
                    });
                }
            };
            let parsed: Self = toml::from_str(&raw).map_err(|e| ProxyError::Profile {
                path: path.display().to_string(),
                kind: format!("parse: {e}"),
            })?;
            if let Some(active) = parsed.active {
                out.insert(stem.to_string(), active);
            } else {
                tracing::debug!(
                    path = %path.display(),
                    claw_type = stem,
                    "overlay file has no [active] section, skipping"
                );
            }
        }
        Ok(out)
    }

    /// Persist back to `default.toml` with atomic rename. Creates the
    /// directory if missing. Overwrites an existing file.
    pub fn save_default(&self, profile_dir: &Path) -> Result<(), ProxyError> {
        let path = profile_dir.join("default.toml");
        self.save_to(&path)
    }

    /// Write `default.toml` ONLY if the file does not yet exist
    /// (first-boot stub). The atomic O_EXCL on the tmp file is purely
    /// defensive — the real safety net is the explicit existence check
    /// here, because the rename step does NOT use `renameat2(NOREPLACE)`
    /// (Linux 3.15+ only) on most distros. The exists-check loses a race
    /// with a parallel writer but that is harmless: both writers would
    /// land the same first-run content.
    ///
    /// This is the entry point the binary uses on first boot so that a
    /// service restart while the operator is editing `default.toml`
    /// cannot truncate their changes.
    pub fn save_default_if_absent(&self, profile_dir: &Path) -> Result<(), ProxyError> {
        let path = profile_dir.join("default.toml");
        if path.exists() {
            return Ok(());
        }
        self.save_to(&path)
    }

    fn save_to(&self, path: &Path) -> Result<(), ProxyError> {
        use std::io::Write;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| ProxyError::Profile {
                path: parent.display().to_string(),
                kind: format!("mkdir: {e}"),
            })?;
        }
        let raw = toml::to_string_pretty(self).map_err(|e| ProxyError::Profile {
            path: path.display().to_string(),
            kind: format!("serialize: {e}"),
        })?;
        // Atomic write: tmp file → fsync → rename → fsync parent.
        // Mirrors `keystore_rs::file_backend::write_0600` so a crash or
        // power loss between any two steps cannot produce a zero-byte
        // `default.toml` — which would otherwise cause the daemon to
        // refuse to start (NoProvider) on next boot.
        let tmp = path.with_extension("toml.tmp");
        // Best-effort cleanup of a stale tmp from a previous crash.
        match fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(ProxyError::Profile {
                    path: tmp.display().to_string(),
                    kind: format!("remove stale tmp: {e}"),
                });
            }
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| ProxyError::Profile {
                path: tmp.display().to_string(),
                kind: format!("open tmp: {e}"),
            })?;
        if let Err(e) = file.write_all(raw.as_bytes()) {
            drop(file);
            let _ = fs::remove_file(&tmp);
            return Err(ProxyError::Profile {
                path: tmp.display().to_string(),
                kind: format!("write: {e}"),
            });
        }
        if let Err(e) = file.sync_all() {
            drop(file);
            let _ = fs::remove_file(&tmp);
            return Err(ProxyError::Profile {
                path: tmp.display().to_string(),
                kind: format!("fsync: {e}"),
            });
        }
        drop(file);
        fs::rename(&tmp, path).map_err(|e| ProxyError::Profile {
            path: path.display().to_string(),
            kind: format!("rename: {e}"),
        })?;
        // Fsync the parent directory so the rename is durable across
        // power loss. Best-effort — on filesystems that don't honour
        // directory fsync this is a no-op but never errors.
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::OpenOptions::new().read(true).open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Atomically update the `[active]` block of `default.toml` while
    /// preserving everything else in the file (provider entries, comments
    /// can't be preserved because TOML doesn't round-trip comments through
    /// serde — but provider tables are kept verbatim). Reads → mutates →
    /// writes via `save_to`'s atomic rename.
    pub fn update_default_active(
        profile_dir: &Path,
        new_active: &ActiveProfile,
    ) -> Result<(), ProxyError> {
        let path = profile_dir.join("default.toml");
        let mut doc = Self::load_default(profile_dir)?;
        doc.active = Some(new_active.clone());
        doc.save_to(&path)
    }

    /// Insert or replace a `[providers.<id>]` block in `default.toml`,
    /// preserving the rest of the file. Returns the loaded document so
    /// callers (the admin endpoint) can immediately rebuild the runtime
    /// provider registry from the same state that's on disk.
    ///
    /// Caller is responsible for serialising mutations through the
    /// proxy's `profile_io_lock` — this function does NOT take its own
    /// lock because the runtime layer is what owns the lock and we want
    /// to keep the lock-vs-disk responsibility in one place.
    pub fn upsert_provider(
        profile_dir: &Path,
        id: &str,
        cfg: ProviderConfig,
    ) -> Result<Self, ProxyError> {
        let path = profile_dir.join("default.toml");
        let mut doc = Self::load_default(profile_dir)?;
        doc.providers.insert(id.to_string(), cfg);
        doc.save_to(&path)?;
        Ok(doc)
    }

    /// Remove a `[providers.<id>]` block from `default.toml` and persist.
    /// Returns the loaded document for the same rebuild-from-state
    /// reason as `upsert_provider`. Returns `Profile { not_found }` when
    /// the id was not configured to begin with — callers should treat
    /// this as 404, not 500.
    pub fn delete_provider(profile_dir: &Path, id: &str) -> Result<Self, ProxyError> {
        let path = profile_dir.join("default.toml");
        let mut doc = Self::load_default(profile_dir)?;
        if doc.providers.remove(id).is_none() {
            return Err(ProxyError::Profile {
                path: path.display().to_string(),
                kind: format!("provider {id:?} not configured"),
            });
        }
        // Also clear the active block if it referenced the deleted
        // provider — otherwise the next request would 503 with
        // `proxy.no_provider`. Leaving active orphaned is a footgun.
        if doc
            .active
            .as_ref()
            .is_some_and(|a| a.provider == id)
        {
            doc.active = None;
        }
        doc.save_to(&path)?;
        Ok(doc)
    }

    /// Atomically write a per-claw overlay file at
    /// `<profile_dir>/<claw_type>.toml`. Overlays only carry an `[active]`
    /// block; provider tables live in the global default. If a file
    /// already exists it is overwritten atomically.
    pub fn write_per_claw_overlay(
        profile_dir: &Path,
        claw_type: &str,
        new_active: &ActiveProfile,
    ) -> Result<(), ProxyError> {
        let path = profile_dir.join(format!("{claw_type}.toml"));
        let doc = ProfileDoc {
            active: Some(new_active.clone()),
            providers: BTreeMap::new(),
        };
        doc.save_to(&path)
    }

    /// Resolve the active provider config + model. Returns `Err` when the
    /// profile has no `[active]` section, or when active references an
    /// unknown provider id.
    pub fn active_provider(&self) -> Result<(&str, &ProviderConfig, &str), ProxyError> {
        let active = self
            .active
            .as_ref()
            .ok_or_else(|| ProxyError::NoProvider(String::new()))?;
        let provider = self.providers.get(&active.provider).ok_or_else(|| {
            ProxyError::UnknownProvider {
                provider: active.provider.clone(),
                hint: format!(
                    "profile has no [providers.{}] table; configure it via the admin API",
                    active.provider,
                ),
            }
        })?;
        Ok((&active.provider, provider, &active.model))
    }
}

/// Build a sensible first-run profile pointed at a local ollama on the
/// conventional port. Saved on first boot so operators see something
/// reasonable when they open the admin UI.
#[must_use]
pub fn first_run_profile() -> ProfileDoc {
    let mut providers = BTreeMap::new();
    providers.insert(
        "ollama".to_string(),
        ProviderConfig {
            kind: ProviderKind::OpenaiCompat,
            base_url: "http://127.0.0.1:11434/v1".into(),
            credential_account: None,
            models: vec!["llama3.1".into()],
            cli_binary_path: None,
            cli_timeout_secs: None,
            cli_flavor: CliFlavor::default(),
        },
    );
    ProfileDoc {
        active: Some(ActiveProfile {
            provider: "ollama".into(),
            model: "llama3.1".into(),
        }),
        providers,
    }
}

/// Test helper — pretty-print the profile, mostly for assertions.
#[doc(hidden)]
#[must_use]
pub fn dump(p: &ProfileDoc) -> String {
    toml::to_string_pretty(p).unwrap_or_else(|_| String::from("<unserializable>"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_profile_is_ok_returns_default() {
        let dir = tempdir().unwrap();
        let profile = ProfileDoc::load_default(dir.path()).unwrap();
        assert!(profile.active.is_none());
        assert!(profile.providers.is_empty());
    }

    #[test]
    fn first_run_profile_round_trips() {
        let dir = tempdir().unwrap();
        let original = first_run_profile();
        original.save_default(dir.path()).unwrap();
        let reloaded = ProfileDoc::load_default(dir.path()).unwrap();
        assert_eq!(reloaded.active.as_ref().unwrap().provider, "ollama");
        assert_eq!(reloaded.providers.len(), 1);
        let (id, cfg, model) = reloaded.active_provider().unwrap();
        assert_eq!(id, "ollama");
        assert_eq!(model, "llama3.1");
        assert_eq!(cfg.kind, ProviderKind::OpenaiCompat);
        assert_eq!(cfg.base_url, "http://127.0.0.1:11434/v1");
    }

    #[test]
    fn active_referencing_unknown_provider_is_an_error() {
        let p = ProfileDoc {
            active: Some(ActiveProfile {
                provider: "ghost".into(),
                model: "any".into(),
            }),
            ..ProfileDoc::default()
        };
        match p.active_provider() {
            Err(ProxyError::UnknownProvider { provider, .. }) => {
                assert_eq!(provider, "ghost");
            }
            other => panic!("expected UnknownProvider, got {other:?}"),
        }
    }

    #[test]
    fn per_claw_overlays_load_from_disk() {
        let dir = tempdir().unwrap();
        // default.toml — the [providers] table that every overlay reuses.
        first_run_profile().save_default(dir.path()).unwrap();

        // openclaw.toml — overlay that activates a different model. No
        // providers section — those stay global.
        let overlay = r#"
[active]
provider = "ollama"
model = "qwen3:4b"
"#;
        std::fs::write(dir.path().join("openclaw.toml"), overlay).unwrap();

        // hermes-agent.toml — overlay missing [active] (should be skipped).
        std::fs::write(dir.path().join("hermes-agent.toml"), "# empty\n").unwrap();

        let overlays = ProfileDoc::load_per_claw_overlays(dir.path()).unwrap();
        assert!(overlays.contains_key("openclaw"), "openclaw missing");
        assert_eq!(overlays["openclaw"].provider, "ollama");
        assert_eq!(overlays["openclaw"].model, "qwen3:4b");
        assert!(!overlays.contains_key("hermes-agent"));
        // default.toml is filtered out — it's not a per-claw overlay.
        assert!(!overlays.contains_key("default"));
    }

    #[test]
    fn per_claw_overlays_missing_dir_is_ok() {
        let dir = tempdir().unwrap();
        let nonexistent = dir.path().join("absent");
        let overlays = ProfileDoc::load_per_claw_overlays(&nonexistent).unwrap();
        assert!(overlays.is_empty());
    }

    #[test]
    fn malformed_toml_is_reported_with_path() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("default.toml"), b"not valid toml [[[").unwrap();
        match ProfileDoc::load_default(dir.path()) {
            Err(ProxyError::Profile { path, kind }) => {
                assert!(path.ends_with("default.toml"));
                assert!(kind.starts_with("parse:"));
            }
            other => panic!("expected Profile error, got {other:?}"),
        }
    }
}
