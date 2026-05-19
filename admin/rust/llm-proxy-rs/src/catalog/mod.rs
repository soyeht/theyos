//! Single source of truth for the provider catalog that powers the
//! Models admin UI.
//!
//! The catalog is **static data** baked into the binary, exposed at
//! `GET /admin/catalog` so the frontend renders the same list the proxy
//! understands. The frontend NEVER hard-codes provider URLs or
//! credential hints — it asks the proxy.
//!
//! ## Schema versioning
//!
//! [`CatalogDoc::version`] is a monotonically increasing integer that the
//! frontend can use to detect catalog changes (e.g. invalidate a local
//! cache). Bump it whenever you add/remove/rename a provider.
//!
//! ## Adding a new provider
//!
//! 1. Add a new [`CatalogEntry`] to [`providers::ALL`].
//! 2. If the provider needs a non-trivial backend (Anthropic translation,
//!    CLI subprocess), make sure the matching [`ProviderKind`] variant is
//!    already wired in `lib::build_provider_registry`.
//! 3. The catalog itself never goes near the keystore — credentials are
//!    looked up at *provider construction*, not at catalog load.

use serde::{Deserialize, Serialize};

use crate::profile::ProviderKind;

pub mod providers;

/// Schema version of the catalog document. Bump when entries change.
pub const CATALOG_VERSION: u32 = 1;

/// Top-level shape of `GET /admin/catalog`. Holds the version + the list
/// of entries. The list is in stable presentation order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogDoc {
    pub version: u32,
    pub entries: Vec<CatalogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    /// Stable, lowercase, kebab-case identifier. Matches the openclaw
    /// provider id where one exists.
    pub id: String,

    /// Human-readable name, e.g. "OpenAI", "Z.AI (GLM)".
    pub display_name: String,

    /// Short tagline shown in the Models card; under 80 chars.
    pub tagline: String,

    /// Which backend handles requests for this provider.
    pub kind: ProviderKind,

    /// Default base URL. The user can override per-installation via
    /// `[providers.<id>.base_url]` in their TOML profile.
    pub default_base_url: String,

    /// Optional alternate base URL — typically the provider's coding-
    /// plan endpoint. The UI surfaces both choices.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coding_plan_base_url: Option<String>,

    /// Models the provider exposes by default. Users can extend the list
    /// in their profile.
    pub models: Vec<CatalogModel>,

    /// What sort of credential the provider needs, and an env-var hint.
    pub credential: CredentialHint,

    /// Optional documentation URL (for the "learn more" link in the UI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,

    /// Optional plan-signup metadata for providers that offer a flat-
    /// rate coding subscription on top of pay-per-token API access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanInfo>,

    /// Whether the provider is offered for both China and global
    /// regions (and which one this entry represents).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<Region>,

    /// For `kind == CliOauth`: which CLI flavor's invocation contract
    /// the proxy uses to spawn the subprocess. Defaults to
    /// [`CliFlavor::Claude`] (the historical v1.0 default) for entries
    /// where the field is absent. New CLI-OAuth catalog entries must
    /// set this explicitly to the appropriate variant.
    #[serde(default)]
    pub cli_flavor: crate::profile::CliFlavor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogModel {
    pub id: String,
    pub display_name: String,
    /// Optional context window in tokens (for the UI to display).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CredentialHint {
    /// Local providers (ollama/llamacpp/mlx) — no credential needed.
    None,
    /// Cloud API providers — bearer-token-style API key.
    ApiKey {
        /// Conventional env var name to surface in onboarding text.
        env_hint: String,
    },
    /// CLI-OAuth providers — the credential lives in a subprocess login
    /// (e.g. `~/.config/claude` for Claude Code).
    CliOauth { cli_binary: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanInfo {
    pub name: String,
    pub signup_url: String,
    /// Optional alternate model id when authenticating via the plan
    /// (e.g. Kimi Coding uses `kimi-for-coding` regardless of the
    /// model id you'd use via the regular API).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_model_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Region {
    Global,
    China,
}

impl CatalogDoc {
    /// Build the static catalog baked into this binary. Allocates owned
    /// `String`s for each entry — cheap enough to call once at startup;
    /// callers should cache the result rather than rebuild per-request.
    #[must_use]
    pub fn builtin() -> Self {
        Self {
            version: CATALOG_VERSION,
            entries: providers::make_all(),
        }
    }

    /// Look up an entry by id. `None` if absent.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.id == id)
    }
}

impl CatalogEntry {
    /// Build a [`crate::profile::ProviderConfig`] from this catalog entry
    /// using the entry's defaults. The caller sets the optional
    /// `credential_account` (the keystore label where the API key lives)
    /// — the catalog itself never holds secrets.
    #[must_use]
    pub fn to_provider_config(
        &self,
        credential_account: Option<String>,
        use_coding_plan_endpoint: bool,
    ) -> crate::profile::ProviderConfig {
        let base_url = if use_coding_plan_endpoint {
            self.coding_plan_base_url
                .clone()
                .unwrap_or_else(|| self.default_base_url.clone())
        } else {
            self.default_base_url.clone()
        };
        crate::profile::ProviderConfig {
            kind: self.kind,
            base_url,
            credential_account,
            models: self.models.iter().map(|m| m.id.clone()).collect(),
            cli_binary_path: None,
            cli_timeout_secs: None,
            cli_flavor: self.cli_flavor,
        }
    }
}
