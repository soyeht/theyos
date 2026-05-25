//! Catalog invariants + integration tests.
//!
//! These verify the **contract** the Models UI depends on, plus the
//! integration path "catalog entry → `ProviderConfig` → instantiated
//! Provider". Failing any of these means a real user-visible bug:
//!
//! - Duplicate ids → the UI deduplicates incorrectly and renders the
//!   wrong card for the wrong provider.
//! - Invalid base URL → the proxy can't reach the upstream.
//! - Catalog entry that can't build a Provider → the user sees the
//!   provider listed but `/v1/chat/completions` 502s.

use std::collections::HashMap;
use std::sync::Arc;

use llm_proxy::profile::ProviderKind;
use llm_proxy::{
    ActiveProfile, AnthropicApiProvider, CatalogDoc, CliSubprocessProvider, CredentialHint,
    OpenAiCompatProvider, Provider, ServerState, router,
};

// ── Pure-data invariants on the static catalog ──────────────────────────────

#[test]
fn catalog_ids_are_unique() {
    let cat = CatalogDoc::builtin();
    let mut seen = std::collections::HashSet::new();
    for entry in &cat.entries {
        assert!(
            seen.insert(entry.id.clone()),
            "duplicate catalog id: {}",
            entry.id
        );
    }
}

#[test]
fn catalog_ids_match_openclaw_provider_plugin_ids() {
    // openclaw publishes its provider ids in docs/concepts/model-providers.md
    // and src/agents/models-config.* — these names are part of the public
    // contract every claw depends on. Mismatching them silently breaks
    // claw-to-proxy routing.
    let cat = CatalogDoc::builtin();
    for expected in [
        "openai",
        "anthropic",
        "google",
        "xai",
        "deepseek",
        "zai",
        "moonshot",
        "qwen",
        "minimax",
        "openrouter",
        "groq",
        "cerebras",
        "together",
        "mistral",
        "nvidia",
        "claude-cli",
        "ollama",
        "llamacpp",
        "mlx",
    ] {
        assert!(
            cat.find(expected).is_some(),
            "catalog missing openclaw-compatible provider id {expected:?}"
        );
    }
}

#[test]
fn catalog_base_urls_are_well_formed() {
    let cat = CatalogDoc::builtin();
    for entry in &cat.entries {
        if matches!(entry.kind, ProviderKind::CliOauth) {
            // CLI-OAuth providers don't use base_url; it's intentionally
            // empty.
            assert_eq!(
                entry.default_base_url, "",
                "cli-oauth entry {} should have empty base_url",
                entry.id
            );
            continue;
        }
        assert!(
            entry.default_base_url.starts_with("http://")
                || entry.default_base_url.starts_with("https://"),
            "catalog {} base URL is malformed (no scheme): {}",
            entry.id,
            entry.default_base_url
        );
        // Strip scheme and verify there's a host segment before the first /.
        let after_scheme = entry
            .default_base_url
            .split_once("://")
            .map(|x| x.1)
            .unwrap_or("");
        let host = after_scheme.split('/').next().unwrap_or("");
        assert!(
            !host.is_empty() && host.contains('.')
                || host == "127.0.0.1"
                || host.starts_with("localhost"),
            "catalog {} base URL has no recognisable host: {}",
            entry.id,
            entry.default_base_url
        );

        if let Some(coding) = &entry.coding_plan_base_url {
            assert!(
                coding.starts_with("http://") || coding.starts_with("https://"),
                "catalog {} coding-plan URL is malformed: {coding}",
                entry.id
            );
            assert_ne!(
                coding, &entry.default_base_url,
                "catalog {} coding URL equals default — coding endpoint must be a distinct surface",
                entry.id
            );
        }
    }
}

#[test]
fn catalog_models_are_non_empty_for_every_entry() {
    let cat = CatalogDoc::builtin();
    for entry in &cat.entries {
        assert!(
            !entry.models.is_empty(),
            "catalog {} ships with no models — the UI would show an empty model picker",
            entry.id
        );
        for model in &entry.models {
            assert!(
                !model.id.is_empty(),
                "catalog {} has a model with empty id",
                entry.id
            );
            assert!(
                !model.display_name.is_empty(),
                "catalog {} model {:?} has empty display name",
                entry.id,
                model.id
            );
        }
    }
}

#[test]
fn catalog_credential_hints_match_kind() {
    // Anthropic-API + cloud OpenAI-compat providers MUST need an api-key
    // credential (otherwise they'll 401 on first request). Local providers
    // MUST have CredentialHint::None. CLI-OAuth providers MUST have
    // CliOauth with a non-empty cli binary name.
    let cat = CatalogDoc::builtin();
    for entry in &cat.entries {
        let local = matches!(entry.id.as_str(), "ollama" | "llamacpp" | "mlx");
        match (&entry.credential, entry.kind, local) {
            (CredentialHint::None, ProviderKind::OpenaiCompat, true) => {}
            (CredentialHint::ApiKey { env_hint }, ProviderKind::OpenaiCompat, false) => {
                assert!(
                    !env_hint.is_empty(),
                    "{}: api-key env hint must be non-empty",
                    entry.id
                );
            }
            (CredentialHint::ApiKey { .. }, ProviderKind::AnthropicApi, _) => {}
            (CredentialHint::CliOauth { cli_binary }, ProviderKind::CliOauth, _) => {
                assert!(
                    !cli_binary.is_empty(),
                    "{}: cli-oauth binary name must be non-empty",
                    entry.id
                );
            }
            (cred, kind, _) => {
                panic!(
                    "catalog {} has incoherent credential hint: kind={kind:?}, credential={cred:?}",
                    entry.id
                );
            }
        }
    }
}

#[test]
fn version_is_a_positive_integer() {
    // The frontend uses the version to invalidate caches; bumping to 0 would
    // make caches stale forever.
    let cat = CatalogDoc::builtin();
    assert!(cat.version > 0, "catalog version must be positive");
}

// ── Catalog → ProviderConfig → Provider integration ─────────────────────────

#[test]
fn every_catalog_entry_produces_an_instantiable_provider_config() {
    // Walk every catalog entry — across all three kinds — build a
    // ProviderConfig (as the admin endpoint would when the user clicks
    // "install"), and verify it can be turned into a live Provider when
    // given a fake credential.
    //
    // Guards against catalog drift where a kind/config combination would
    // parse but fail at provider construction:
    //   - OpenaiCompat with empty base_url
    //   - AnthropicApi missing the credential plumbing
    //   - CliOauth with an unmapped CliFlavor (would only surface at
    //     runtime when a user POSTs the provider)
    let cat = CatalogDoc::builtin();
    for entry in &cat.entries {
        let cfg = entry.to_provider_config(None, false);
        match entry.kind {
            ProviderKind::OpenaiCompat => {
                assert!(!cfg.base_url.is_empty(), "{}: empty base_url", entry.id);
                let api_key = match &entry.credential {
                    CredentialHint::None => None,
                    _ => Some("fake-key-for-test".to_string()),
                };
                let _ = OpenAiCompatProvider::new(
                    &entry.id,
                    &cfg.base_url,
                    api_key,
                    cfg.models.clone(),
                )
                .unwrap_or_else(|e| {
                    panic!("catalog entry {} won't build a Provider: {e}", entry.id)
                });
            }
            ProviderKind::AnthropicApi => {
                // AnthropicApi requires a credential — the registry path
                // refuses to build without one. We provide a fake key so
                // we're testing the construction shape, not the keystore.
                let _ = AnthropicApiProvider::new(
                    &entry.id,
                    Some(&cfg.base_url).filter(|s| !s.is_empty()),
                    "fake-key-for-test".to_string(),
                    cfg.models.clone(),
                )
                .unwrap_or_else(|e| {
                    panic!("catalog entry {} won't build a Provider: {e}", entry.id)
                });
            }
            ProviderKind::CliOauth => {
                // CliOauth never reads the keystore — the credential is
                // the user's local CLI login state. Path resolution
                // happens at spawn time; constructor is infallible.
                let _ = CliSubprocessProvider::new(
                    &entry.id,
                    cfg.cli_flavor,
                    cfg.cli_binary_path.as_ref(),
                    cfg.cli_timeout_secs.map(std::time::Duration::from_secs),
                    cfg.models.clone(),
                );
            }
        }
    }
}

#[test]
fn coding_plan_base_url_is_used_when_user_picks_it() {
    let cat = CatalogDoc::builtin();
    let zai = cat.find("zai").expect("zai must be in the catalog");
    let cfg_default = zai.to_provider_config(None, false);
    let cfg_plan = zai.to_provider_config(None, true);
    assert_ne!(
        cfg_default.base_url, cfg_plan.base_url,
        "coding plan toggle must change the base URL for Z.AI"
    );
    assert!(
        cfg_plan.base_url.contains("/coding/"),
        "Z.AI coding plan URL should target the /coding/ surface, got {}",
        cfg_plan.base_url
    );
}

#[test]
fn coding_plan_falls_back_to_default_when_provider_has_no_alternate() {
    // For providers with no separate coding endpoint, asking for the
    // "use coding plan" path must not 500 the UI — it just yields the
    // default URL.
    let cat = CatalogDoc::builtin();
    let openai = cat.find("openai").expect("openai must be in catalog");
    let cfg_default = openai.to_provider_config(None, false);
    let cfg_plan = openai.to_provider_config(None, true);
    assert_eq!(cfg_default.base_url, cfg_plan.base_url);
}

#[test]
fn cli_oauth_entries_cover_all_four_flavors() {
    // Slice F invariant: catalog must expose one CliOauth entry per
    // supported subprocess flavor — claude, codex, gemini, opencode.
    // The frontend renders these as "use your subscription"
    // affordances; missing any flavor = users on that subscription
    // can't onboard without hand-editing the profile TOML.
    let cat = CatalogDoc::builtin();
    use llm_proxy::profile::{CliFlavor, ProviderKind};

    let cli_oauth: Vec<&llm_proxy::CatalogEntry> = cat
        .entries
        .iter()
        .filter(|e| e.kind == ProviderKind::CliOauth)
        .collect();

    let flavors: std::collections::HashSet<CliFlavor> =
        cli_oauth.iter().map(|e| e.cli_flavor).collect();
    assert!(
        flavors.contains(&CliFlavor::Claude),
        "claude-cli catalog entry missing"
    );
    assert!(
        flavors.contains(&CliFlavor::Codex),
        "openai-codex catalog entry missing"
    );
    assert!(
        flavors.contains(&CliFlavor::Gemini),
        "google-gemini-cli catalog entry missing"
    );
    assert!(
        flavors.contains(&CliFlavor::Opencode),
        "opencode-cli catalog entry missing"
    );

    // Each CliOauth entry must carry a binary hint so the UI can show
    // "install <binary> on the host" in the onboarding card.
    for entry in &cli_oauth {
        let llm_proxy::CredentialHint::CliOauth { cli_binary } = &entry.credential else {
            panic!(
                "CliOauth entry {:?} must use CredentialHint::CliOauth",
                entry.id
            );
        };
        assert!(
            !cli_binary.is_empty(),
            "{} cli_binary must be non-empty",
            entry.id
        );
    }
}

#[test]
fn catalog_models_carry_through_to_provider_config() {
    // The models list must survive translation to ProviderConfig so the
    // /v1/models endpoint can enumerate them.
    let cat = CatalogDoc::builtin();
    for entry in &cat.entries {
        let cfg = entry.to_provider_config(None, false);
        let from_catalog: Vec<&str> = entry.models.iter().map(|m| m.id.as_str()).collect();
        let from_cfg: Vec<&str> = cfg.models.iter().map(String::as_str).collect();
        assert_eq!(from_catalog, from_cfg, "{} model list mismatch", entry.id);
    }
}

// ── HTTP endpoint exposure ──────────────────────────────────────────────────

#[tokio::test]
async fn admin_catalog_endpoint_serves_the_builtin_catalog() {
    let provider = OpenAiCompatProvider::new(
        "ollama-test",
        "http://127.0.0.1:1",
        None,
        vec!["any".into()],
    )
    .unwrap();
    let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
    providers.insert("ollama-test".into(), Arc::new(provider));
    let state = ServerState::new(
        providers,
        ActiveProfile {
            provider: "ollama-test".into(),
            model: "any".into(),
        },
        HashMap::new(),
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let body: CatalogDoc = reqwest::Client::new()
        .get(format!("http://{addr}/admin/catalog"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let local = CatalogDoc::builtin();
    assert_eq!(body.version, local.version);
    assert_eq!(body.entries.len(), local.entries.len());
    let anthropic = body
        .entries
        .iter()
        .find(|e| e.id == "anthropic")
        .expect("anthropic missing from served catalog");
    match &anthropic.credential {
        CredentialHint::ApiKey { env_hint } => assert_eq!(env_hint, "ANTHROPIC_API_KEY"),
        other => panic!("expected ApiKey credential for anthropic, got {other:?}"),
    }
    assert_eq!(anthropic.kind, ProviderKind::AnthropicApi);
}

#[tokio::test]
async fn admin_catalog_json_round_trips_through_serde() {
    // Frontend deserialises the JSON; any non-string field that isn't
    // serializable would surface here.
    let cat = CatalogDoc::builtin();
    let json = serde_json::to_string(&cat).unwrap();
    let parsed: CatalogDoc = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.version, cat.version);
    assert_eq!(parsed.entries.len(), cat.entries.len());
    let lhs: Vec<&str> = cat.entries.iter().map(|e| e.id.as_str()).collect();
    let rhs: Vec<&str> = parsed.entries.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(lhs, rhs);
}
