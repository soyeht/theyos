// Provider names like OpenAI, Anthropic, GLM, Kimi etc. are proper product
// names, not identifiers — `doc_markdown` would force backticks around all of
// them which makes the docs harder to read, not easier. The architecture
// diagrams in module docstrings use deliberate indentation that
// `doc_overindented_list_items` misreads.
#![allow(
    clippy::doc_markdown,
    clippy::doc_overindented_list_items,
    clippy::missing_errors_doc
)]

//! theyOS LLM proxy.
//!
//! A host-side multiplexer that exposes a single OpenAI-compatible HTTP
//! endpoint at `127.0.0.1:18900` and routes incoming `chat/completions`
//! requests to the *active* upstream provider configured in the host's
//! profile. Claws reach the proxy via reverse SSH tunnel — they always
//! talk to loopback, never to the real provider, and credentials never
//! cross the VM boundary.
//!
//! ## Per-claw routing (Slice 2)
//!
//! The proxy exposes two routing surfaces:
//!
//! - `POST /v1/chat/completions` and `GET /v1/models` — the global default
//!   active profile (set by `~/.theyos/llm-profiles/default.toml [active]`).
//! - `POST /v1/c/<claw-type>/chat/completions` and `GET /v1/c/<claw-type>/models`
//!   — the per-claw active profile (overlay file
//!   `~/.theyos/llm-profiles/<claw-type>.toml`). The overlay only carries
//!   `[active]`; provider configs live in the global `default.toml`.
//!
//! The claw never picks its provider — the host does, via the profile. The
//! claw only stamps the URL with its own `claw_type` so the host knows
//! which override (if any) applies.
//!
//! ## Public API surface
//!
//! - [`build_state_from_profile`] — load on-disk profile, look up active
//!   provider credentials, build a ready-to-serve [`ServerState`].
//! - [`server::router`] — axum router consumable by `axum::serve()`.

pub mod audit;
pub mod catalog;
pub mod config;
pub mod error;
pub mod profile;
pub mod provider;
pub mod server;
pub mod translate;

pub use catalog::{CatalogDoc, CatalogEntry, CatalogModel, CredentialHint, PlanInfo, Region};
pub use config::{KeystoreKind, ProxyConfig};
pub use error::ProxyError;
pub use profile::{ActiveProfile, ProfileDoc, ProviderConfig, ProviderKind, first_run_profile};
pub use provider::{
    AnthropicApiProvider, ChatResponse, ClaudeCliProvider, CliSubprocessProvider, ModelInfo,
    OpenAiCompatProvider, Provider,
};
pub use server::{ServerState, router};

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use keystore_rs::{FileKeystore, KeystoreBackend, SystemKeystore};
#[cfg(target_os = "linux")]
use keystore_rs::{TpmKeystore, tpm2_available};

/// Build a server state from the on-disk profile directory.
///
/// Loads `default.toml` (providers + default active), scans for per-claw
/// overlay files (`<claw-type>.toml`), looks up each provider's credential
/// in the OS keystore (when one is configured), instantiates the concrete
/// [`Provider`] implementations, and bundles everything into a
/// [`ServerState`].
///
/// Returns [`ProxyError::NoProvider`] when the default profile is empty
/// or has no `[active]` entry — callers (typically the bin) should treat
/// this as "first boot, write a stub and exit gracefully".
pub fn build_state_from_profile(config: &ProxyConfig) -> Result<ServerState, ProxyError> {
    let profile = ProfileDoc::load_default(&config.profile_dir)?;
    let default_active = profile
        .active
        .as_ref()
        .ok_or_else(|| ProxyError::NoProvider(String::new()))?
        .clone();

    let per_claw_active = ProfileDoc::load_per_claw_overlays(&config.profile_dir)?;

    let credential_store: Arc<dyn KeystoreBackend> = build_credential_store(config);
    let providers = build_provider_registry(&profile.providers, &*credential_store)?;

    // Sanity: the default-active provider must exist in the registry,
    // otherwise the proxy will hand out 503 to every request.
    if !providers.contains_key(&default_active.provider) {
        return Err(ProxyError::UnknownProvider {
            provider: default_active.provider.clone(),
            hint: format!(
                "[active.provider] = {:?} is not in [providers.*]",
                default_active.provider
            ),
        });
    }
    // Same for every overlay.
    for (claw_type, active) in &per_claw_active {
        if !providers.contains_key(&active.provider) {
            return Err(ProxyError::UnknownProvider {
                provider: active.provider.clone(),
                hint: format!(
                    "[active.provider] = {:?} (overlay for claw_type={claw_type:?}) is not in [providers.*]",
                    active.provider
                ),
            });
        }
    }

    let audit = match audit::AuditLogger::open(config.audit_log.as_deref()) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = ?config.audit_log,
                "could not open audit log; continuing without it"
            );
            audit::AuditLogger::disabled()
        }
    };

    Ok(ServerState::with_full_wiring(
        providers,
        default_active,
        per_claw_active,
        audit,
        Some(config.profile_dir.clone()),
        Some(credential_store),
    ))
}

/// Build a fresh provider registry from a profile's `[providers.*]`
/// section and the supplied keystore. Used at startup AND by the admin
/// endpoints that mutate providers — those rebuild from the just-written
/// disk state so the live registry mirrors what's persisted.
pub fn build_provider_registry(
    configs: &BTreeMap<String, ProviderConfig>,
    keystore: &dyn KeystoreBackend,
) -> Result<HashMap<String, Arc<dyn Provider>>, ProxyError> {
    let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
    for (id, cfg) in configs {
        let api_key = lookup_credential(id, cfg, keystore)?;
        let provider: Arc<dyn Provider> = match cfg.kind {
            ProviderKind::OpenaiCompat => Arc::new(OpenAiCompatProvider::new(
                id,
                &cfg.base_url,
                api_key,
                cfg.models.clone(),
            )?),
            ProviderKind::CliOauth => {
                let timeout = cfg.cli_timeout_secs.map(std::time::Duration::from_secs);
                Arc::new(CliSubprocessProvider::new(
                    id,
                    cfg.cli_flavor,
                    cfg.cli_binary_path.as_ref(),
                    timeout,
                    cfg.models.clone(),
                ))
            }
            ProviderKind::AnthropicApi => {
                let api_key = api_key.ok_or_else(|| ProxyError::Credential {
                    provider: id.clone(),
                    hint: "anthropic-api needs a credential — set credential_account in the profile".into(),
                })?;
                Arc::new(AnthropicApiProvider::new(
                    id,
                    Some(&cfg.base_url).filter(|s| !s.is_empty()),
                    api_key,
                    cfg.models.clone(),
                )?)
            }
        };
        providers.insert(id.clone(), provider);
    }
    Ok(providers)
}

fn lookup_credential(
    id: &str,
    cfg: &ProviderConfig,
    keystore: &dyn KeystoreBackend,
) -> Result<Option<String>, ProxyError> {
    let Some(account) = &cfg.credential_account else {
        return Ok(None);
    };
    match keystore.get(account) {
        Ok(bytes) => Ok(Some(String::from_utf8(bytes).map_err(|e| {
            ProxyError::Credential {
                provider: id.to_string(),
                hint: format!("credential is not UTF-8: {e}"),
            }
        })?)),
        Err(keystore_rs::KeystoreError::NotFound { label }) => Err(ProxyError::Credential {
            provider: id.to_string(),
            hint: format!(
                "keystore account {label:?} not found — add it before activating this provider"
            ),
        }),
        Err(e) => Err(ProxyError::Credential {
            provider: id.to_string(),
            hint: e.hint(),
        }),
    }
}

/// Construct the credential backend selected by [`ProxyConfig::keystore_kind`].
///
/// The proxy daemon and `theyos-llm-proxy set-credential`/`get-credential`/
/// `delete-credential` subcommands share this function so all three operate
/// on the same store. Returns an `Arc<dyn KeystoreBackend>` for runtime
/// dispatch — concrete backend choice is a startup decision, not part of
/// the hot path.
///
/// ## `KeystoreKind::Auto` resolution
///
/// - **macOS:** `SystemKeystore` (Login Keychain — wrapped by Secure
///   Enclave on Apple Silicon and T2 Intel Macs).
/// - **Linux + TPM2 present:** `TpmKeystore` (sealed via
///   `systemd-creds --with-key=auto+tpm2`).
/// - **Linux without TPM2:** `FileKeystore` (`0600` plaintext). Logs a
///   warning so the operator can decide whether to provision a TPM or
///   set `THEYOS_LLM_KEYSTORE=tpm` to refuse boot until one is
///   available.
///
/// ## `KeystoreKind::Tpm` (Linux explicit)
///
/// Requested explicitly via `THEYOS_LLM_KEYSTORE=tpm` and a TPM2 must be
/// reachable. If absent, this function falls back to the file backend
/// and logs an error — the proxy will then start, but credential reads
/// fail at first use (a loud failure mode beats a silent insecure
/// fallback). Operators who want hard failure should set
/// `THEYOS_LLM_KEYSTORE=tpm` and monitor the startup log.
///
/// Tests bypass this entirely via a thread-local override
/// (`THEYOS_LLM_PROXY_TEST_KEYSTORE_DIR`) → file backend so they never touch
/// the user's real Keychain / Secret Service.
#[must_use]
pub fn build_credential_store(config: &ProxyConfig) -> Arc<dyn KeystoreBackend> {
    // Test hermeticity: if an integration test sets this, force the file
    // backend at the requested path regardless of what the env var says.
    if let Ok(dir) = std::env::var("THEYOS_LLM_PROXY_TEST_KEYSTORE_DIR") {
        return Arc::new(FileKeystore::new(
            std::path::PathBuf::from(dir),
            keystore_rs::SERVICE,
        ));
    }

    let kind = resolve_kind(config.keystore_kind);
    match kind {
        KeystoreKind::File => {
            tracing::info!(
                dir = %config.keystore_dir.display(),
                "keystore: file backend (0600, no encryption-at-rest)"
            );
            Arc::new(FileKeystore::new(
                &config.keystore_dir,
                keystore_rs::SERVICE,
            ))
        }
        KeystoreKind::System => {
            tracing::info!("keystore: OS-native (Keychain / Secret Service)");
            Arc::new(SystemKeystore::default())
        }
        #[cfg(target_os = "linux")]
        KeystoreKind::Tpm => {
            tracing::info!(
                dir = %config.keystore_dir.display(),
                "keystore: TPM2-sealed (systemd-creds)"
            );
            Arc::new(TpmKeystore::new(
                &config.keystore_dir,
                keystore_rs::SERVICE,
            ))
        }
        #[cfg(not(target_os = "linux"))]
        KeystoreKind::Tpm => {
            tracing::error!(
                "keystore: THEYOS_LLM_KEYSTORE=tpm requested but TPM backend is Linux-only; falling back to OS-native"
            );
            Arc::new(SystemKeystore::default())
        }
        // `Auto` is resolved before reaching this match — `resolve_kind`
        // never returns it. The arm is here so the compiler sees the
        // match is total without an `unreachable!` (which would be a
        // latent panic source for a refactor that adds variants).
        KeystoreKind::Auto => {
            tracing::error!(
                "keystore: Auto kind reached match arm — this is a bug; falling back to file"
            );
            Arc::new(FileKeystore::new(
                &config.keystore_dir,
                keystore_rs::SERVICE,
            ))
        }
    }
}

/// Resolve [`KeystoreKind::Auto`] into a concrete backend choice based on
/// host capabilities. Other kinds pass through unchanged.
fn resolve_kind(kind: KeystoreKind) -> KeystoreKind {
    if !matches!(kind, KeystoreKind::Auto) {
        return kind;
    }

    #[cfg(target_os = "macos")]
    {
        tracing::debug!("keystore Auto: macOS → System (Login Keychain)");
        KeystoreKind::System
    }

    #[cfg(target_os = "linux")]
    {
        if tpm2_available() {
            tracing::debug!("keystore Auto: Linux + TPM2 → Tpm (systemd-creds)");
            KeystoreKind::Tpm
        } else {
            tracing::warn!(
                "keystore Auto: Linux without TPM2 → File (0600). Provision a \
                 TPM or set THEYOS_LLM_KEYSTORE=system if Secret Service is \
                 reachable."
            );
            KeystoreKind::File
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        tracing::warn!("keystore Auto: unsupported OS → File (0600)");
        KeystoreKind::File
    }
}
