//! Artifact resolver — discovers and fetches pre-built artifact manifests.
//!
//! The resolver talks to the artifact registry (Cloudflare R2 or any HTTPS host)
//! to find the latest available artifact for a given claw and architecture.
//!
//! All operations are **synchronous** (uses `ureq`).  The caller (`install_worker`)
//! wraps them in `tokio::task::spawn_blocking`.

use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

use core_rs::artifact_meta;
use core_rs::artifact_registry::{ArtifactManifest, host_arch};
use core_rs::artifact_trust::{ArtifactSignatureKeyring, ArtifactTrustMode, production_keyring};

// ── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("artifact not available for {claw}/{arch}")]
    NotAvailable { claw: String, arch: String },
    #[error("insecure artifact registry url (https required for non-loopback hosts): {0}")]
    InsecureUrl(String),
    #[error("artifact registry unreachable: {0}")]
    RegistryUnreachable(String),
    #[error("sha256 mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("incompatible architecture: host={host}, artifact={artifact}")]
    ArchMismatch { host: String, artifact: String },
    #[error("insufficient disk space: need {need_mb}MB, have {have_mb}MB")]
    InsufficientDisk { need_mb: u64, have_mb: u64 },
    #[error("download failed: {0}")]
    Download(String),
    #[error("decompression failed: {0}")]
    Decompress(String),
    #[error("manifest validation failed: {0}")]
    Validation(String),
    #[error("artifact signature verification failed: {0}")]
    Signature(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// Trust policy: keyring + per-host signature-verification mode for resolve.

/// Upper bound on a fetched registry body; a larger body fails closed.
const MAX_REGISTRY_BODY_BYTES: u64 = 4 * 1024 * 1024;

/// Trust configuration for verifying an artifact manifest's detached signature
/// during resolution.
///
/// Supplied by the caller. Production install uses
/// [`ArtifactTrustConfig::production_for_install`]. [`ArtifactResolver::new`]
/// configures no trust at all for explicit no-trust callers (not a configured
/// "unsigned mode"). When a config is present, a remote registry **requires** a
/// valid signature; `allow_unsigned_loopback` is the only relaxation and applies
/// strictly to a loopback/local host.
#[derive(Debug, Clone)]
pub struct ArtifactTrustConfig {
    keyring: ArtifactSignatureKeyring,
    allow_unsigned_loopback: bool,
}

impl ArtifactTrustConfig {
    /// A trust config that requires a valid signature for every host.
    #[must_use]
    pub fn new(keyring: ArtifactSignatureKeyring) -> Self {
        Self {
            keyring,
            allow_unsigned_loopback: false,
        }
    }

    /// Production install trust for the P0.1 hard-cut.
    ///
    /// Remote registries and mirrors require a valid signature from the pinned
    /// production keyring. A loopback/local registry may omit signatures because
    /// selecting a loopback registry is an explicit dev/test override, not a
    /// remote trust root.
    #[must_use]
    pub fn production_for_install() -> Self {
        Self::new(production_keyring()).allow_unsigned_loopback(true)
    }

    /// Permit an unsigned manifest, but ONLY when the registry host is strictly
    /// loopback/local. This never relaxes a remote host.
    #[must_use]
    pub fn allow_unsigned_loopback(mut self, allow: bool) -> Self {
        self.allow_unsigned_loopback = allow;
        self
    }

    /// The trust mode for a registry base URL: [`ArtifactTrustMode::Required`] for
    /// any remote host, and [`ArtifactTrustMode::OptionalIfAbsent`] only when
    /// unsigned-loopback is enabled AND the host is strictly loopback/local.
    fn mode_for(&self, registry_url: &str) -> ArtifactTrustMode {
        if self.allow_unsigned_loopback && registry_host_is_loopback(registry_url) {
            ArtifactTrustMode::OptionalIfAbsent
        } else {
            ArtifactTrustMode::Required
        }
    }
}

/// Whether an `http(s)` URL's host is strictly loopback/local: `localhost`, an
/// IPv4 in `127.0.0.0/8`, or `::1`. Fails closed (returns `false`) for a remote,
/// LAN, tailnet, or public host, and for any host that cannot be parsed
/// unambiguously - an unparseable or empty host is treated as remote.
fn registry_host_is_loopback(url: &str) -> bool {
    let Some(host) = url_host(url) else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

/// Extract the bare host (no scheme, userinfo, port, or path) from an `http(s)`
/// URL. Returns `None` when there is no `://` or the host is empty.
fn url_host(url: &str) -> Option<String> {
    let authority = url.split_once("://")?.1.split('/').next().unwrap_or("");
    // Strip any userinfo ("user:pass@host").
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    // IPv6 literal "[::1]:port" -> "::1"; otherwise "host:port" -> "host".
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// The result of a single registry fetch: a body, or a clean HTTP 404.
enum FetchOutcome {
    Body(Vec<u8>),
    NotFound,
}

// Resolver.

/// Resolves artifact manifests from the registry.
///
/// `trust` is `None` for [`ArtifactResolver::new`] - fetch + parse with no
/// signature verification, NOT a configured "unsigned mode". Production install
/// callers should use [`ArtifactResolver::for_install`] with an explicit
/// [`ArtifactTrustConfig`]. When an [`ArtifactTrustConfig`] is supplied via
/// [`ArtifactResolver::with_trust`], the resolver verifies the manifest's
/// detached signature before parsing it.
pub struct ArtifactResolver {
    registry_url: String,
    arch: String,
    http: ureq::Agent,
    trust: Option<ArtifactTrustConfig>,
}

impl ArtifactResolver {
    /// Create a resolver with NO signature trust configured.
    ///
    /// This preserves fetch + parse with no verification for explicit no-trust
    /// callers such as focused tests or local tooling; it is not signed-artifact
    /// enforcement. Production install callers use [`ArtifactResolver::for_install`]
    /// with [`ArtifactTrustConfig::production_for_install`].
    ///
    /// `registry_url` is the base URL of the artifact registry (no trailing slash).
    #[must_use]
    pub fn new(registry_url: &str) -> Self {
        Self::build(registry_url, None)
    }

    /// Create a resolver that verifies manifest signatures against `trust`.
    ///
    /// A remote registry requires a valid signature; an unsigned manifest is
    /// accepted only when `trust` allows unsigned loopback AND the host is
    /// strictly loopback/local.
    #[must_use]
    pub fn with_trust(registry_url: &str, trust: ArtifactTrustConfig) -> Self {
        Self::build(registry_url, Some(trust))
    }

    /// Build a resolver for the install/consumption path, honoring an explicitly
    /// injected trust config.
    ///
    /// The production install path passes
    /// [`ArtifactTrustConfig::production_for_install`], making remote registries
    /// fail closed unless a valid detached signature verifies against the pinned
    /// production key. Tests and local tooling may still pass `None` to preserve
    /// explicit no-trust behavior. `Some(trust)`, including an empty keyring,
    /// activates verification and fails closed until real key pins exist - an
    /// empty keyring is not a production config.
    #[must_use]
    pub fn for_install(registry_url: &str, trust: Option<ArtifactTrustConfig>) -> Self {
        match trust {
            Some(trust) => Self::with_trust(registry_url, trust),
            None => Self::new(registry_url),
        }
    }

    /// Build the production install resolver.
    ///
    /// This constructor is compiled on every host platform so the hard-cut trust
    /// wiring is type-checked even when the Linux prebuilt install worker is not.
    #[must_use]
    pub fn production_for_install(registry_url: &str) -> Self {
        Self::for_install(
            registry_url,
            Some(ArtifactTrustConfig::production_for_install()),
        )
    }

    fn build(registry_url: &str, trust: Option<ArtifactTrustConfig>) -> Self {
        let http = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(30))
            .build();

        Self {
            registry_url: registry_url.trim_end_matches('/').to_string(),
            arch: host_arch(),
            http,
            trust,
        }
    }

    /// Resolve the latest manifest for a claw from the registry.
    ///
    /// Fetches `<registry>/<claw>/<arch>/latest.json`. When a trust config is
    /// present, also fetches `<...>/latest.json.sig.json` and verifies the
    /// detached signature **before** the manifest bytes are parsed or validated.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError`] if the registry is unreachable, the artifact is
    /// not found, the signature is required-but-missing/invalid, the manifest is
    /// invalid, or the architecture doesn't match.
    pub fn resolve(&self, claw: &str) -> Result<ArtifactManifest, ArtifactError> {
        // Reject insecure registry base URLs — including any
        // `THEYOS_ARTIFACT_REGISTRY_URL` override — before touching the
        // network, so an `http://` override cannot fetch a manifest at all.
        // Loopback hosts remain allowed for local test fixtures.
        if !core_rs::artifact_registry::is_secure_artifact_url(&self.registry_url) {
            return Err(ArtifactError::InsecureUrl(self.registry_url.clone()));
        }

        let url = format!("{}/{}/{}/latest.json", self.registry_url, claw, self.arch);

        let latest_json_bytes = match self.fetch(&url)? {
            FetchOutcome::Body(bytes) => bytes,
            FetchOutcome::NotFound => {
                return Err(ArtifactError::NotAvailable {
                    claw: claw.to_string(),
                    arch: self.arch.clone(),
                });
            }
        };

        // The signature gate runs BEFORE any parse, when trust is configured.
        if let Some(trust) = &self.trust {
            let mode = trust.mode_for(&self.registry_url);
            let sig_url = format!("{url}.sig.json");
            // A 404 means "no signature present"; any other fetch failure is fatal
            // and must not fall through to treating the manifest as unsigned.
            let signature = match self.fetch(&sig_url)? {
                FetchOutcome::Body(bytes) => Some(bytes),
                FetchOutcome::NotFound => None,
            };
            trust
                .keyring
                .verify_latest_json(mode, &latest_json_bytes, signature.as_deref())
                .map_err(|e| ArtifactError::Signature(e.to_string()))?;
        }

        // Parse only after the signature gate.
        let manifest: ArtifactManifest =
            serde_json::from_slice(&latest_json_bytes).map_err(|e| {
                ArtifactError::Validation(format!("failed to parse manifest from {url}: {e}"))
            })?;

        // Structural validation
        manifest
            .validate()
            .map_err(|e| ArtifactError::Validation(e.to_string()))?;

        // Architecture check
        if manifest.arch != self.arch {
            return Err(ArtifactError::ArchMismatch {
                host: self.arch.clone(),
                artifact: manifest.arch.clone(),
            });
        }

        // The requested claw (URL path) is the identity the caller asked for;
        // the manifest body is data. Nothing downstream re-checks this: the
        // installer turns `manifest.claw` into `create_dir_all` /
        // `remove_dir_all` targets. A body that names a different claw than
        // the request is rejected here, before it can steer the install
        // directory.
        if manifest.claw != claw {
            return Err(ArtifactError::Validation(format!(
                "manifest claw {:?} does not match requested claw {claw:?}",
                manifest.claw,
            )));
        }

        Ok(manifest)
    }

    /// Fetch a URL, returning its body bytes or a clean [`FetchOutcome::NotFound`]
    /// on HTTP 404. Any other transport/HTTP error is an
    /// [`ArtifactError::RegistryUnreachable`] - fail-closed, never silently
    /// treated as absence.
    fn fetch(&self, url: &str) -> Result<FetchOutcome, ArtifactError> {
        let response = match self.http.get(url).call() {
            Ok(response) => response,
            Err(ureq::Error::Status(404, _)) => return Ok(FetchOutcome::NotFound),
            Err(e) => return Err(ArtifactError::RegistryUnreachable(format!("{url}: {e}"))),
        };
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_REGISTRY_BODY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| ArtifactError::RegistryUnreachable(format!("{url}: {e}")))?;
        // Fail closed on an oversize body: reading one byte past the cap lets us
        // detect (rather than silently truncate) it. A truncated prefix must never
        // be parsed or signature-verified as if it were the complete response.
        if bytes.len() as u64 > MAX_REGISTRY_BODY_BYTES {
            return Err(ArtifactError::RegistryUnreachable(format!(
                "{url}: response body exceeds {MAX_REGISTRY_BODY_BYTES} bytes"
            )));
        }
        Ok(FetchOutcome::Body(bytes))
    }

    /// Check if the local golden already matches the manifest's fingerprint.
    ///
    /// Returns `true` only if the golden at `<assets_dir>/goldens/<claw>/current/`
    /// has both a usable `rootfs.ext4` and a `golden.meta.json` with a matching
    /// fingerprint.
    #[must_use]
    pub fn is_up_to_date(manifest: &ArtifactManifest, assets_dir: &Path) -> bool {
        if artifact_meta::golden_current_rootfs(assets_dir, &manifest.claw).is_none() {
            return false;
        }
        let meta = artifact_meta::read_current_golden_meta(assets_dir, &manifest.claw);
        meta.is_some_and(|m| m.fingerprint.as_str() == manifest.fingerprint)
    }

    /// Returns the registry base URL.
    #[must_use]
    pub fn registry_url(&self) -> &str {
        &self.registry_url
    }

    /// Returns the detected host architecture.
    #[must_use]
    pub fn arch(&self) -> &str {
        &self.arch
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
