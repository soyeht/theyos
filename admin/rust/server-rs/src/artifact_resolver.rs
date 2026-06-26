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
use core_rs::artifact_trust::{ArtifactSignatureKeyring, ArtifactTrustMode};

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
/// Supplied by the caller. A real production keyring is wired in a later slice,
/// once a production public key exists; until then [`ArtifactResolver::new`]
/// configures no trust at all (the deferred status quo, not a configured
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
/// `trust` is `None` for [`ArtifactResolver::new`] - the deferred status quo
/// (fetch + parse, no verification) that predates a production public key, NOT a
/// configured "unsigned mode". When an [`ArtifactTrustConfig`] is supplied via
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
    /// This preserves the existing behavior (fetch + parse, no verification) and
    /// is the deferred status quo until a production public key exists; it is not
    /// signed-artifact enforcement. Use [`ArtifactResolver::with_trust`] to verify
    /// signatures.
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
    /// `trust` is `None` in production today - no production public key exists, so
    /// the install path keeps the deferred status quo (no verification). A caller
    /// or future config supplies a real [`ArtifactTrustConfig`] once a production
    /// key, custody, and policy exist; this associated fn is the single seam where
    /// that injection lands. Tests inject a test-only keyring to prove the
    /// consumption path end-to-end. `None` is the deferred status quo (no
    /// verification); `Some(trust)`, including an empty keyring, activates
    /// verification and fails closed until real key pins exist - an empty keyring
    /// is not a production config.
    #[must_use]
    pub fn for_install(registry_url: &str, trust: Option<ArtifactTrustConfig>) -> Self {
        match trust {
            Some(trust) => Self::with_trust(registry_url, trust),
            None => Self::new(registry_url),
        }
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
mod tests {
    use super::*;

    #[test]
    fn resolver_new_sets_arch() {
        let r = ArtifactResolver::new("https://example.com/artifacts");
        assert!(!r.arch().is_empty());
        assert!(r.arch().contains('-'));
    }

    #[test]
    fn resolver_strips_trailing_slash() {
        let r = ArtifactResolver::new("https://example.com/artifacts/");
        assert_eq!(r.registry_url(), "https://example.com/artifacts");
    }

    #[test]
    fn resolve_rejects_public_http_registry_override() {
        // Simulates THEYOS_ARTIFACT_REGISTRY_URL=http://evil.example/...
        // The override must fail before any manifest is downloaded.
        let r = ArtifactResolver::new("http://evil.example/artifacts");
        let err = r.resolve("picoclaw").unwrap_err();
        assert!(
            matches!(err, ArtifactError::InsecureUrl(_)),
            "public http registry override must be rejected pre-network, got: {err}"
        );
    }

    #[test]
    fn resolve_rejects_userinfo_loopback_registry_override() {
        // A loopback string smuggled into userinfo must not bypass the policy;
        // the real host here is `evil.example`.
        let r = ArtifactResolver::new("http://127.0.0.1@evil.example/artifacts");
        assert!(matches!(
            r.resolve("picoclaw").unwrap_err(),
            ArtifactError::InsecureUrl(_)
        ));
    }

    #[test]
    fn resolve_allows_loopback_http_registry() {
        // Loopback http is allowed by policy, so resolution proceeds past the
        // scheme gate and fails later on the network (nothing is listening).
        let r = ArtifactResolver::new("http://127.0.0.1:1/artifacts");
        let err = r.resolve("picoclaw").unwrap_err();
        assert!(
            !matches!(err, ArtifactError::InsecureUrl(_)),
            "loopback http registry must pass the scheme gate, got: {err}"
        );
    }

    #[test]
    fn is_up_to_date_false_for_missing_golden() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest = ArtifactManifest {
            manifest_version: 1,
            claw: "picoclaw".into(),
            version: "0.1.0".into(),
            arch: "x86_64-linux".into(),
            fingerprint: "e".repeat(64),
            base_rootfs_version: "v2".into(),
            sha256: "a".repeat(64),
            size_bytes: 100,
            url: "https://example.com/rootfs.ext4.zst".into(),
            published_at: "2026-04-01T00:00:00Z".into(),
            channel: "stable".into(),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            kernel_version: None,
            firecracker_version: None,
            runtime_min_version: None,
        };
        assert!(!ArtifactResolver::is_up_to_date(&manifest, tmp.path()));
    }

    #[test]
    fn is_up_to_date_false_when_meta_exists_but_rootfs_is_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let assets_dir = tmp.path();
        let manifest = ArtifactManifest {
            manifest_version: 1,
            claw: "picoclaw".into(),
            version: "0.1.0".into(),
            arch: "x86_64-linux".into(),
            fingerprint: "e".repeat(64),
            base_rootfs_version: "v2".into(),
            sha256: "a".repeat(64),
            size_bytes: 100,
            url: "https://example.com/rootfs.ext4.zst".into(),
            published_at: "2026-04-01T00:00:00Z".into(),
            channel: "stable".into(),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            kernel_version: None,
            firecracker_version: None,
            runtime_min_version: None,
        };

        let fp = artifact_meta::Fingerprint::new(&manifest.fingerprint);
        let version_dir = artifact_meta::golden_version_dir(assets_dir, &manifest.claw, &fp);
        std::fs::create_dir_all(&version_dir).unwrap();
        let meta = artifact_meta::GoldenMeta {
            claw_type: manifest.claw.clone(),
            fingerprint: fp.clone(),
            base_rootfs_sha256: manifest.base_rootfs_sha256.clone(),
            installer_plan_sha256: manifest.installer_plan_sha256.clone(),
            kernel_sha256: manifest.kernel_sha256.clone(),
            builder_version: "prebuilt-0.1.0".into(),
            created_at: manifest.published_at.clone(),
        };
        artifact_meta::write_meta(&version_dir.join("golden.meta.json"), &meta).unwrap();
        let current_link = artifact_meta::golden_current_link(assets_dir, &manifest.claw);
        artifact_meta::update_current_link(&current_link, &fp).unwrap();

        assert!(!ArtifactResolver::is_up_to_date(&manifest, assets_dir));
    }

    #[test]
    fn resolve_unreachable_registry() {
        let r = ArtifactResolver::new("http://127.0.0.1:1");
        let result = r.resolve("picoclaw");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ArtifactError::RegistryUnreachable(_)),
            "expected RegistryUnreachable, got: {err}"
        );
    }

    /// Serve a single HTTP response from a background thread, returning the
    /// base URL (e.g. `"http://127.0.0.1:<port>"`).
    fn serve_once(body: &str, content_type: &str) -> (String, std::net::TcpListener) {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let response_bytes = response.into_bytes();
        let listener_clone = listener.try_clone().expect("clone listener");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener_clone.accept() {
                // Read the request (discard)
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                // Send response
                let _ = stream.write_all(&response_bytes);
                let _ = stream.flush();
            }
        });

        (base_url, listener)
    }

    #[test]
    fn resolve_happy_path_with_fixture_server() {
        let arch = core_rs::artifact_registry::host_arch();
        let manifest = ArtifactManifest {
            manifest_version: 1,
            claw: "testclaw".into(),
            version: "1.0.0".into(),
            arch: arch.clone(),
            fingerprint: "e".repeat(64),
            base_rootfs_version: "v2".into(),
            sha256: "a".repeat(64),
            size_bytes: 1000,
            url: "https://example.com/rootfs.ext4.zst".into(),
            published_at: "2026-04-01T00:00:00Z".into(),
            channel: "stable".into(),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            kernel_version: Some(core_rs::guest_net::KERNEL_FILENAME.into()),
            firecracker_version: None,
            runtime_min_version: None,
        };
        let json = serde_json::to_string(&manifest).unwrap();

        // Serve the manifest JSON on a local HTTP server
        let (base_url, _listener) = serve_once(&json, "application/json");

        // The resolver fetches <base>/<claw>/<arch>/latest.json, but our
        // trivial server ignores the path and always returns the body.
        let r = ArtifactResolver::new(&base_url);
        // Override arch to match the manifest
        let result = r.resolve("testclaw");

        assert!(result.is_ok(), "resolve should succeed, got: {result:?}");
        let resolved = result.unwrap();
        assert_eq!(resolved.claw, "testclaw");
        assert_eq!(resolved.version, "1.0.0");
        assert_eq!(resolved.fingerprint, "e".repeat(64));
        assert_eq!(resolved.base_rootfs_sha256, "b".repeat(64));
        assert_eq!(resolved.installer_plan_sha256, "c".repeat(64));
        assert_eq!(resolved.kernel_sha256, "d".repeat(64));
    }

    #[test]
    fn resolve_returns_not_available_on_404() {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");

        let listener_clone = listener.try_clone().expect("clone");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener_clone.accept() {
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let resp =
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(resp);
            }
        });

        let r = ArtifactResolver::new(&base_url);
        let result = r.resolve("nonexistent");
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ArtifactError::NotAvailable { .. }),
            "expected NotAvailable"
        );
    }

    // P0.1-C: signature trust mechanics (test keyring; no production key).

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
    use core_rs::artifact_signature::{
        ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW, ARTIFACT_SIGNATURE_SCHEMA_VERSION,
        ArtifactSignatureEnvelope, ArtifactSignatureKey, signature_payload,
    };
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    const SIGNER_KEY_ID: &str = "resolver-test-p256";

    fn signing_key(scalar: u8) -> SigningKey {
        SigningKey::from_slice(&[scalar; 32]).expect("valid test scalar")
    }

    fn public_pin(scalar: u8, key_id: &str) -> ArtifactSignatureKey {
        let public = signing_key(scalar)
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        ArtifactSignatureKey::new(key_id, ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW, public)
    }

    fn keyring(scalar: u8) -> ArtifactSignatureKeyring {
        ArtifactSignatureKeyring::new().with_current(public_pin(scalar, SIGNER_KEY_ID))
    }

    /// Detached signature JSON over the exact `manifest_bytes`, signed by `scalar`.
    fn sign(scalar: u8, key_id: &str, manifest_bytes: &[u8]) -> Vec<u8> {
        let signature: Signature = signing_key(scalar).sign(&signature_payload(manifest_bytes));
        let envelope = ArtifactSignatureEnvelope {
            schema_version: ARTIFACT_SIGNATURE_SCHEMA_VERSION,
            alg: ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW.to_string(),
            key_id: key_id.to_string(),
            signature_b64url: B64URL.encode(signature.to_bytes()),
        };
        serde_json::to_vec(&envelope).expect("signature json")
    }

    fn test_manifest_bytes() -> Vec<u8> {
        let manifest = ArtifactManifest {
            manifest_version: 1,
            claw: "testclaw".into(),
            version: "1.0.0".into(),
            arch: core_rs::artifact_registry::host_arch(),
            fingerprint: "e".repeat(64),
            base_rootfs_version: "v2".into(),
            sha256: "a".repeat(64),
            size_bytes: 1000,
            url: "https://example.com/rootfs.ext4.zst".into(),
            published_at: "2026-04-01T00:00:00Z".into(),
            channel: "stable".into(),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            kernel_version: Some(core_rs::guest_net::KERNEL_FILENAME.into()),
            firecracker_version: None,
            runtime_min_version: None,
        };
        serde_json::to_vec(&manifest).expect("manifest json")
    }

    fn http_ok(body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    /// Serve path-routed responses on a loopback port: `latest.json` -> the
    /// manifest, `latest.json.sig.json` -> the signature (or 404 when `sig` is
    /// `None`). Handles a bounded number of sequential connections, then stops.
    fn serve_signed(manifest: Vec<u8>, sig: Option<Vec<u8>>) -> (String, std::net::TcpListener) {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");
        let listener_clone = listener.try_clone().expect("clone listener");

        std::thread::spawn(move || {
            for _ in 0..8 {
                let Ok((mut stream, _)) = listener_clone.accept() else {
                    break;
                };
                let mut buf = [0u8; 4096];
                let n = std::io::Read::read(&mut stream, &mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split(' ').nth(1))
                    .unwrap_or("");

                let response = if path.ends_with(".sig.json") {
                    match &sig {
                        Some(body) => http_ok(body),
                        None => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                    }
                } else {
                    http_ok(&manifest)
                };
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });

        (base_url, listener)
    }

    #[test]
    fn registry_host_is_loopback_accepts_only_strict_loopback() {
        assert!(registry_host_is_loopback("http://127.0.0.1:8080"));
        assert!(registry_host_is_loopback("http://127.5.6.7/path"));
        assert!(registry_host_is_loopback("http://localhost:9000"));
        assert!(registry_host_is_loopback("http://[::1]:8080"));
        // Remote / LAN / tailnet / public / ambiguous -> not loopback (fail closed).
        assert!(!registry_host_is_loopback(
            "https://r2.example.com/artifacts"
        ));
        assert!(!registry_host_is_loopback("http://192.168.1.10:8080"));
        assert!(!registry_host_is_loopback("http://100.64.0.1"));
        assert!(!registry_host_is_loopback("https://localhost.evil.com"));
        assert!(!registry_host_is_loopback("not a url"));
        assert!(!registry_host_is_loopback("http:///latest.json"));
    }

    #[test]
    fn trust_override_never_relaxes_a_remote_host() {
        let cfg = ArtifactTrustConfig::new(keyring(7)).allow_unsigned_loopback(true);
        // Mandatory: the loopback override must NOT apply to a remote host.
        assert_eq!(
            cfg.mode_for("https://r2.example.com/artifacts"),
            ArtifactTrustMode::Required
        );
        assert_eq!(
            cfg.mode_for("http://192.168.1.10:8080"),
            ArtifactTrustMode::Required
        );
        // Loopback WITH the override -> OptionalIfAbsent.
        assert_eq!(
            cfg.mode_for("http://127.0.0.1:8080"),
            ArtifactTrustMode::OptionalIfAbsent
        );
        // Loopback WITHOUT the override -> still Required.
        assert_eq!(
            ArtifactTrustConfig::new(keyring(7)).mode_for("http://127.0.0.1:8080"),
            ArtifactTrustMode::Required
        );
    }

    #[test]
    fn resolve_required_accepts_valid_signature() {
        let manifest = test_manifest_bytes();
        let sig = sign(7, SIGNER_KEY_ID, &manifest);
        let (base_url, _l) = serve_signed(manifest, Some(sig));
        let r = ArtifactResolver::with_trust(&base_url, ArtifactTrustConfig::new(keyring(7)));
        let resolved = r.resolve("testclaw").expect("valid signature resolves");
        assert_eq!(resolved.claw, "testclaw");
    }

    #[test]
    fn resolve_required_rejects_missing_signature() {
        let manifest = test_manifest_bytes();
        let (base_url, _l) = serve_signed(manifest, None);
        let r = ArtifactResolver::with_trust(&base_url, ArtifactTrustConfig::new(keyring(7)));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::Signature(_)
        ));
    }

    #[test]
    fn resolve_required_rejects_bad_signature() {
        let manifest = test_manifest_bytes();
        // Sign DIFFERENT bytes, so the signature does not match the served manifest.
        let sig = sign(7, SIGNER_KEY_ID, b"other-bytes");
        let (base_url, _l) = serve_signed(manifest, Some(sig));
        let r = ArtifactResolver::with_trust(&base_url, ArtifactTrustConfig::new(keyring(7)));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::Signature(_)
        ));
    }

    #[test]
    fn resolve_required_rejects_unknown_key() {
        let manifest = test_manifest_bytes();
        let sig = sign(7, SIGNER_KEY_ID, &manifest);
        let (base_url, _l) = serve_signed(manifest, Some(sig));
        // Keyring pins a different key (scalar 9); the signer's key is unknown.
        let r = ArtifactResolver::with_trust(&base_url, ArtifactTrustConfig::new(keyring(9)));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::Signature(_)
        ));
    }

    #[test]
    fn resolve_required_rejects_revoked_key() {
        let manifest = test_manifest_bytes();
        let sig = sign(7, SIGNER_KEY_ID, &manifest);
        let (base_url, _l) = serve_signed(manifest, Some(sig));
        let revoked = keyring(7).revoke(SIGNER_KEY_ID);
        let r = ArtifactResolver::with_trust(&base_url, ArtifactTrustConfig::new(revoked));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::Signature(_)
        ));
    }

    #[test]
    fn resolve_stripped_signature_does_not_fall_back_to_unsigned() {
        // Stripping latest.json.sig.json (404) must fail closed in Required mode,
        // not silently accept the manifest as unsigned.
        let manifest = test_manifest_bytes();
        let (base_url, _l) = serve_signed(manifest, None);
        let r = ArtifactResolver::with_trust(&base_url, ArtifactTrustConfig::new(keyring(7)));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::Signature(_)
        ));
    }

    #[test]
    fn resolve_loopback_unsigned_passes_only_with_override() {
        let manifest = test_manifest_bytes();
        let (base_url, _l) = serve_signed(manifest, None);
        // The explicit loopback override allows an unsigned manifest on loopback.
        let permissive = ArtifactTrustConfig::new(keyring(7)).allow_unsigned_loopback(true);
        let r = ArtifactResolver::with_trust(&base_url, permissive);
        assert!(r.resolve("testclaw").is_ok());
    }

    #[test]
    fn resolve_required_verifies_signature_before_parsing() {
        // Malformed manifest bytes + a missing signature: in Required mode the
        // signature gate must fail FIRST (Signature), never reaching the parser
        // (which would otherwise yield Validation).
        let (base_url, _l) = serve_signed(b"{not valid json".to_vec(), None);
        let r = ArtifactResolver::with_trust(&base_url, ArtifactTrustConfig::new(keyring(7)));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::Signature(_)
        ));
    }

    #[test]
    fn resolve_rejects_oversize_body_before_parsing() {
        // A body larger than MAX_REGISTRY_BODY_BYTES must fail closed in fetch(),
        // never truncated-then-parsed. Uses trust None so the only possible failure
        // is the size guard, not signature verification or a JSON parse error.
        let oversize = vec![b'a'; MAX_REGISTRY_BODY_BYTES as usize + 1];
        let (base_url, _l) = serve_signed(oversize, None);
        let r = ArtifactResolver::new(&base_url);
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::RegistryUnreachable(_)
        ));
    }

    /// Serve the manifest on `latest.json` and a bare HTTP status (no body) on
    /// `latest.json.sig.json` - to exercise non-200/404 signature-fetch outcomes.
    fn serve_manifest_sig_status(
        manifest: Vec<u8>,
        sig_status: u16,
    ) -> (String, std::net::TcpListener) {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");
        let listener_clone = listener.try_clone().expect("clone listener");

        std::thread::spawn(move || {
            for _ in 0..8 {
                let Ok((mut stream, _)) = listener_clone.accept() else {
                    break;
                };
                let mut buf = [0u8; 4096];
                let n = std::io::Read::read(&mut stream, &mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split(' ').nth(1))
                    .unwrap_or("");

                let response = if path.ends_with(".sig.json") {
                    format!(
                        "HTTP/1.1 {sig_status} STATUS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .into_bytes()
                } else {
                    http_ok(&manifest)
                };
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });

        (base_url, listener)
    }

    #[test]
    fn resolve_sig_fetch_non_404_error_fails_closed() {
        // A non-404 error fetching latest.json.sig.json (here HTTP 500) must fail
        // closed: it is NOT treated as "signature absent" and must never fall
        // through to accepting the manifest as unsigned.
        let manifest = test_manifest_bytes();
        let (base_url, _l) = serve_manifest_sig_status(manifest, 500);
        let r = ArtifactResolver::with_trust(&base_url, ArtifactTrustConfig::new(keyring(7)));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::RegistryUnreachable(_)
        ));
    }

    #[test]
    fn resolve_trust_none_preserves_status_quo_and_ignores_signatures() {
        // trust None is the deferred status quo: the resolver never fetches or
        // verifies a signature. Even a server that would error on the .sig.json
        // endpoint resolves fine, because that endpoint is never requested.
        let manifest = test_manifest_bytes();
        let (base_url, _l) = serve_manifest_sig_status(manifest, 500);
        let r = ArtifactResolver::new(&base_url);
        let resolved = r
            .resolve("testclaw")
            .expect("trust None resolves without touching .sig.json");
        assert_eq!(resolved.claw, "testclaw");
    }

    // P0.1-E: the install/consumption seam (ArtifactResolver::for_install) carries
    // an injected trust config through to verification. Production passes None.

    #[test]
    fn for_install_with_trust_verifies_valid_signed_consumption() {
        let manifest = test_manifest_bytes();
        let sig = sign(7, SIGNER_KEY_ID, &manifest);
        let (base_url, _l) = serve_signed(manifest, Some(sig));
        let r =
            ArtifactResolver::for_install(&base_url, Some(ArtifactTrustConfig::new(keyring(7))));
        let resolved = r
            .resolve("testclaw")
            .expect("valid signed consumption resolves");
        assert_eq!(resolved.claw, "testclaw");
    }

    #[test]
    fn for_install_with_trust_rejects_missing_signature() {
        let manifest = test_manifest_bytes();
        let (base_url, _l) = serve_signed(manifest, None);
        let r =
            ArtifactResolver::for_install(&base_url, Some(ArtifactTrustConfig::new(keyring(7))));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::Signature(_)
        ));
    }

    #[test]
    fn for_install_with_trust_rejects_bad_signature() {
        let manifest = test_manifest_bytes();
        let sig = sign(7, SIGNER_KEY_ID, b"other-bytes");
        let (base_url, _l) = serve_signed(manifest, Some(sig));
        let r =
            ArtifactResolver::for_install(&base_url, Some(ArtifactTrustConfig::new(keyring(7))));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::Signature(_)
        ));
    }

    #[test]
    fn for_install_with_trust_rejects_unknown_key() {
        let manifest = test_manifest_bytes();
        let sig = sign(7, SIGNER_KEY_ID, &manifest);
        let (base_url, _l) = serve_signed(manifest, Some(sig));
        let r =
            ArtifactResolver::for_install(&base_url, Some(ArtifactTrustConfig::new(keyring(9))));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::Signature(_)
        ));
    }

    #[test]
    fn for_install_with_trust_rejects_revoked_key() {
        let manifest = test_manifest_bytes();
        let sig = sign(7, SIGNER_KEY_ID, &manifest);
        let (base_url, _l) = serve_signed(manifest, Some(sig));
        let revoked = keyring(7).revoke(SIGNER_KEY_ID);
        let r = ArtifactResolver::for_install(&base_url, Some(ArtifactTrustConfig::new(revoked)));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::Signature(_)
        ));
    }

    #[test]
    fn for_install_with_trust_non_404_sig_fails_closed() {
        let manifest = test_manifest_bytes();
        let (base_url, _l) = serve_manifest_sig_status(manifest, 500);
        let r =
            ArtifactResolver::for_install(&base_url, Some(ArtifactTrustConfig::new(keyring(7))));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::RegistryUnreachable(_)
        ));
    }

    #[test]
    fn for_install_with_trust_loopback_unsigned_only_with_override() {
        let manifest = test_manifest_bytes();
        let (base_url, _l) = serve_signed(manifest, None);
        let permissive = ArtifactTrustConfig::new(keyring(7)).allow_unsigned_loopback(true);
        let r = ArtifactResolver::for_install(&base_url, Some(permissive));
        assert!(r.resolve("testclaw").is_ok());
    }

    #[test]
    fn for_install_none_is_deferred_status_quo() {
        // Production today: None means no verification - the install path resolves
        // unsigned exactly as ArtifactResolver::new, even where a .sig.json errors.
        let manifest = test_manifest_bytes();
        let (base_url, _l) = serve_manifest_sig_status(manifest, 500);
        let r = ArtifactResolver::for_install(&base_url, None);
        let resolved = r.resolve("testclaw").expect("None resolves as status quo");
        assert_eq!(resolved.claw, "testclaw");
    }

    #[test]
    fn for_install_with_empty_keyring_fails_closed() {
        // An empty keyring is NOT the status quo: Some(trust) activates
        // verification, and with no accepted keys an otherwise-valid signature
        // fails closed (its key_id is unknown). It must never be silently accepted
        // as "no enforcement" - so an empty keyring is not a production config.
        let manifest = test_manifest_bytes();
        let sig = sign(7, SIGNER_KEY_ID, &manifest);
        let (base_url, _l) = serve_signed(manifest, Some(sig));
        let empty = ArtifactTrustConfig::new(ArtifactSignatureKeyring::new());
        let r = ArtifactResolver::for_install(&base_url, Some(empty));
        assert!(matches!(
            r.resolve("testclaw").unwrap_err(),
            ArtifactError::Signature(_)
        ));
    }
}
