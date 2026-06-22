//! Artifact resolver — discovers and fetches pre-built artifact manifests.
//!
//! The resolver talks to the artifact registry (Cloudflare R2 or any HTTPS host)
//! to find the latest available artifact for a given claw and architecture.
//!
//! All operations are **synchronous** (uses `ureq`).  The caller (`install_worker`)
//! wraps them in `tokio::task::spawn_blocking`.

use std::path::Path;
use std::time::Duration;

use core_rs::artifact_meta;
use core_rs::artifact_registry::{ArtifactManifest, host_arch};

// ── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("artifact not available for {claw}/{arch}")]
    NotAvailable { claw: String, arch: String },
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
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// ── Resolver ────────────────────────────────────────────────────────────────

/// Resolves artifact manifests from the registry.
pub struct ArtifactResolver {
    registry_url: String,
    arch: String,
    http: ureq::Agent,
}

impl ArtifactResolver {
    /// Create a new resolver.
    ///
    /// `registry_url` is the base URL of the artifact registry (no trailing slash).
    #[must_use]
    pub fn new(registry_url: &str) -> Self {
        let http = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(30))
            .build();

        Self {
            registry_url: registry_url.trim_end_matches('/').to_string(),
            arch: host_arch(),
            http,
        }
    }

    /// Resolve the latest manifest for a claw from the registry.
    ///
    /// Fetches `<registry>/<claw>/<arch>/latest.json` and validates it.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError`] if the registry is unreachable, the artifact
    /// is not found, the manifest is invalid, or the architecture doesn't match.
    pub fn resolve(&self, claw: &str) -> Result<ArtifactManifest, ArtifactError> {
        let url = format!("{}/{}/{}/latest.json", self.registry_url, claw, self.arch);

        let response = self.http.get(&url).call().map_err(|e| match &e {
            ureq::Error::Status(404, _) => ArtifactError::NotAvailable {
                claw: claw.to_string(),
                arch: self.arch.clone(),
            },
            _ => ArtifactError::RegistryUnreachable(format!("{url}: {e}")),
        })?;

        let manifest: ArtifactManifest = response.into_json().map_err(|e| {
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
}
