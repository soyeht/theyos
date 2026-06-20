//! Artifact registry — schema and validation for pre-built claw artifacts.
//!
//! Defines the [`ArtifactManifest`] that describes a downloadable golden rootfs
//! artifact.  The CI builds golden images and publishes them alongside a
//! `latest.json` manifest.  The host downloads, verifies, and installs the
//! rootfs without needing `imagebuilder`, `sudo`, or Firecracker locally.
//!
//! # Registry layout
//!
//! ```text
//! <registry_base_url>/
//!   <claw>/
//!     <arch>/
//!       latest.json                 ← ArtifactManifest (stable channel)
//!       <version>/
//!         manifest.json
//!         rootfs.ext4.zst
//! ```

use serde::{Deserialize, Serialize};

// ── ArtifactManifest ────────────────────────────────────────────────────────

/// Manifest describing a pre-built golden rootfs artifact.
///
/// Published by the CI alongside the compressed rootfs.  The host backend
/// downloads this manifest to discover and verify artifacts before installing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactManifest {
    /// Schema version for forward-compatible evolution.  Must be `1`.
    pub manifest_version: u32,
    /// Claw type identifier (e.g. `"hermes-agent"`).
    pub claw: String,
    /// Semver version of the claw (e.g. `"0.7.0"`).
    pub version: String,
    /// Target architecture (e.g. `"x86_64-linux"`, `"aarch64-linux"`).
    pub arch: String,
    /// Golden fingerprint (SHA-256 of `base_rootfs` + `installer_plan` + kernel).
    /// Reuses the same algorithm as `core_rs::artifact_meta::golden_fingerprint`.
    pub fingerprint: String,
    /// Base rootfs version identifier (e.g. `"v2"`).
    pub base_rootfs_version: String,
    /// SHA-256 hex digest of the compressed `rootfs.ext4.zst` file.
    pub sha256: String,
    /// Size of the compressed `.zst` file in bytes (for progress and disk check).
    pub size_bytes: u64,
    /// Download URL for `rootfs.ext4.zst`.
    pub url: String,
    /// ISO-8601 timestamp when this artifact was published.
    pub published_at: String,
    /// Release channel (e.g. `"stable"`, `"beta"`).
    pub channel: String,

    // ── Build input hashes (for GoldenMeta compatibility) ─────────────────
    //
    // These are the three SHA-256 digests that `golden_fingerprint()` hashes
    // together to produce `fingerprint`.  The installer writes them into
    // `golden.meta.json` so that DAG staleness detection, `doctor`, and
    // `artifacts sync` work identically for pre-built and locally-built goldens.
    /// SHA-256 hex digest of the base rootfs used as the build source.
    pub base_rootfs_sha256: String,
    /// SHA-256 hex digest of the expanded `InstallerPlan`.
    pub installer_plan_sha256: String,
    /// SHA-256 hex digest of the kernel image used during the build.
    pub kernel_sha256: String,

    // ── Observable metadata (not installation gates) ────────────────────────
    /// Kernel version used during the build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    /// Firecracker version used during the build (e.g. `"v1.15.0"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firecracker_version: Option<String>,
    /// Minimum theyOS runtime version required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_min_version: Option<String>,
}

// ── Validation ──────────────────────────────────────────────────────────────

/// Errors from manifest validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("unsupported manifest_version {0} (expected 1)")]
    UnsupportedVersion(u32),
    #[error("sha256 must be 64 hex characters, got {0} chars")]
    InvalidSha256Length(usize),
    #[error("sha256 contains non-hex characters")]
    InvalidSha256Hex,
    #[error("{field} must be 64 hex characters, got {len} chars")]
    InvalidDigestLength { field: &'static str, len: usize },
    #[error("{field} contains non-hex characters")]
    InvalidDigestHex { field: &'static str },
    #[error("url must start with http:// or https://")]
    InvalidUrlScheme,
    #[error("empty required field: {0}")]
    EmptyField(&'static str),
}

impl ArtifactManifest {
    /// Validate the manifest's structural integrity.
    ///
    /// Checks:
    /// - `manifest_version` is 1
    /// - `sha256` is exactly 64 lowercase hex characters
    /// - Required string fields are non-empty
    ///
    /// Does NOT check arch compatibility (use [`check_arch_compatible`] for that).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if any field is invalid.
    pub fn validate(&self) -> Result<(), ValidationError> {
        fn validate_digest(field: &'static str, value: &str) -> Result<(), ValidationError> {
            if value.len() != 64 {
                return Err(ValidationError::InvalidDigestLength {
                    field,
                    len: value.len(),
                });
            }
            if !value.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ValidationError::InvalidDigestHex { field });
            }
            Ok(())
        }

        if self.manifest_version != 1 {
            return Err(ValidationError::UnsupportedVersion(self.manifest_version));
        }

        if self.sha256.len() != 64 {
            return Err(ValidationError::InvalidSha256Length(self.sha256.len()));
        }

        if !self.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ValidationError::InvalidSha256Hex);
        }

        validate_digest("fingerprint", &self.fingerprint)?;
        validate_digest("base_rootfs_sha256", &self.base_rootfs_sha256)?;
        validate_digest("installer_plan_sha256", &self.installer_plan_sha256)?;
        validate_digest("kernel_sha256", &self.kernel_sha256)?;

        for (field, value) in [
            ("claw", self.claw.as_str()),
            ("version", self.version.as_str()),
            ("arch", self.arch.as_str()),
            ("fingerprint", self.fingerprint.as_str()),
            ("url", self.url.as_str()),
            ("channel", self.channel.as_str()),
        ] {
            if value.is_empty() {
                return Err(ValidationError::EmptyField(field));
            }
        }

        if !(self.url.starts_with("http://") || self.url.starts_with("https://")) {
            return Err(ValidationError::InvalidUrlScheme);
        }

        Ok(())
    }
}

// ── Architecture detection ──────────────────────────────────────────────────

/// Returns the host architecture string (e.g. `"x86_64-linux"`, `"aarch64-darwin"`).
#[must_use]
pub fn host_arch() -> String {
    let os = if std::env::consts::OS == "macos" {
        "darwin"
    } else {
        std::env::consts::OS
    };
    format!("{}-{os}", std::env::consts::ARCH)
}

/// Check whether a manifest's `arch` is compatible with the current host.
///
/// # Errors
///
/// Returns an error string describing the mismatch if the architecture
/// is not compatible with the host.
pub fn check_arch_compatible(manifest_arch: &str) -> Result<(), String> {
    let host = host_arch();
    if manifest_arch == host {
        Ok(())
    } else {
        Err(format!(
            "incompatible architecture: host={host}, artifact={manifest_arch}"
        ))
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> ArtifactManifest {
        ArtifactManifest {
            manifest_version: 1,
            claw: "hermes-agent".into(),
            version: "0.7.0".into(),
            arch: "x86_64-linux".into(),
            fingerprint: "e".repeat(64),
            base_rootfs_version: "v2".into(),
            sha256: "a".repeat(64),
            size_bytes: 500_000_000,
            url: "https://r2.example.com/hermes-agent/x86_64-linux/0.7.0/rootfs.ext4.zst".into(),
            published_at: "2026-04-01T00:00:00Z".into(),
            channel: "stable".into(),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            kernel_version: Some(crate::guest_net::KERNEL_FILENAME.into()),
            firecracker_version: Some("v1.15.0".into()),
            runtime_min_version: None,
        }
    }

    // ── Serde round-trip ────────────────────────────────────────────────

    #[test]
    fn serde_roundtrip() {
        let m = valid_manifest();
        let json = serde_json::to_string_pretty(&m).expect("serialize");
        let parsed: ArtifactManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.claw, "hermes-agent");
        assert_eq!(parsed.manifest_version, 1);
        assert_eq!(parsed.sha256, "a".repeat(64));
        assert_eq!(
            parsed.kernel_version.as_deref(),
            Some(crate::guest_net::KERNEL_FILENAME)
        );
    }

    #[test]
    fn serde_optional_fields_absent() {
        let mut m = valid_manifest();
        m.kernel_version = None;
        m.firecracker_version = None;
        m.runtime_min_version = None;
        let json = serde_json::to_string(&m).expect("serialize");
        assert!(!json.contains("kernel_version"));
        assert!(!json.contains("firecracker_version"));
        assert!(!json.contains("runtime_min_version"));

        let parsed: ArtifactManifest = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.kernel_version.is_none());
    }

    // ── Validation ──────────────────────────────────────────────────────

    #[test]
    fn validate_ok() {
        assert!(valid_manifest().validate().is_ok());
    }

    #[test]
    fn validate_bad_version() {
        let mut m = valid_manifest();
        m.manifest_version = 2;
        assert_eq!(
            m.validate().unwrap_err(),
            ValidationError::UnsupportedVersion(2)
        );
    }

    #[test]
    fn validate_sha256_wrong_length() {
        let mut m = valid_manifest();
        m.sha256 = "abc".into();
        assert_eq!(
            m.validate().unwrap_err(),
            ValidationError::InvalidSha256Length(3)
        );
    }

    #[test]
    fn validate_sha256_non_hex() {
        let mut m = valid_manifest();
        m.sha256 = format!("{}zzzz", "a".repeat(60));
        assert_eq!(m.validate().unwrap_err(), ValidationError::InvalidSha256Hex);
    }

    #[test]
    fn validate_empty_claw() {
        let mut m = valid_manifest();
        m.claw = String::new();
        assert_eq!(
            m.validate().unwrap_err(),
            ValidationError::EmptyField("claw")
        );
    }

    #[test]
    fn validate_empty_url() {
        let mut m = valid_manifest();
        m.url = String::new();
        assert_eq!(
            m.validate().unwrap_err(),
            ValidationError::EmptyField("url")
        );
    }

    #[test]
    fn validate_rejects_relative_url() {
        let mut m = valid_manifest();
        m.url = "/hermes-agent/x86_64-linux/0.7.0/rootfs.ext4.zst".into();
        assert_eq!(m.validate().unwrap_err(), ValidationError::InvalidUrlScheme);
    }

    #[test]
    fn validate_rejects_invalid_fingerprint() {
        let mut m = valid_manifest();
        m.fingerprint = "short".into();
        assert_eq!(
            m.validate().unwrap_err(),
            ValidationError::InvalidDigestLength {
                field: "fingerprint",
                len: 5,
            }
        );
    }

    #[test]
    fn validate_rejects_invalid_base_rootfs_sha256() {
        let mut m = valid_manifest();
        m.base_rootfs_sha256 = format!("{}zzzz", "b".repeat(60));
        assert_eq!(
            m.validate().unwrap_err(),
            ValidationError::InvalidDigestHex {
                field: "base_rootfs_sha256",
            }
        );
    }

    #[test]
    fn validate_rejects_invalid_installer_plan_sha256() {
        let mut m = valid_manifest();
        m.installer_plan_sha256 = "abc".into();
        assert_eq!(
            m.validate().unwrap_err(),
            ValidationError::InvalidDigestLength {
                field: "installer_plan_sha256",
                len: 3,
            }
        );
    }

    #[test]
    fn validate_rejects_invalid_kernel_sha256() {
        let mut m = valid_manifest();
        m.kernel_sha256 = format!("{}zzzz", "d".repeat(60));
        assert_eq!(
            m.validate().unwrap_err(),
            ValidationError::InvalidDigestHex {
                field: "kernel_sha256",
            }
        );
    }

    // ── Architecture ────────────────────────────────────────────────────

    #[test]
    fn host_arch_is_non_empty() {
        let arch = host_arch();
        assert!(!arch.is_empty());
        assert!(arch.contains('-'), "expected 'arch-os' format, got: {arch}");
    }

    #[test]
    fn check_arch_compatible_with_self() {
        let host = host_arch();
        assert!(check_arch_compatible(&host).is_ok());
    }

    #[test]
    fn check_arch_mismatch() {
        let result = check_arch_compatible("mips-bsd");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("mips-bsd"),
            "error should contain artifact arch: {err}"
        );
    }
}
