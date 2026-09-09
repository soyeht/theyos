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
    #[error(
        "url uses insecure http:// scheme for a non-loopback host (https required in production)"
    )]
    InsecureUrlScheme,
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

        // Production artifacts must travel over HTTPS. `http://` is permitted
        // only for loopback hosts (local test fixtures) - see
        // [`is_secure_artifact_url`].
        if !is_secure_artifact_url(&self.url) {
            return Err(ValidationError::InsecureUrlScheme);
        }

        Ok(())
    }
}

// ── URL scheme policy ─────────────────────────────────────────────────────────

/// Whether `url` is acceptable as a production artifact URL.
///
/// Policy:
/// - `https://...` is always accepted.
/// - `http://...` is accepted **only** when the host is loopback
///   (`127.0.0.1`, `localhost`, or `::1`), which covers local test fixtures
///   and same-host registries where there is no meaningful MITM surface.
/// - Anything else (public `http://`, missing/unknown scheme) is rejected.
///
/// This is the single source of truth for the HTTP-to-HTTPS policy and is applied
/// to both manifest download URLs ([`ArtifactManifest::validate`]) and the
/// artifact registry base URL (including the `THEYOS_ARTIFACT_REGISTRY_URL`
/// override), so an environment override cannot reintroduce an insecure scheme.
///
/// The host is parsed defensively: userinfo (`user@host`) is stripped so a
/// crafted `http://127.0.0.1@evil.com/...` resolves to the real host `evil.com`
/// and is rejected; IPv6 literals (`[::1]`) and `:port` suffixes are handled.
#[must_use]
pub fn is_secure_artifact_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return true;
    }
    if let Some(after_scheme) = lower.strip_prefix("http://") {
        return host_is_loopback(after_scheme);
    }
    false
}

/// Extract the host from the authority that follows `http://` (already
/// lowercased) and decide whether it is a loopback host.
fn host_is_loopback(after_scheme: &str) -> bool {
    // The authority ends at the first '/', '?', or '#'.
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];

    // Strip any `userinfo@` - the host is whatever follows the LAST '@'.
    let host_port = match authority.rsplit_once('@') {
        Some((_userinfo, host_port)) => host_port,
        None => authority,
    };

    // IPv6 literals are bracketed: `[::1]` or `[::1]:port`.
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return false; // unclosed bracket
        };
        // The only legal authority after `]` is empty or a `:port`. A
        // non-empty, non-port suffix (e.g. `[::1]evil.example`) is a malformed
        // authority and must fail closed rather than trust the bracketed host.
        if !suffix.is_empty() && !is_port_suffix(suffix) {
            return false;
        }
        host
    } else {
        // Split an optional `:port`; a present port must be all ASCII digits,
        // otherwise the authority is malformed (e.g. `127.0.0.1:notaport`).
        match host_port.rsplit_once(':') {
            Some((host, port)) => {
                if !is_ascii_digits(port) {
                    return false;
                }
                host
            }
            None => host_port,
        }
    };

    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// Whether `suffix` is a legal `:port` - a `:` followed by 1+ ASCII digits.
fn is_port_suffix(suffix: &str) -> bool {
    matches!(suffix.strip_prefix(':'), Some(port) if is_ascii_digits(port))
}

/// Whether `s` is a non-empty run of ASCII digits.
fn is_ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
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

// Runtime compatibility

/// Error from [`check_runtime_compatible`].
///
/// Messages are safe to surface to clients/status: they contain only version
/// strings, never local paths or host identifiers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeCompatError {
    #[error("claw requires theyOS runtime {required} or newer, but this engine is {current}")]
    RuntimeTooOld { required: String, current: String },
    #[error("manifest runtime_min_version `{value}` is not valid semver")]
    RuntimeVersionUnparseable { value: String },
    #[error("engine version `{value}` is not valid semver")]
    EngineVersionUnparseable { value: String },
}

/// Check whether the running engine satisfies a manifest's `runtime_min_version`.
///
/// Semantics:
/// - `runtime_min_version` absent (`None`) -> **fail-open** (`Ok`). The field is
///   optional and the currently published manifests omit it, so a missing
///   minimum must never block an install.
/// - present and `current_engine_version >= min` -> `Ok`.
/// - present and `current_engine_version < min` -> [`RuntimeCompatError::RuntimeTooOld`]
///   (**fail-closed**).
/// - present but not valid semver -> [`RuntimeCompatError::RuntimeVersionUnparseable`]
///   (**fail-closed**: do not silently ignore a gate the publisher intended).
///
/// Comparison uses full semver precedence including prerelease ordering, so a
/// prerelease engine is older than the equivalent release (`1.2.0-rc.1 < 1.2.0`).
/// `current_engine_version` is normally `env!("CARGO_PKG_VERSION")`, which is
/// always valid semver; an unparseable value still fails closed rather than
/// panicking.
///
/// NOTE: this gate is only as trustworthy as the manifest it reads. Until
/// artifact manifests are signed (P0.1), `runtime_min_version` could be lowered
/// by anyone who controls the manifest. The gate is nonetheless semantically
/// correct and, once P0.1 lands, runs on the signature-verified manifest.
///
/// # Errors
///
/// Returns [`RuntimeCompatError`] when the engine is too old or a version
/// string cannot be parsed.
pub fn check_runtime_compatible(
    runtime_min_version: Option<&str>,
    current_engine_version: &str,
) -> Result<(), RuntimeCompatError> {
    let Some(min_raw) = runtime_min_version else {
        return Ok(());
    };
    let min = semver::Version::parse(min_raw).map_err(|_| {
        RuntimeCompatError::RuntimeVersionUnparseable {
            value: min_raw.to_string(),
        }
    })?;
    let current = semver::Version::parse(current_engine_version).map_err(|_| {
        RuntimeCompatError::EngineVersionUnparseable {
            value: current_engine_version.to_string(),
        }
    })?;
    if current < min {
        return Err(RuntimeCompatError::RuntimeTooOld {
            required: min.to_string(),
            current: current.to_string(),
        });
    }
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
