//! Artifact metadata, fingerprinting, and DAG-based staleness detection.
//!
//! The artifact DAG is: `base_rootfs → golden → snapshot → warm_pool/instances`.
//!
//! Each artifact has a content-addressed [`Fingerprint`] computed from its
//! inputs.  Staleness is detected by comparing the expected fingerprint
//! (computed from current inputs) against the fingerprint recorded in the
//! artifact's `.meta.json`.  This eliminates the need for age-based staleness
//! or `--force` flags.
//!
//! # Disk layout
//!
//! ```text
//! ~/firecracker/assets/goldens/<claw>/<fingerprint>/
//!     rootfs.ext4
//!     golden.meta.json
//! ~/firecracker/assets/goldens/<claw>/current -> <fingerprint>
//!
//! ~/firecracker/assets/snapshots/<claw>/<fingerprint>/
//!     vmstate.snapshot
//!     mem.snapshot
//!     rootfs.ext4
//!     snapshot.ready
//!     snapshot.meta.json
//! ~/firecracker/assets/snapshots/<claw>/current -> <fingerprint>
//! ```

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Fingerprint ─────────────────────────────────────────────────────────────

/// Content-addressed identifier for an artifact, computed from its inputs.
///
/// Stored as a lowercase hex-encoded SHA-256 digest (64 characters).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint(pub String);

impl Fingerprint {
    /// Create a fingerprint from a hex string.  Does NOT validate format.
    #[must_use]
    pub fn new(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    /// The hex digest string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Short representation for display (first 12 hex chars).
    #[must_use]
    pub fn short(&self) -> &str {
        &self.0[..self.0.len().min(12)]
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Metadata types ──────────────────────────────────────────────────────────

/// Metadata for a golden image.  Written to `golden.meta.json` alongside the
/// rootfs in a fingerprinted directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenMeta {
    /// Claw type this golden was built for (e.g. `"picoclaw"`).
    pub claw_type: String,
    /// Content-addressed fingerprint computed from the build inputs.
    pub fingerprint: Fingerprint,
    /// SHA-256 hex digest of the base rootfs file used as the build source.
    pub base_rootfs_sha256: String,
    /// SHA-256 hex digest of the expanded `InstallerPlan` (with env vars resolved).
    pub installer_plan_sha256: String,
    /// SHA-256 hex digest of the kernel image (`vmlinux`) used during the build.
    pub kernel_sha256: String,
    /// Builder version identifier (git rev or imagebuilder version string).
    pub builder_version: String,
    /// ISO 8601 timestamp when the golden was created.
    pub created_at: String,
}

/// Metadata for a snapshot.  Written to `snapshot.meta.json` alongside the
/// snapshot files in a fingerprinted directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// Claw type this snapshot was built for (e.g. `"picoclaw"`).
    pub claw_type: String,
    /// Content-addressed fingerprint of this snapshot.
    pub fingerprint: Fingerprint,
    /// Fingerprint of the golden image this snapshot was built from.
    pub golden_fingerprint: Fingerprint,
    /// SHA-256 hex digest of the kernel image used.
    pub kernel_sha256: String,
    /// Builder version identifier.
    pub builder_version: String,
    /// ISO 8601 timestamp when the snapshot was created.
    pub created_at: String,
}

// ── Staleness ───────────────────────────────────────────────────────────────

/// Reason why an artifact is considered stale and needs rebuilding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleReason {
    /// No artifact exists at all.
    Missing,
    /// Artifact exists but has no metadata file (pre-migration artifact).
    NoMetadata,
    /// A specific input changed compared to the recorded metadata.
    InputChanged {
        /// Which input field changed (e.g. `"base_rootfs_sha256"`).
        field: String,
    },
    /// The `--force` flag was used.
    Forced,
}

impl std::fmt::Display for StaleReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "missing"),
            Self::NoMetadata => write!(f, "no metadata (pre-migration artifact)"),
            Self::InputChanged { field } => write!(f, "input changed: {field}"),
            Self::Forced => write!(f, "forced"),
        }
    }
}

// ── Fingerprint computation ─────────────────────────────────────────────────

/// Compute the golden fingerprint from its build inputs.
///
/// `fingerprint = SHA-256(base_rootfs_sha256 || ":" || installer_plan_sha256 || ":" || kernel_sha256)`
#[must_use]
pub fn golden_fingerprint(
    base_rootfs_sha256: &str,
    installer_plan_sha256: &str,
    kernel_sha256: &str,
) -> Fingerprint {
    let mut hasher = Sha256::new();
    hasher.update(base_rootfs_sha256.as_bytes());
    hasher.update(b":");
    hasher.update(installer_plan_sha256.as_bytes());
    hasher.update(b":");
    hasher.update(kernel_sha256.as_bytes());
    Fingerprint(hex::encode(hasher.finalize()))
}

/// Compute the snapshot fingerprint from its inputs.
///
/// `fingerprint = SHA-256(golden_fingerprint || ":" || kernel_sha256)`
#[must_use]
pub fn snapshot_fingerprint(golden_fp: &Fingerprint, kernel_sha256: &str) -> Fingerprint {
    let mut hasher = Sha256::new();
    hasher.update(golden_fp.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(kernel_sha256.as_bytes());
    Fingerprint(hex::encode(hasher.finalize()))
}

// ── Staleness detection ─────────────────────────────────────────────────────

/// Determine why a golden image is stale, or `None` if it's fresh.
///
/// Compares the recorded metadata against the expected fingerprint computed
/// from the current build inputs.
#[must_use]
pub fn golden_stale_reason(
    current_meta: Option<&GoldenMeta>,
    expected_fp: &Fingerprint,
) -> Option<StaleReason> {
    let Some(meta) = current_meta else {
        return Some(StaleReason::Missing);
    };
    if meta.fingerprint == *expected_fp {
        return None; // fresh
    }
    // Determine which specific input changed for diagnostics
    // (the caller already computed the expected fingerprint, but we report
    //  the most likely cause by re-checking individual fields)
    Some(StaleReason::InputChanged {
        field: "fingerprint mismatch".to_string(),
    })
}

/// Determine why a golden is stale with field-level detail.
///
/// Compares each input field individually to identify the exact cause.
#[must_use]
pub fn golden_stale_reason_detailed(
    current_meta: Option<&GoldenMeta>,
    base_rootfs_sha256: &str,
    installer_plan_sha256: &str,
    kernel_sha256: &str,
) -> Option<StaleReason> {
    let Some(meta) = current_meta else {
        return Some(StaleReason::Missing);
    };
    if meta.base_rootfs_sha256 != base_rootfs_sha256 {
        return Some(StaleReason::InputChanged {
            field: "base_rootfs_sha256".to_string(),
        });
    }
    if meta.installer_plan_sha256 != installer_plan_sha256 {
        return Some(StaleReason::InputChanged {
            field: "installer_plan_sha256".to_string(),
        });
    }
    if meta.kernel_sha256 != kernel_sha256 {
        return Some(StaleReason::InputChanged {
            field: "kernel_sha256".to_string(),
        });
    }
    // All individual fields match — fingerprint should also match.
    // Double-check to catch implementation bugs.
    let expected = golden_fingerprint(base_rootfs_sha256, installer_plan_sha256, kernel_sha256);
    if meta.fingerprint != expected {
        return Some(StaleReason::InputChanged {
            field: "fingerprint (computed mismatch despite matching fields)".to_string(),
        });
    }
    None // fresh
}

/// Determine why a snapshot is stale relative to its golden, or `None` if fresh.
#[must_use]
pub fn snapshot_stale_reason(
    current_meta: Option<&SnapshotMeta>,
    golden_meta: &GoldenMeta,
) -> Option<StaleReason> {
    let Some(meta) = current_meta else {
        return Some(StaleReason::Missing);
    };
    if meta.golden_fingerprint != golden_meta.fingerprint {
        return Some(StaleReason::InputChanged {
            field: "golden_fingerprint".to_string(),
        });
    }
    if meta.kernel_sha256 != golden_meta.kernel_sha256 {
        return Some(StaleReason::InputChanged {
            field: "kernel_sha256".to_string(),
        });
    }
    None // fresh
}

// ── File hashing ────────────────────────────────────────────────────────────

/// Compute the SHA-256 hex digest of a file using the system `sha256sum` command.
///
/// Prefer this over in-process hashing for large files (rootfs images) as
/// `sha256sum` can use SHA-NI hardware acceleration.
///
/// # Errors
///
/// Returns an error if the file does not exist or `sha256sum` is not available.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("sha256sum: {e}")))?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "sha256sum failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    // Output format: "<hash>  <filename>\n"
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .next()
        .map(String::from)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "sha256sum: unexpected output format",
            )
        })
}

/// Compute the SHA-256 hex digest of a byte slice in-process.
///
/// Use this for small inputs (metadata strings, plan hashes).
/// For large files (rootfs images), use [`sha256_file`] instead.
#[must_use]
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ── Metadata I/O ────────────────────────────────────────────────────────────

/// Read and deserialize a `.meta.json` file.
///
/// Returns `None` if the file does not exist or is malformed.
#[must_use]
pub fn read_meta<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Serialize and write a `.meta.json` file atomically.
///
/// Writes to a temporary file in the same directory, then renames.  This
/// ensures readers never see a partial write.
///
/// # Errors
///
/// Returns an error if the directory does not exist or the write fails.
pub fn write_meta<T: Serialize>(path: &Path, meta: &T) -> io::Result<()> {
    let json = serde_json::to_string_pretty(meta).map_err(io::Error::other)?;

    let dir = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "meta path has no parent dir")
    })?;

    // Write to a temp file in the same directory, then rename for atomicity.
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    std::fs::write(&tmp, json.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ── Path helpers ────────────────────────────────────────────────────────────

/// Base directory for golden images: `<assets_dir>/goldens/<claw>/`
#[must_use]
pub fn golden_claw_dir(assets_dir: &Path, claw: &str) -> PathBuf {
    assets_dir.join("goldens").join(claw)
}

/// Directory for a specific golden version: `<assets_dir>/goldens/<claw>/<fingerprint>/`
#[must_use]
pub fn golden_version_dir(assets_dir: &Path, claw: &str, fp: &Fingerprint) -> PathBuf {
    golden_claw_dir(assets_dir, claw).join(fp.as_str())
}

/// Path to the `current` symlink for a claw's golden: `<assets_dir>/goldens/<claw>/current`
#[must_use]
pub fn golden_current_link(assets_dir: &Path, claw: &str) -> PathBuf {
    golden_claw_dir(assets_dir, claw).join("current")
}

/// Resolve the current golden rootfs for a claw.
///
/// Returns `Some(<path_to_rootfs.ext4>)` if the `current` symlink exists and
/// the target directory contains `rootfs.ext4`.  Returns `None` otherwise.
#[must_use]
pub fn golden_current_rootfs(assets_dir: &Path, claw: &str) -> Option<PathBuf> {
    let link = golden_current_link(assets_dir, claw);
    let target = std::fs::read_link(&link).ok()?;
    // Symlink is relative (just the fingerprint dir name)
    let abs = if target.is_relative() {
        link.parent()?.join(&target)
    } else {
        target
    };
    let rootfs = abs.join("rootfs.ext4");
    rootfs.exists().then_some(rootfs)
}

/// Read the golden metadata from the current version.
#[must_use]
pub fn read_current_golden_meta(assets_dir: &Path, claw: &str) -> Option<GoldenMeta> {
    let link = golden_current_link(assets_dir, claw);
    let target = std::fs::read_link(&link).ok()?;
    let abs = if target.is_relative() {
        link.parent()?.join(&target)
    } else {
        target
    };
    read_meta(&abs.join("golden.meta.json"))
}

/// Update the `current` symlink to point to a new fingerprint.
///
/// Creates the parent directories if needed.  Replaces any existing symlink
/// atomically (create new link, then rename over old).
///
/// # Errors
///
/// Returns an error if the symlink cannot be created.
pub fn update_current_link(link_path: &Path, fingerprint: &Fingerprint) -> io::Result<()> {
    if let Some(parent) = link_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Atomic symlink update: create temp link, rename over target.
    let tmp_link = link_path.with_extension("tmp");
    if tmp_link.exists() || tmp_link.symlink_metadata().is_ok() {
        std::fs::remove_file(&tmp_link)?;
    }
    std::os::unix::fs::symlink(fingerprint.as_str(), &tmp_link)?;
    std::fs::rename(&tmp_link, link_path)?;
    Ok(())
}

// ── Snapshot path helpers ───────────────────────────────────────────────────

/// Base directory for snapshots: `<assets_dir>/snapshots/<claw>/`
#[must_use]
pub fn snapshot_claw_dir(assets_dir: &Path, claw: &str) -> PathBuf {
    assets_dir.join("snapshots").join(claw)
}

/// Directory for a specific snapshot version: `<assets_dir>/snapshots/<claw>/<fingerprint>/`
#[must_use]
pub fn snapshot_version_dir(assets_dir: &Path, claw: &str, fp: &Fingerprint) -> PathBuf {
    snapshot_claw_dir(assets_dir, claw).join(fp.as_str())
}

/// Path to the `current` symlink for a claw's snapshot.
#[must_use]
pub fn snapshot_current_link(assets_dir: &Path, claw: &str) -> PathBuf {
    snapshot_claw_dir(assets_dir, claw).join("current")
}

/// Read the snapshot metadata from the current version.
#[must_use]
pub fn read_current_snapshot_meta(assets_dir: &Path, claw: &str) -> Option<SnapshotMeta> {
    let link = snapshot_current_link(assets_dir, claw);
    let target = std::fs::read_link(&link).ok()?;
    let abs = if target.is_relative() {
        link.parent()?.join(&target)
    } else {
        target
    };
    read_meta(&abs.join("snapshot.meta.json"))
}

// ── Hex encoding (inline, no dep) ──────────────────────────────────────────

mod hex {
    /// Encode bytes as lowercase hex string.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
