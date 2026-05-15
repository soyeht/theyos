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
mod tests {
    use super::*;

    // ── Fingerprint ─────────────────────────────────────────────────────

    #[test]
    fn fingerprint_new_and_display() {
        let fp = Fingerprint::new("abc123def456");
        assert_eq!(fp.as_str(), "abc123def456");
        assert_eq!(fp.to_string(), "abc123def456");
    }

    #[test]
    fn fingerprint_short_truncates_to_12() {
        let fp = Fingerprint::new("abcdef012345678901234567890123456789");
        assert_eq!(fp.short(), "abcdef012345");
    }

    #[test]
    fn fingerprint_short_on_short_string() {
        let fp = Fingerprint::new("abc");
        assert_eq!(fp.short(), "abc");
    }

    #[test]
    fn fingerprint_equality() {
        let a = Fingerprint::new("aaa");
        let b = Fingerprint::new("aaa");
        let c = Fingerprint::new("bbb");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── Golden fingerprint computation ──────────────────────────────────

    #[test]
    fn golden_fingerprint_deterministic() {
        let fp1 = golden_fingerprint("rootfs_hash", "plan_hash", "kernel_hash");
        let fp2 = golden_fingerprint("rootfs_hash", "plan_hash", "kernel_hash");
        assert_eq!(fp1, fp2, "same inputs must produce same fingerprint");
    }

    #[test]
    fn golden_fingerprint_changes_with_rootfs() {
        let fp1 = golden_fingerprint("rootfs_a", "plan", "kernel");
        let fp2 = golden_fingerprint("rootfs_b", "plan", "kernel");
        assert_ne!(
            fp1, fp2,
            "different rootfs must produce different fingerprint"
        );
    }

    #[test]
    fn golden_fingerprint_changes_with_plan() {
        let fp1 = golden_fingerprint("rootfs", "plan_a", "kernel");
        let fp2 = golden_fingerprint("rootfs", "plan_b", "kernel");
        assert_ne!(
            fp1, fp2,
            "different plan must produce different fingerprint"
        );
    }

    #[test]
    fn golden_fingerprint_changes_with_kernel() {
        let fp1 = golden_fingerprint("rootfs", "plan", "kernel_a");
        let fp2 = golden_fingerprint("rootfs", "plan", "kernel_b");
        assert_ne!(
            fp1, fp2,
            "different kernel must produce different fingerprint"
        );
    }

    #[test]
    fn golden_fingerprint_is_64_hex_chars() {
        let fp = golden_fingerprint("r", "p", "k");
        assert_eq!(fp.as_str().len(), 64, "SHA-256 hex digest is 64 chars");
        assert!(
            fp.as_str().chars().all(|c| c.is_ascii_hexdigit()),
            "must be hex"
        );
    }

    // ── Snapshot fingerprint computation ────────────────────────────────

    #[test]
    fn snapshot_fingerprint_deterministic() {
        let gfp = Fingerprint::new("golden123");
        let fp1 = snapshot_fingerprint(&gfp, "kernel_hash");
        let fp2 = snapshot_fingerprint(&gfp, "kernel_hash");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn snapshot_fingerprint_changes_with_golden() {
        let fp1 = snapshot_fingerprint(&Fingerprint::new("golden_a"), "kernel");
        let fp2 = snapshot_fingerprint(&Fingerprint::new("golden_b"), "kernel");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn snapshot_fingerprint_changes_with_kernel() {
        let gfp = Fingerprint::new("golden");
        let fp1 = snapshot_fingerprint(&gfp, "kernel_a");
        let fp2 = snapshot_fingerprint(&gfp, "kernel_b");
        assert_ne!(fp1, fp2);
    }

    // ── Staleness detection ─────────────────────────────────────────────

    #[test]
    fn golden_stale_when_missing() {
        let expected = Fingerprint::new("expected");
        let reason = golden_stale_reason(None, &expected);
        assert_eq!(reason, Some(StaleReason::Missing));
    }

    #[test]
    fn golden_fresh_when_fingerprint_matches() {
        let fp = golden_fingerprint("r", "p", "k");
        let meta = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: fp.clone(),
            base_rootfs_sha256: "r".into(),
            installer_plan_sha256: "p".into(),
            kernel_sha256: "k".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        assert_eq!(golden_stale_reason(Some(&meta), &fp), None);
    }

    #[test]
    fn golden_stale_when_fingerprint_differs() {
        let fp = golden_fingerprint("r", "p", "k");
        let meta = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: Fingerprint::new("old_fingerprint"),
            base_rootfs_sha256: "r_old".into(),
            installer_plan_sha256: "p".into(),
            kernel_sha256: "k".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        let reason = golden_stale_reason(Some(&meta), &fp);
        assert!(reason.is_some());
        assert!(matches!(reason, Some(StaleReason::InputChanged { .. })));
    }

    #[test]
    fn golden_stale_detailed_identifies_rootfs_change() {
        let meta = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: golden_fingerprint("old_rootfs", "p", "k"),
            base_rootfs_sha256: "old_rootfs".into(),
            installer_plan_sha256: "p".into(),
            kernel_sha256: "k".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        let reason = golden_stale_reason_detailed(Some(&meta), "new_rootfs", "p", "k");
        assert_eq!(
            reason,
            Some(StaleReason::InputChanged {
                field: "base_rootfs_sha256".into()
            })
        );
    }

    #[test]
    fn golden_stale_detailed_identifies_plan_change() {
        let meta = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: golden_fingerprint("r", "old_plan", "k"),
            base_rootfs_sha256: "r".into(),
            installer_plan_sha256: "old_plan".into(),
            kernel_sha256: "k".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        let reason = golden_stale_reason_detailed(Some(&meta), "r", "new_plan", "k");
        assert_eq!(
            reason,
            Some(StaleReason::InputChanged {
                field: "installer_plan_sha256".into()
            })
        );
    }

    #[test]
    fn golden_stale_detailed_identifies_kernel_change() {
        let meta = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: golden_fingerprint("r", "p", "old_kernel"),
            base_rootfs_sha256: "r".into(),
            installer_plan_sha256: "p".into(),
            kernel_sha256: "old_kernel".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        let reason = golden_stale_reason_detailed(Some(&meta), "r", "p", "new_kernel");
        assert_eq!(
            reason,
            Some(StaleReason::InputChanged {
                field: "kernel_sha256".into()
            })
        );
    }

    #[test]
    fn golden_stale_detailed_fresh_when_all_match() {
        let meta = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: golden_fingerprint("r", "p", "k"),
            base_rootfs_sha256: "r".into(),
            installer_plan_sha256: "p".into(),
            kernel_sha256: "k".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        assert_eq!(
            golden_stale_reason_detailed(Some(&meta), "r", "p", "k"),
            None
        );
    }

    #[test]
    fn snapshot_stale_when_missing() {
        let golden = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: Fingerprint::new("golden_fp"),
            base_rootfs_sha256: "r".into(),
            installer_plan_sha256: "p".into(),
            kernel_sha256: "k".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        assert_eq!(
            snapshot_stale_reason(None, &golden),
            Some(StaleReason::Missing)
        );
    }

    #[test]
    fn snapshot_fresh_when_golden_matches() {
        let golden = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: Fingerprint::new("golden_fp"),
            base_rootfs_sha256: "r".into(),
            installer_plan_sha256: "p".into(),
            kernel_sha256: "k".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        let snap = SnapshotMeta {
            claw_type: "picoclaw".into(),
            fingerprint: Fingerprint::new("snap_fp"),
            golden_fingerprint: Fingerprint::new("golden_fp"),
            kernel_sha256: "k".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        assert_eq!(snapshot_stale_reason(Some(&snap), &golden), None);
    }

    #[test]
    fn snapshot_stale_when_golden_changed() {
        let golden = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: Fingerprint::new("new_golden_fp"),
            base_rootfs_sha256: "r".into(),
            installer_plan_sha256: "p".into(),
            kernel_sha256: "k".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        let snap = SnapshotMeta {
            claw_type: "picoclaw".into(),
            fingerprint: Fingerprint::new("snap_fp"),
            golden_fingerprint: Fingerprint::new("old_golden_fp"),
            kernel_sha256: "k".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        assert_eq!(
            snapshot_stale_reason(Some(&snap), &golden),
            Some(StaleReason::InputChanged {
                field: "golden_fingerprint".into()
            })
        );
    }

    #[test]
    fn snapshot_stale_when_kernel_changed() {
        let golden = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: Fingerprint::new("golden_fp"),
            base_rootfs_sha256: "r".into(),
            installer_plan_sha256: "p".into(),
            kernel_sha256: "new_kernel".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        let snap = SnapshotMeta {
            claw_type: "picoclaw".into(),
            fingerprint: Fingerprint::new("snap_fp"),
            golden_fingerprint: Fingerprint::new("golden_fp"),
            kernel_sha256: "old_kernel".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        assert_eq!(
            snapshot_stale_reason(Some(&snap), &golden),
            Some(StaleReason::InputChanged {
                field: "kernel_sha256".into()
            })
        );
    }

    // ── sha256_bytes ────────────────────────────────────────────────────

    #[test]
    fn sha256_bytes_deterministic() {
        let h1 = sha256_bytes(b"hello world");
        let h2 = sha256_bytes(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_bytes_is_64_hex_chars() {
        let h = sha256_bytes(b"test");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_bytes_known_value() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = sha256_bytes(b"");
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ── sha256_file ─────────────────────────────────────────────────────

    #[test]
    fn sha256_file_works_on_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"deterministic content").unwrap();

        let h1 = sha256_file(&path).unwrap();
        let h2 = sha256_file(&path).unwrap();
        assert_eq!(h1, h2, "same file must produce same hash");
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn sha256_file_matches_sha256_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        let content = b"cross check";
        std::fs::write(&path, content).unwrap();

        let file_hash = sha256_file(&path).unwrap();
        let bytes_hash = sha256_bytes(content);
        assert_eq!(
            file_hash, bytes_hash,
            "file hash must match in-process hash"
        );
    }

    #[test]
    fn sha256_file_error_on_missing_file() {
        let result = sha256_file(Path::new("/nonexistent/file.bin"));
        assert!(result.is_err());
    }

    // ── Meta I/O ────────────────────────────────────────────────────────

    #[test]
    fn meta_round_trip_golden() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("golden.meta.json");
        let meta = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: Fingerprint::new("abc123"),
            base_rootfs_sha256: "rootfs_hash".into(),
            installer_plan_sha256: "plan_hash".into(),
            kernel_sha256: "kernel_hash".into(),
            builder_version: "v1.0.0".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };

        write_meta(&path, &meta).unwrap();
        let loaded: GoldenMeta = read_meta(&path).unwrap();
        assert_eq!(loaded.claw_type, "picoclaw");
        assert_eq!(loaded.fingerprint, Fingerprint::new("abc123"));
        assert_eq!(loaded.base_rootfs_sha256, "rootfs_hash");
        assert_eq!(loaded.installer_plan_sha256, "plan_hash");
        assert_eq!(loaded.kernel_sha256, "kernel_hash");
    }

    #[test]
    fn meta_round_trip_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.meta.json");
        let meta = SnapshotMeta {
            claw_type: "picoclaw".into(),
            fingerprint: Fingerprint::new("snap_fp"),
            golden_fingerprint: Fingerprint::new("golden_fp"),
            kernel_sha256: "kernel_hash".into(),
            builder_version: "v1.0.0".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };

        write_meta(&path, &meta).unwrap();
        let loaded: SnapshotMeta = read_meta(&path).unwrap();
        assert_eq!(loaded.claw_type, "picoclaw");
        assert_eq!(loaded.golden_fingerprint, Fingerprint::new("golden_fp"));
    }

    #[test]
    fn read_meta_returns_none_for_missing_file() {
        let result: Option<GoldenMeta> = read_meta(Path::new("/nonexistent/meta.json"));
        assert!(result.is_none());
    }

    #[test]
    fn read_meta_returns_none_for_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.meta.json");
        std::fs::write(&path, "not json").unwrap();
        let result: Option<GoldenMeta> = read_meta(&path);
        assert!(result.is_none());
    }

    // ── Path helpers ────────────────────────────────────────────────────

    #[test]
    fn golden_claw_dir_format() {
        let p = golden_claw_dir(Path::new("/assets"), "picoclaw");
        assert_eq!(p, PathBuf::from("/assets/goldens/picoclaw"));
    }

    #[test]
    fn golden_version_dir_format() {
        let fp = Fingerprint::new("abc123");
        let p = golden_version_dir(Path::new("/assets"), "picoclaw", &fp);
        assert_eq!(p, PathBuf::from("/assets/goldens/picoclaw/abc123"));
    }

    #[test]
    fn golden_current_link_format() {
        let p = golden_current_link(Path::new("/assets"), "picoclaw");
        assert_eq!(p, PathBuf::from("/assets/goldens/picoclaw/current"));
    }

    #[test]
    fn snapshot_claw_dir_format() {
        let p = snapshot_claw_dir(Path::new("/assets"), "picoclaw");
        assert_eq!(p, PathBuf::from("/assets/snapshots/picoclaw"));
    }

    #[test]
    fn snapshot_current_link_format() {
        let p = snapshot_current_link(Path::new("/assets"), "picoclaw");
        assert_eq!(p, PathBuf::from("/assets/snapshots/picoclaw/current"));
    }

    // ── Symlink helpers ─────────────────────────────────────────────────

    #[test]
    fn update_current_link_creates_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("goldens").join("picoclaw").join("current");
        let fp = Fingerprint::new("abc123");

        update_current_link(&link, &fp).unwrap();

        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        let target = std::fs::read_link(&link).unwrap();
        assert_eq!(target.to_str().unwrap(), "abc123");
    }

    #[test]
    fn update_current_link_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("goldens").join("picoclaw").join("current");
        let fp1 = Fingerprint::new("old_fp");
        let fp2 = Fingerprint::new("new_fp");

        update_current_link(&link, &fp1).unwrap();
        update_current_link(&link, &fp2).unwrap();

        let target = std::fs::read_link(&link).unwrap();
        assert_eq!(target.to_str().unwrap(), "new_fp");
    }

    #[test]
    fn golden_current_rootfs_resolves_through_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let assets = dir.path();

        // Set up: goldens/picoclaw/abc123/rootfs.ext4
        let fp = Fingerprint::new("abc123");
        let ver_dir = golden_version_dir(assets, "picoclaw", &fp);
        std::fs::create_dir_all(&ver_dir).unwrap();
        std::fs::write(ver_dir.join("rootfs.ext4"), b"fake rootfs").unwrap();

        // Create current -> abc123
        let link = golden_current_link(assets, "picoclaw");
        update_current_link(&link, &fp).unwrap();

        // Resolve
        let rootfs = golden_current_rootfs(assets, "picoclaw").unwrap();
        assert!(rootfs.ends_with("abc123/rootfs.ext4"));
        assert!(rootfs.exists());
    }

    #[test]
    fn golden_current_rootfs_returns_none_without_symlink() {
        let dir = tempfile::tempdir().unwrap();
        assert!(golden_current_rootfs(dir.path(), "picoclaw").is_none());
    }

    #[test]
    fn read_current_golden_meta_works() {
        let dir = tempfile::tempdir().unwrap();
        let assets = dir.path();

        let fp = Fingerprint::new("abc123");
        let ver_dir = golden_version_dir(assets, "picoclaw", &fp);
        std::fs::create_dir_all(&ver_dir).unwrap();

        let meta = GoldenMeta {
            claw_type: "picoclaw".into(),
            fingerprint: fp.clone(),
            base_rootfs_sha256: "r".into(),
            installer_plan_sha256: "p".into(),
            kernel_sha256: "k".into(),
            builder_version: "test".into(),
            created_at: "2026-03-09T00:00:00Z".into(),
        };
        write_meta(&ver_dir.join("golden.meta.json"), &meta).unwrap();

        let link = golden_current_link(assets, "picoclaw");
        update_current_link(&link, &fp).unwrap();

        let loaded = read_current_golden_meta(assets, "picoclaw").unwrap();
        assert_eq!(loaded.claw_type, "picoclaw");
        assert_eq!(loaded.fingerprint, fp);
    }

    // ── StaleReason Display ─────────────────────────────────────────────

    #[test]
    fn stale_reason_display() {
        assert_eq!(StaleReason::Missing.to_string(), "missing");
        assert_eq!(
            StaleReason::NoMetadata.to_string(),
            "no metadata (pre-migration artifact)"
        );
        assert_eq!(StaleReason::Forced.to_string(), "forced");
        assert_eq!(
            StaleReason::InputChanged {
                field: "base_rootfs_sha256".into()
            }
            .to_string(),
            "input changed: base_rootfs_sha256"
        );
    }

    // ── hex encoding ────────────────────────────────────────────────────

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex::encode(b""), "");
    }

    #[test]
    fn hex_encode_known() {
        assert_eq!(hex::encode([0x00, 0xff, 0xab]), "00ffab");
    }
}
