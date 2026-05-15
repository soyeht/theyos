//! Artifact path resolution and staleness helpers (P28).
//!
//! ## Changes in P28
//!
//! Installer shell scripts have been fully removed. The imagebuilder now uses
//! `InstallerPlan` from `vmrunner-rs` to install claws inside build VMs.
//! Staleness is detected solely via image age (days since build).
//! Hash-based staleness using installer scripts is gone.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// All claw types the build pipeline can produce golden rootfs images for.
///
/// Returns only `Tier::Supported` claws — detected/catalog entries don't
/// have builtin installer plans, so pre-building goldens for them would
/// fail. Template-driven claws (detected) bake their goldens on-demand via
/// `install_worker` when a user installs them (see P-46 Fase C).
#[must_use]
pub fn all_claws() -> Vec<&'static str> {
    core_rs::manifest::supported_names()
}

/// Claws that build Rust projects (benefit from cargo cache).
pub static RUST_CLAWS: &[&str] = &["zeroclaw"];

/// Claws that use npm (benefit from npm cache).
pub static NODE_CLAWS: &[&str] = &["openclaw"];

// ── Path helpers ──────────────────────────────────────────────────────────────

/// Path to the golden ext4 image for a claw type.
pub fn golden_image_path(assets_dir: &Path, claw: &str) -> PathBuf {
    assets_dir.join(format!("ubuntu-24.04-{claw}.ext4"))
}

/// Path for the build workspace rootfs copy.
pub fn build_rootfs_path(build_dir: &Path, claw: &str) -> PathBuf {
    build_dir.join(format!("rootfs-{claw}.ext4"))
}

// ── Staleness ─────────────────────────────────────────────────────────────────

/// Age of the golden image in days (999 if missing/unknown).
pub fn image_age_days(assets_dir: &Path, claw: &str) -> u64 {
    let img = golden_image_path(assets_dir, claw);
    if let Ok(meta) = std::fs::metadata(&img) {
        if let Ok(modified) = meta.modified() {
            let age = SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();
            return age.as_secs() / 86400;
        }
    }
    999
}

/// Human-readable file size.
pub fn file_size_human(path: &Path) -> String {
    core_rs::os::file_size_human(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn golden_image_path_format() {
        let dir = TempDir::new().unwrap();
        let p = golden_image_path(dir.path(), "nullclaw");
        assert!(p.to_string_lossy().ends_with("ubuntu-24.04-nullclaw.ext4"));
    }

    #[test]
    fn all_claws_has_eight_entries() {
        assert_eq!(all_claws().len(), 8);
    }

    #[test]
    fn build_rootfs_path_format() {
        let dir = TempDir::new().unwrap();
        let p = build_rootfs_path(dir.path(), "nullclaw");
        assert!(p.to_string_lossy().ends_with("rootfs-nullclaw.ext4"));
    }

    #[test]
    fn image_age_missing_returns_999() {
        let dir = TempDir::new().unwrap();
        let age = image_age_days(dir.path(), "nullclaw");
        assert_eq!(age, 999);
    }

    #[test]
    fn image_age_fresh_returns_zero() {
        let dir = TempDir::new().unwrap();
        let img = golden_image_path(dir.path(), "nullclaw");
        std::fs::write(&img, b"fake").unwrap();
        let age = image_age_days(dir.path(), "nullclaw");
        assert_eq!(age, 0);
    }
}
