//! Phase 1 — debootstrap base installation.
//!
//! Runs `debootstrap --variant=minbase noble <rootfs_dir> http://archive.ubuntu.com/ubuntu`.
//!
//! Debootstrap may exit non-zero on NixOS / minimal environments because
//! `dpkg --configure` needs `/proc` mounted (which we only do in phase 2).
//! We tolerate that specific failure: if the rootfs directory has `/bin`
//! populated, we consider the base install usable and continue.
//! The chroot phase will call `dpkg --configure -a` once mounts are active.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::{Result, RootfsError, RootfsPhase};

const PHASE: RootfsPhase = RootfsPhase::Debootstrap;
const UBUNTU_MIRROR: &str = "http://archive.ubuntu.com/ubuntu";
const UBUNTU_SUITE: &str = "noble";

/// Run debootstrap into `rootfs_dir`.
///
/// Returns `Ok(())` if:
/// - debootstrap exits 0, OR
/// - debootstrap exits non-zero but `<rootfs_dir>/bin` is populated
///   (partial debootstrap that we can recover in chroot phase).
pub fn run(debootstrap_bin: &Path, rootfs_dir: &Path) -> Result<()> {
    println!("[rootfsbuilder] === Phase 1: debootstrap (this takes a few minutes) ===");

    std::fs::create_dir_all(rootfs_dir)
        .map_err(|e| RootfsError::new(PHASE, format!("cannot create rootfs dir: {e}")))?;

    let status = Command::new(debootstrap_bin)
        .args([
            "--variant=minbase",
            UBUNTU_SUITE,
            &rootfs_dir.display().to_string(),
            UBUNTU_MIRROR,
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| RootfsError::new(PHASE, format!("failed to spawn debootstrap: {e}")))?;

    if status.success() {
        println!("[rootfsbuilder] debootstrap base done");
        return Ok(());
    }

    // Non-zero exit: tolerate if rootfs looks populated (common on NixOS).
    let bin_dir = rootfs_dir.join("bin");
    if bin_dir.is_dir() {
        println!(
            "[rootfsbuilder] debootstrap exited non-zero but rootfs looks populated — continuing"
        );
        println!(
            "[rootfsbuilder] (dpkg --configure -a will run inside chroot where /proc is mounted)"
        );
        return Ok(());
    }

    Err(RootfsError::new(
        PHASE,
        format!(
            "debootstrap failed (exit {:?}) and rootfs dir {} is empty",
            status.code(),
            rootfs_dir.display()
        ),
    )
    .with_detail(format!(
        "Try running manually to see full output:\n  sudo {} --variant=minbase {} {} {}",
        debootstrap_bin.display(),
        UBUNTU_SUITE,
        rootfs_dir.display(),
        UBUNTU_MIRROR,
    )))
}

/// Validate that debootstrap left a sensibly populated rootfs.
pub fn validate_rootfs(rootfs_dir: &Path) -> Result<()> {
    let required = ["bin", "usr", "etc"];
    for dir in &required {
        let p = rootfs_dir.join(dir);
        if !p.is_dir() {
            return Err(RootfsError::new(
                PHASE,
                format!(
                    "rootfs appears incomplete: expected directory {} inside {}",
                    dir,
                    rootfs_dir.display()
                ),
            ));
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn validate_rootfs_ok_when_dirs_present() {
        let dir = TempDir::new().unwrap();
        for d in &["bin", "usr", "etc"] {
            fs::create_dir(dir.path().join(d)).unwrap();
        }
        assert!(validate_rootfs(dir.path()).is_ok());
    }

    #[test]
    fn validate_rootfs_fails_missing_dir() {
        let dir = TempDir::new().unwrap();
        // Only create 'bin' — 'usr' and 'etc' are missing.
        fs::create_dir(dir.path().join("bin")).unwrap();
        let err = validate_rootfs(dir.path()).unwrap_err();
        assert_eq!(err.phase, RootfsPhase::Debootstrap);
        assert!(err.to_string().contains("incomplete"));
    }

    #[test]
    fn validate_rootfs_fails_empty_dir() {
        let dir = TempDir::new().unwrap();
        let err = validate_rootfs(dir.path()).unwrap_err();
        assert!(err.to_string().contains("incomplete"));
    }

    #[test]
    fn run_fails_gracefully_on_missing_binary() {
        let dir = TempDir::new().unwrap();
        let fake_bin = dir.path().join("no-such-binary");
        let rootfs = dir.path().join("rootfs");
        // Should return an Err, not panic.
        let result = run(&fake_bin, &rootfs);
        assert!(result.is_err());
    }

    #[test]
    fn run_tolerates_nonzero_exit_with_populated_rootfs() {
        // Simulate the "debootstrap exits 1 but rootfs has /bin" scenario
        // by creating the rootfs/bin dir first and using a script that exits 1.
        let dir = TempDir::new().unwrap();
        let rootfs = dir.path().join("rootfs");
        fs::create_dir_all(rootfs.join("bin")).unwrap();

        // Write a tiny script that exits 1 to mimic debootstrap non-zero exit.
        let fake_debootstrap = dir.path().join("fake-debootstrap");
        fs::write(&fake_debootstrap, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(
            &fake_debootstrap,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        // With /bin populated, run() should tolerate the non-zero exit.
        let result = run(&fake_debootstrap, &rootfs);
        assert!(
            result.is_ok(),
            "should tolerate non-zero exit when rootfs/bin exists"
        );
    }

    #[test]
    fn run_fails_when_nonzero_exit_and_rootfs_empty() {
        let dir = TempDir::new().unwrap();
        let rootfs = dir.path().join("rootfs");
        // Do NOT create rootfs/bin — simulate a fully failed debootstrap.

        let fake_debootstrap = dir.path().join("fake-debootstrap");
        fs::write(&fake_debootstrap, "#!/bin/sh\nmkdir -p \"$3\"\nexit 1\n").unwrap();
        std::fs::set_permissions(
            &fake_debootstrap,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        let result = run(&fake_debootstrap, &rootfs);
        assert!(
            result.is_err(),
            "should fail when rootfs/bin is missing after non-zero exit"
        );
    }
}
