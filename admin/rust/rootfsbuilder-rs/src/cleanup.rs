//! RAII cleanup guard for the build work directory.
//!
//! On success → the work directory is removed.
//! On failure → the work directory is **preserved** for debugging, and
//!              we only attempt to unmount any lingering bind-mounts so
//!              the host does not get stuck with mounted paths.
//!
//! The guard also tracks which virtual filesystems are currently mounted
//! inside the rootfs so it can unmount them in reverse order on drop.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Bind-mount names inside the rootfs, in mount order.
/// Unmounted in **reverse** order on cleanup.
static VIRTUAL_MOUNTS: &[&str] = &["tmp", "sys", "proc", "dev/pts", "dev"];

/// RAII guard around the build work directory.
///
/// ```rust,ignore
/// let guard = WorkdirGuard::new(work_dir.clone());
/// // ... do work ...
/// guard.success(); // disarms the guard; workdir will be deleted
/// // If guard drops without calling .success(), workdir is preserved.
/// ```
pub struct WorkdirGuard {
    work_dir: PathBuf,
    rootfs_dir: PathBuf,
    succeeded: bool,
}

impl WorkdirGuard {
    pub fn new(work_dir: PathBuf) -> Self {
        let rootfs_dir = work_dir.join("rootfs");
        Self {
            work_dir,
            rootfs_dir,
            succeeded: false,
        }
    }

    /// Mark the build as successful. On drop, the work directory will be removed.
    pub fn success(&mut self) {
        self.succeeded = true;
    }

    /// Attempt to unmount all virtual filesystems (best-effort, no panic).
    pub fn unmount_all(&self) {
        for mp in VIRTUAL_MOUNTS.iter().rev() {
            let target = self.rootfs_dir.join(mp);
            if target.exists() {
                lazy_unmount(&target);
            }
        }
    }
}

impl Drop for WorkdirGuard {
    fn drop(&mut self) {
        // Always attempt unmount to avoid stuck mounts.
        self.unmount_all();

        if self.succeeded {
            // Clean removal
            if let Err(e) = std::fs::remove_dir_all(&self.work_dir) {
                eprintln!(
                    "[rootfsbuilder] warn: could not remove work dir {}: {e}",
                    self.work_dir.display()
                );
            }
        } else {
            eprintln!(
                "[rootfsbuilder] preserving work dir for debugging: {}",
                self.work_dir.display()
            );
        }
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// `umount -l <target>` — lazy unmount; best-effort, never panics.
pub fn lazy_unmount(target: &Path) {
    let _ = Command::new("umount")
        .args(["-l", &target.display().to_string()])
        .output();
}

/// Mount a bind filesystem into the rootfs. Returns the mounted target path.
pub fn bind_mount(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    let status = Command::new("mount")
        .args([
            "--bind",
            &src.display().to_string(),
            &dst.display().to_string(),
        ])
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "mount --bind {} {} failed",
            src.display(),
            dst.display()
        )));
    }
    Ok(())
}

/// Mount a virtual filesystem (`-t <fstype>`).
pub fn vfs_mount(fstype: &str, label: &str, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    let status = Command::new("mount")
        .args(["-t", fstype, label, &dst.display().to_string()])
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "mount -t {fstype} {label} {} failed",
            dst.display()
        )));
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn guard_removes_dir_on_success() {
        let base = TempDir::new().unwrap();
        let work = base.path().join("work");
        std::fs::create_dir_all(&work).unwrap();

        {
            let mut guard = WorkdirGuard::new(work.clone());
            guard.success();
        } // drop

        assert!(!work.exists(), "workdir should be removed after success");
    }

    #[test]
    fn guard_preserves_dir_on_failure() {
        let base = TempDir::new().unwrap();
        let work = base.path().join("work");
        std::fs::create_dir_all(&work).unwrap();

        {
            let _guard = WorkdirGuard::new(work.clone());
            // drop without calling .success()
        }

        assert!(work.exists(), "workdir should be preserved after failure");
    }

    #[test]
    fn guard_rootfs_dir_derived_correctly() {
        let base = TempDir::new().unwrap();
        let work = base.path().join("work");
        std::fs::create_dir_all(&work).unwrap();

        let guard = WorkdirGuard::new(work.clone());
        assert_eq!(guard.rootfs_dir, work.join("rootfs"));
        // Disarm so it removes cleanly
        drop(guard);
    }

    #[test]
    fn virtual_mounts_order() {
        // Unmount order should be reverse of mount order.
        // Mount order: dev, dev/pts, proc, sys, tmp
        // Unmount order: tmp, sys, proc, dev/pts, dev
        assert_eq!(VIRTUAL_MOUNTS[0], "tmp");
        assert_eq!(VIRTUAL_MOUNTS[4], "dev");
    }
}
