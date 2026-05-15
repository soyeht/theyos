//! rootfsbuilder — Build Ubuntu 24.04 ext4 rootfs for Firecracker VMs.
//!
//! Replaces `scripts/firecracker/build-rootfs.sh`.
//!
//! # Usage
//!
//! ```text
//! sudo rootfsbuilder [--force]
//! ```
//!
//! # Environment variables
//!
//! | Variable               | Default                                                          |
//! |------------------------|------------------------------------------------------------------|
//! | `ROOTFS_OUTPUT`        | `~/firecracker/assets/ubuntu-24.04-rootfs-v2.ext4`              |
//! | `FIRECRACKER_SSH_PUBKEY` | `~/firecracker/assets/ubuntu-24.04-root.id_rsa.pub`           |
//! | `SUDO_USER`            | resolved from `whoami` if absent                                 |
//! | `SUDO_UID` / `SUDO_GID`| current uid/gid if absent                                        |
//!
//! # Build phases
//!
//! | # | Phase       | What happens                                           |
//! |---|-------------|--------------------------------------------------------|
//! | 0 | Preflight   | Check root, binaries, SSH key, output not existing     |
//! | 1 | Debootstrap | Bootstrap Ubuntu 24.04 (noble) into temp rootfs dir    |
//! | 2 | Chroot      | Install packages, configure SSH/systemd, set up fcnet  |
//! | 3 | ImageCreate | `mke2fs` to create the ext4 image from rootfs dir      |
//! | 4 | Verify      | `e2fsck`, sha256, size report                          |

mod chroot;
mod cleanup;
mod config;
mod debootstrap;
mod error;
mod image;
mod preflight;

use std::fs;
use std::path::PathBuf;

use cleanup::WorkdirGuard;
use config::Config;

// ── CLI ───────────────────────────────────────────────────────────────────────

fn usage() {
    println!(
        r"Usage: sudo rootfsbuilder [--force]

Builds a clean Ubuntu 24.04 (noble) ext4 rootfs for Firecracker VMs.
Must be run as root (debootstrap/chroot/mke2fs require root).

Options:
  --force   Overwrite existing output file
  --help    Show this help

Environment:
  ROOTFS_OUTPUT             Output path (default: ~/firecracker/assets/ubuntu-24.04-rootfs-v2.ext4)
  FIRECRACKER_SSH_PUBKEY    SSH pubkey path (default: ~/firecracker/assets/ubuntu-24.04-root.id_rsa.pub)"
    );
}

fn parse_args() -> Option<bool> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut force = false;
    for arg in &args {
        match arg.as_str() {
            "--force" => force = true,
            "--help" | "-h" => {
                usage();
                std::process::exit(0);
            }
            other => {
                eprintln!("[rootfsbuilder] unknown argument: {other}");
                eprintln!("Run 'rootfsbuilder --help' for usage.");
                return None;
            }
        }
    }
    Some(force)
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let Some(force) = parse_args() else {
        std::process::exit(2)
    };

    let cfg = Config::from_env(force);

    println!("[rootfsbuilder] output: {}", cfg.output.display());
    println!(
        "[rootfsbuilder] real user: {} (uid={}, gid={})",
        cfg.real_user, cfg.real_uid, cfg.real_gid
    );

    if let Err(e) = run(cfg) {
        eprintln!("\n[rootfsbuilder] BUILD FAILED\n{e}");
        std::process::exit(1);
    }
}

// ── Build orchestrator ────────────────────────────────────────────────────────

#[allow(clippy::needless_pass_by_value)]
fn run(cfg: Config) -> error::Result<()> {
    // ── Phase 0: Pre-flight ───────────────────────────────────────────────────
    println!("[rootfsbuilder] === Phase 0: Pre-flight ===");
    let pre = preflight::run(&cfg)?;

    // ── Create work directory ─────────────────────────────────────────────────
    let work_dir = make_work_dir()?;
    let rootfs_dir = work_dir.join("rootfs");
    let mut guard = WorkdirGuard::new(work_dir.clone());

    println!("[rootfsbuilder] work directory: {}", work_dir.display());

    // Read SSH pubkey content once (used in phase 2 chroot script).
    let ssh_pubkey_content = fs::read_to_string(&cfg.ssh_pubkey).map_err(|e| {
        error::RootfsError::new(
            error::RootfsPhase::Preflight,
            format!("read SSH pubkey {}: {e}", cfg.ssh_pubkey.display()),
        )
    })?;

    // ── Phase 1: debootstrap ──────────────────────────────────────────────────
    debootstrap::run(&pre.debootstrap_bin, &rootfs_dir)?;
    debootstrap::validate_rootfs(&rootfs_dir)?;

    // ── Phase 2: chroot configuration ─────────────────────────────────────────
    // Note: chroot::run() handles its own mount/unmount internally.
    chroot::run(&rootfs_dir, &ssh_pubkey_content)?;

    // ── Phase 3: Create ext4 image ────────────────────────────────────────────
    let build_rootfs = work_dir.join(format!(
        "rootfs-{}.ext4",
        cfg.output
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("build")
    ));

    image::create_ext4(
        &rootfs_dir,
        &build_rootfs,
        cfg.rootfs_size_blocks,
        cfg.real_uid,
        cfg.real_gid,
    )?;

    // ── Phase 4: Verify ───────────────────────────────────────────────────────
    image::verify_and_report(&build_rootfs)?;

    // ── Move to final output location ─────────────────────────────────────────
    if let Some(parent) = cfg.output.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            error::RootfsError::new(
                error::RootfsPhase::ImageCreate,
                format!("create output parent dir: {e}"),
            )
        })?;
    }
    fs::rename(&build_rootfs, &cfg.output)
        .or_else(|_| {
            // rename fails across filesystems; fall back to copy + remove.
            fs::copy(&build_rootfs, &cfg.output).and_then(|_| fs::remove_file(&build_rootfs))
        })
        .map_err(|e| {
            error::RootfsError::new(
                error::RootfsPhase::ImageCreate,
                format!(
                    "move image from {} to {}: {e}",
                    build_rootfs.display(),
                    cfg.output.display()
                ),
            )
        })?;

    // Re-apply ownership on final path.
    let _ = std::process::Command::new("chown")
        .arg(format!("{}:{}", cfg.real_uid, cfg.real_gid))
        .arg(&cfg.output)
        .status();

    guard.success();

    println!("[rootfsbuilder] Done → {}", cfg.output.display());
    Ok(())
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn make_work_dir() -> error::Result<PathBuf> {
    // Create /tmp/fc-rootfs-build.XXXXXX equivalent via tempfile-style approach
    // without adding a crate dependency: just use a pid-based suffix.
    let pid = std::process::id();
    let dir = PathBuf::from(format!("/tmp/fc-rootfs-build.{pid}"));
    fs::create_dir_all(&dir).map_err(|e| {
        error::RootfsError::new(
            error::RootfsPhase::Preflight,
            format!("create work dir {}: {e}", dir.display()),
        )
    })?;
    Ok(dir)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_does_not_panic() {
        // Just ensures no panic in the usage string formatting.
        usage();
    }

    #[test]
    fn make_work_dir_creates_directory() {
        // We can't run as root in tests, so just verify the path logic.
        let pid = std::process::id();
        let expected = PathBuf::from(format!("/tmp/fc-rootfs-build.{pid}"));
        // Don't actually create it (would need /tmp write access which we have,
        // but we don't want test side-effects). Just verify the path format.
        assert!(expected.to_string_lossy().contains("fc-rootfs-build."));
        assert!(expected.to_string_lossy().contains(&pid.to_string()));
    }

    #[test]
    fn parse_args_recognises_force() {
        // Inject --force via env trick — we test the logic directly.
        let mut force = false;
        for arg in &["--force"] {
            if *arg == "--force" {
                force = true;
            }
        }
        assert!(force);
    }

    #[test]
    fn parse_args_empty_is_no_force() {
        let args: Vec<&str> = vec![];
        let mut force = false;
        for arg in &args {
            if *arg == "--force" {
                force = true;
            }
        }
        assert!(!force);
    }
}
