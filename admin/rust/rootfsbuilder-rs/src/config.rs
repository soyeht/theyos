//! Build configuration resolved from environment variables and sudo context.
//!
//! Mirrors the variable resolution done at the top of `build-rootfs.sh`:
//!
//! ```bash
//! REAL_USER="${SUDO_USER:-$(whoami)}"
//! REAL_HOME="$(eval echo ~"${REAL_USER}")"
//! REAL_UID="${SUDO_UID:-$(id -u)}"
//! REAL_GID="${SUDO_GID:-$(id -g)}"
//! OUTPUT="${ROOTFS_OUTPUT:-${REAL_HOME}/firecracker/assets/ubuntu-24.04-rootfs-v2.ext4}"
//! SSH_PUBKEY="${FIRECRACKER_SSH_PUBKEY:-${REAL_HOME}/firecracker/assets/ubuntu-24.04-root.id_rsa.pub}"
//! ROOTFS_SIZE_BLOCKS=1048576  # 4 GiB at 4 KB/block
//! ```

use std::path::PathBuf;
use std::process::Command;

/// Resolved build configuration.
#[derive(Debug)]
pub struct Config {
    /// Force overwrite even if output already exists.
    pub force: bool,

    /// The username of the invoking (real) user — not root.
    pub real_user: String,
    /// UID to chown the finished image to.
    pub real_uid: u32,
    /// GID to chown the finished image to.
    pub real_gid: u32,

    /// Output ext4 image path.
    pub output: PathBuf,
    /// SSH public key to inject into the rootfs.
    pub ssh_pubkey: PathBuf,

    /// ext4 size in 4 KB blocks (default 1 048 576 = 4 GiB).
    pub rootfs_size_blocks: u64,
}

impl Config {
    /// Build from the process environment and CLI flags.
    #[allow(clippy::similar_names)]
    pub fn from_env(force: bool) -> Self {
        // ── Real user identity ────────────────────────────────────────────
        let real_user = std::env::var("SUDO_USER")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(whoami);

        let real_home = std::env::var("HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .map_or_else(|| home_of(&real_user), PathBuf::from);

        let real_uid = parse_env_u32("SUDO_UID")
            .unwrap_or_else(|| parse_env_u32("UID").unwrap_or_else(core_rs::os::getuid));
        let real_gid = parse_env_u32("SUDO_GID")
            .unwrap_or_else(|| parse_env_u32("GID").unwrap_or_else(core_rs::os::getgid));

        // ── Output paths ──────────────────────────────────────────────────
        let output = std::env::var("ROOTFS_OUTPUT")
            .ok()
            .filter(|s| !s.is_empty())
            .map_or_else(
                || real_home.join("firecracker/assets/ubuntu-24.04-rootfs-v2.ext4"),
                PathBuf::from,
            );

        let ssh_pubkey = std::env::var("FIRECRACKER_SSH_PUBKEY")
            .ok()
            .filter(|s| !s.is_empty())
            .map_or_else(
                || real_home.join("firecracker/assets/ubuntu-24.04-root.id_rsa.pub"),
                PathBuf::from,
            );

        // ── Image sizing ──────────────────────────────────────────────────
        // 4 GiB = 4 * 1024 * 1024 * 1024 / 4096 blocks = 1 048 576
        let rootfs_size_blocks = 1_048_576u64;

        Self {
            force,
            real_user,
            real_uid,
            real_gid,
            output,
            ssh_pubkey,
            rootfs_size_blocks,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn whoami() -> String {
    Command::new("whoami")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "root".to_string())
}

fn home_of(user: &str) -> PathBuf {
    // `getent passwd <user>` is portable across Linux distributions.
    Command::new("getent")
        .args(["passwd", user])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let line = String::from_utf8_lossy(&o.stdout);
                // Format: user:x:uid:gid:gecos:home:shell
                line.split(':').nth(5).map(|h| PathBuf::from(h.trim()))
            } else {
                None
            }
        })
        .unwrap_or_else(|| PathBuf::from(format!("/home/{user}")))
}

fn parse_env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok()?.trim().parse::<u32>().ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core_rs::env::{remove_test_env, set_test_env};

    // Tests here avoid mutating well-known env vars to prevent races with
    // parallel test threads. Unique key names are used where env mutation
    // is unavoidable.

    #[test]
    fn config_size_blocks_constant() {
        // Does not depend on env — safe to run in parallel.
        let cfg = Config::from_env(false);
        assert_eq!(cfg.rootfs_size_blocks, 1_048_576);
    }

    #[test]
    fn config_force_flag() {
        let cfg = Config::from_env(true);
        assert!(cfg.force);
        let cfg = Config::from_env(false);
        assert!(!cfg.force);
    }

    #[test]
    fn config_real_user_non_empty() {
        let cfg = Config::from_env(false);
        assert!(!cfg.real_user.is_empty());
    }

    #[test]
    fn config_output_default_ends_with_expected_name() {
        // Skip if a parallel test has set ROOTFS_OUTPUT.
        if std::env::var("ROOTFS_OUTPUT").is_ok() {
            return;
        }
        let cfg = Config::from_env(false);
        assert!(
            cfg.output
                .to_string_lossy()
                .ends_with("ubuntu-24.04-rootfs-v2.ext4"),
            "unexpected output path: {}",
            cfg.output.display()
        );
    }

    #[test]
    fn config_pubkey_default_ends_with_expected_name() {
        if std::env::var("FIRECRACKER_SSH_PUBKEY").is_ok() {
            return;
        }
        let cfg = Config::from_env(false);
        assert!(
            cfg.ssh_pubkey
                .to_string_lossy()
                .ends_with("ubuntu-24.04-root.id_rsa.pub"),
            "unexpected pubkey path: {}",
            cfg.ssh_pubkey.display()
        );
    }

    #[test]
    fn parse_env_u32_valid() {
        let key = "ROOTFSBUILDER_CFG_TEST_U32_91827";
        set_test_env(key, "42");
        assert_eq!(parse_env_u32(key), Some(42));
        remove_test_env(key);
    }

    #[test]
    fn parse_env_u32_invalid_returns_none() {
        let key = "ROOTFSBUILDER_CFG_TEST_INVALID_91827";
        set_test_env(key, "not-a-number");
        assert_eq!(parse_env_u32(key), None);
        remove_test_env(key);
    }

    #[test]
    fn parse_env_u32_missing_returns_none() {
        let key = "ROOTFSBUILDER_CFG_TEST_MISSING_91827";
        remove_test_env(key);
        assert_eq!(parse_env_u32(key), None);
    }
}
