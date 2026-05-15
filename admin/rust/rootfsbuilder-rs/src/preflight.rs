//! Phase 0 — Pre-flight checks.
//!
//! Validates everything before any disk/network operation:
//! 1. Running as root (uid == 0).
//! 2. Required host binaries present (`mke2fs`, `e2fsck`).
//! 3. SSH public key exists.
//! 4. Output file does not exist (or `--force` was given).
//! 5. `debootstrap` binary resolvable (PATH or nix-shell fallback).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::Config;
use crate::error::{Result, RootfsError, RootfsPhase};

const PHASE: RootfsPhase = RootfsPhase::Preflight;

/// Outcome of preflight: if successful, contains the resolved debootstrap path.
pub struct PreflightOk {
    pub debootstrap_bin: PathBuf,
}

/// Run all preflight checks. Returns `Err` on the first failure with full context.
pub fn run(cfg: &Config) -> Result<PreflightOk> {
    check_root()?;
    check_required_cmds()?;
    check_ssh_pubkey(&cfg.ssh_pubkey)?;
    check_output_not_exists(&cfg.output, cfg.force)?;
    let debootstrap_bin = resolve_debootstrap(&cfg.real_user)?;
    Ok(PreflightOk { debootstrap_bin })
}

// ── Individual checks ─────────────────────────────────────────────────────────

fn check_root() -> Result<()> {
    let uid = core_rs::os::getuid();
    if uid != 0 {
        return Err(RootfsError::new(
            PHASE,
            format!(
                "must be run as root (current uid={uid}). \
                 Use: sudo rootfsbuilder [--force]"
            ),
        ));
    }
    Ok(())
}

fn check_required_cmds() -> Result<()> {
    for cmd in &["mke2fs", "e2fsck"] {
        if !cmd_in_path(cmd) {
            return Err(RootfsError::new(
                PHASE,
                format!("required command not found in PATH: {cmd}"),
            )
            .with_detail(format!("Install e2fsprogs or ensure '{cmd}' is in $PATH")));
        }
    }
    Ok(())
}

fn check_ssh_pubkey(pubkey: &Path) -> Result<()> {
    if !pubkey.is_file() {
        return Err(
            RootfsError::missing(PHASE, "SSH public key", pubkey).with_detail(format!(
                "Generate with: ssh-keygen -t ed25519 -f {} -N ''",
                pubkey
                    .parent()
                    .unwrap_or(Path::new("."))
                    .join("ubuntu-24.04-root.id_rsa")
                    .display()
            )),
        );
    }
    Ok(())
}

fn check_output_not_exists(output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        return Err(RootfsError::new(
            PHASE,
            format!(
                "output file already exists: {}\n  \
                 Pass --force to overwrite",
                output.display()
            ),
        ));
    }
    Ok(())
}

/// Resolve `debootstrap` binary.
///
/// Search order:
/// 1. `$PATH` (system or NixOS `/run/current-system/sw/bin`).
/// 2. `su - <real_user> -c 'nix-shell -p debootstrap --run "command -v debootstrap"'`
pub fn resolve_debootstrap(real_user: &str) -> Result<PathBuf> {
    // 1. PATH
    if let Some(p) = which("debootstrap") {
        log_debootstrap(&p);
        return Ok(p);
    }

    // 2. nix-shell fallback (run as the real user to avoid root nix issues)
    eprintln!("[rootfsbuilder] debootstrap not in PATH, trying nix-shell as {real_user}...");
    let out = Command::new("su")
        .args([
            "-",
            real_user,
            "-c",
            "nix-shell -p debootstrap --run 'command -v debootstrap'",
        ])
        .output();

    match out {
        Ok(o) if o.status.success() => {
            let path_str = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !path_str.is_empty() {
                let p = PathBuf::from(&path_str);
                if p.is_file() {
                    log_debootstrap(&p);
                    return Ok(p);
                }
            }
        }
        _ => {}
    }

    Err(RootfsError::new(
        PHASE,
        "debootstrap not found in PATH and nix-shell fallback failed",
    )
    .with_detail(
        "Install debootstrap via your package manager, or ensure nix-shell is available.\n\
         On NixOS: nix-shell -p debootstrap"
            .to_string(),
    ))
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn cmd_in_path(cmd: &str) -> bool {
    which(cmd).is_some()
}

fn which(cmd: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| PathBuf::from(dir).join(cmd))
        .find(|p| p.is_file())
}

fn log_debootstrap(p: &Path) {
    println!("[rootfsbuilder] debootstrap: {}", p.display());
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn check_ssh_pubkey_missing_fails() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nokey.pub");
        let err = check_ssh_pubkey(&missing).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn check_ssh_pubkey_present_ok() {
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("key.pub");
        fs::write(&key, "ssh-ed25519 AAAA test\n").unwrap();
        assert!(check_ssh_pubkey(&key).is_ok());
    }

    #[test]
    fn check_output_exists_without_force_fails() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("rootfs.ext4");
        fs::write(&out, b"dummy").unwrap();
        let err = check_output_not_exists(&out, false).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn check_output_exists_with_force_ok() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("rootfs.ext4");
        fs::write(&out, b"dummy").unwrap();
        assert!(check_output_not_exists(&out, true).is_ok());
    }

    #[test]
    fn check_output_missing_ok() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("rootfs.ext4");
        assert!(check_output_not_exists(&out, false).is_ok());
    }

    #[test]
    fn required_cmd_not_found_fails() {
        // Test the logic by checking a guaranteed-missing command name.
        let result: Result<()> = (|| {
            let cmd = "this_binary_definitely_does_not_exist_theyos";
            if !cmd_in_path(cmd) {
                return Err(RootfsError::new(
                    PHASE,
                    format!("required command not found in PATH: {cmd}"),
                ));
            }
            Ok(())
        })();
        assert!(result.is_err());
    }

    #[test]
    fn check_root_fails_when_not_root() {
        // This test only validates the error formatting logic using a simulated uid.
        // We cannot actually become non-root inside a test, but we can check
        // that the message is informative.
        let uid = core_rs::os::getuid();
        // If running as root (e.g. in CI), skip the content assertion.
        if uid != 0 {
            let err = check_root().unwrap_err();
            assert!(err.to_string().contains("must be run as root"));
            assert!(err.to_string().contains(&uid.to_string()));
        }
    }
}
