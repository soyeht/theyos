//! Product-level uninstall entrypoint.
//!
//! `soyeht uninstall` is the only public CLI command. Platform/install-model
//! differences stay behind internal scripts so users and agents do not choose
//! between multiple uninstallers.

use crate::cli::UninstallArgs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
enum UninstallTarget {
    NixosManaged { script: PathBuf },
    SourceCheckout { script: PathBuf },
    ReleaseLinux { script: PathBuf },
}

pub fn cmd_uninstall(args: &UninstallArgs) {
    let target = detect_target().unwrap_or_else(|e| {
        eprintln!("soyeht: ERROR: {e}");
        std::process::exit(1);
    });

    if args.dry_run && matches!(target, UninstallTarget::NixosManaged { .. }) {
        if let UninstallTarget::NixosManaged { script } = target {
            println!(
                "dry-run: would run {}{}",
                script.display(),
                rendered_args(args)
            );
        }
        return;
    }

    let script = match target {
        UninstallTarget::NixosManaged { script }
        | UninstallTarget::SourceCheckout { script }
        | UninstallTarget::ReleaseLinux { script } => script,
    };

    let status = if is_executable(&script) {
        Command::new(&script).args(script_args(args)).status()
    } else {
        Command::new("sh")
            .arg(&script)
            .args(script_args(args))
            .status()
    };

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("soyeht: ERROR: failed to run {}: {e}", script.display());
            std::process::exit(1);
        }
    }
}

fn detect_target() -> Result<UninstallTarget, String> {
    let home = home_dir()?;
    let repo_root = core_rs::path::resolve_repo_root().ok();

    if let Some(root) = repo_root.as_deref() {
        if crate::nixos::is_nixos_managed(root) {
            return repo_script(root, "uninstall-nixos")
                .map(|script| UninstallTarget::NixosManaged { script });
        }

        if source_checkout_installed(root, &home) {
            return repo_script(root, "uninstall")
                .map(|script| UninstallTarget::SourceCheckout { script });
        }
    }

    if let Some(script) = release_linux_script(&home, repo_root.as_deref()) {
        return Ok(UninstallTarget::ReleaseLinux { script });
    }

    if Path::new("/etc/NIXOS").exists() {
        return Err(
            "NixOS detected, but no repo-managed theyOS install receipt was found. \
             Remove the services.theyos module from your NixOS configuration and rebuild."
                .into(),
        );
    }

    Err("no Soyeht installation was detected on this machine".into())
}

fn repo_script(root: &Path, name: &str) -> Result<PathBuf, String> {
    let script = root.join(name);
    if script.is_file() {
        Ok(script)
    } else {
        Err(format!("uninstall helper missing: {}", script.display()))
    }
}

fn release_linux_script(home: &Path, repo_root: Option<&Path>) -> Option<PathBuf> {
    let install_dir = install_dir(home);
    if !release_install_detected(&install_dir) {
        return None;
    }

    let packaged = install_dir.join("engine/uninstall-linux.sh");
    if packaged.is_file() {
        return Some(packaged);
    }

    let repo_script = repo_root?.join("scripts/uninstall-linux.sh");
    repo_script.is_file().then_some(repo_script)
}

fn release_install_detected(install_dir: &Path) -> bool {
    install_dir.join("install-receipt").is_file()
        || install_dir.join("engine/theyos-engine").is_file()
        || install_dir.join("engine/soyeht").is_file()
}

fn install_dir(home: &Path) -> PathBuf {
    std::env::var_os("SOYEHT_INSTALL_DIR")
        .map_or_else(|| home.join(".local/share/Soyeht"), PathBuf::from)
}

fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| "HOME is not set".into())
}

fn source_checkout_installed(root: &Path, home: &Path) -> bool {
    [
        home.join(".local/bin/soyeht"),
        home.join(".local/bin/theyos"),
        home.join(".local/bin/init_macos_guest"),
    ]
    .iter()
    .any(|path| symlink_points_into(path, root))
}

fn symlink_points_into(path: &Path, root: &Path) -> bool {
    let Ok(target) = std::fs::read_link(path) else {
        return false;
    };
    let absolute = if target.is_absolute() {
        target
    } else {
        path.parent().unwrap_or_else(|| Path::new("/")).join(target)
    };
    absolute.starts_with(root)
}

fn is_executable(path: &Path) -> bool {
    core_rs::os::is_executable(path)
}

fn script_args(args: &UninstallArgs) -> Vec<&'static str> {
    let mut out = Vec::new();
    if args.yes {
        out.push("--yes");
    }
    if args.dry_run {
        out.push("--dry-run");
    }
    if args.keep_data {
        out.push("--keep-data");
    }
    out
}

fn rendered_args(args: &UninstallArgs) -> String {
    let args = script_args(args);
    if args.is_empty() {
        String::new()
    } else {
        format!(" {}", args.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_args_preserve_public_flags() {
        let args = UninstallArgs {
            yes: true,
            dry_run: true,
            keep_data: true,
        };
        assert_eq!(
            script_args(&args),
            vec!["--yes", "--dry-run", "--keep-data"]
        );
    }

    #[test]
    fn relative_symlink_into_root_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        let bin = tmp.path().join("home/.local/bin");
        std::fs::create_dir_all(root.join("admin/rust/target/release")).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let target = root.join("admin/rust/target/release/soyeht");
        std::fs::write(&target, "").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, bin.join("soyeht")).unwrap();

        #[cfg(unix)]
        assert!(symlink_points_into(&bin.join("soyeht"), &root));
    }

    #[test]
    fn release_script_requires_release_install_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(repo.join("scripts")).unwrap();
        std::fs::write(repo.join("scripts/uninstall-linux.sh"), "").unwrap();

        assert!(release_linux_script(&home, Some(&repo)).is_none());

        let install_dir = home.join(".local/share/Soyeht");
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::write(install_dir.join("install-receipt"), "").unwrap();
        assert_eq!(
            release_linux_script(&home, Some(&repo)).unwrap(),
            repo.join("scripts/uninstall-linux.sh")
        );
    }
}
