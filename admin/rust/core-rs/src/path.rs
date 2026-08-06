//! Shared repo-root resolution — consolidated from 5 crates.

use std::path::PathBuf;

/// The theyOS repository root could not be found.
#[derive(Debug, thiserror::Error)]
#[error(
    "not inside a theyos repository\n  cd ~/theyos && soyeht\n  — or set THEYOS_DIR=/path/to/theyos"
)]
pub struct RepoRootError;

/// Resolve the theyOS repository root directory.
///
/// Strategy (in order):
///   1. `THEYOS_DIR` env var (if set and non-empty)
///   2. Walk up from the current executable, looking for `admin/` + `flake.nix`
///   3. Walk up from the current working directory (for Nix-installed binaries
///      that live in `/nix/store/` outside the repo tree)
///   4. When running via `sudo`, resolve the invoker's home from
///      `SUDO_USER`/`SUDO_UID` and check `$HOME/theyos`. This catches
///      `sudo soyeht update` invoked from any directory — sudo strips
///      `THEYOS_DIR` from the env, the Nix-store exe path doesn't walk up to
///      the repo, and the cwd may not be inside the repo either.
///
/// Returns an error if no strategy finds the repo.
///
/// # Errors
///
/// Returns [`RepoRootError`] if the repo root cannot be determined.
pub fn resolve_repo_root() -> Result<PathBuf, RepoRootError> {
    if let Ok(d) = std::env::var("THEYOS_DIR")
        && !d.is_empty()
    {
        return Ok(PathBuf::from(d));
    }
    // Walk up from executable path (works when binary is inside the repo tree)
    if let Ok(exe) = std::env::current_exe()
        && let Some(root) = walk_up_for_repo(exe.as_path())
    {
        return Ok(root);
    }
    // Walk up from current working directory (works for Nix-installed binaries)
    if let Ok(cwd) = std::env::current_dir()
        && let Some(root) = walk_up_for_repo(&cwd)
    {
        return Ok(root);
    }
    // sudo-invoker fallback: on NixOS-managed installs the repo canonically
    // lives at `${real_home}/theyos`. This catches `sudo soyeht update` run
    // from any directory where sudo strips THEYOS_DIR and cwd is outside the
    // repo. Prefer passwd-based resolution from SUDO_USER/SUDO_UID; only fall
    // back to SUDO_HOME if the passwd lookup is unavailable.
    if let Some(real_home) = crate::env::sudo_invoker_home() {
        let candidate = real_home.join("theyos");
        if is_theyos_repo(&candidate) {
            return Ok(candidate);
        }
    }
    Err(RepoRootError)
}

/// Returns `true` if `dir` looks like a theyOS repository root.
///
/// Canary: `admin/` directory + `flake.nix` file, both of which are
/// git-tracked and always present at the repo root.
fn is_theyos_repo(dir: &std::path::Path) -> bool {
    dir.join("admin").is_dir() && dir.join("flake.nix").is_file()
}

/// Walk up from `start` looking for a directory that looks like a theyOS repo.
fn walk_up_for_repo(start: &std::path::Path) -> Option<PathBuf> {
    let mut dir = start;
    for _ in 0..12 {
        if is_theyos_repo(dir) {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_repo_root_returns_something() {
        let root = resolve_repo_root().expect("should resolve inside repo");
        assert!(!root.as_os_str().is_empty());
    }
}
