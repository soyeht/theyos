//! Host <-> VM package manager cache sync (cargo registry, npm).
//!
//! All operations are best-effort: if rsync is unavailable or the cache is
//! empty, the build continues without error. A cache miss only costs time.

use std::path::Path;
use std::process::{Command, Stdio};

use vmrunner_rs::ssh_client::SshSession;

/// Which cache type to sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheKind {
    Cargo,
    Npm,
}

impl CacheKind {
    /// Resolve the host-side cache directory using sudo-safe home resolution.
    #[must_use]
    pub fn host_dir(self, repo_root: &std::path::Path) -> std::path::PathBuf {
        let home = core_rs::env::theyos_home(repo_root);
        match self {
            Self::Cargo => std::path::PathBuf::from(&home).join(".cargo/registry"),
            Self::Npm => std::path::PathBuf::from(&home).join(".npm"),
        }
    }

    pub fn vm_dir(self) -> &'static str {
        match self {
            Self::Cargo => "/root/.cargo/registry",
            Self::Npm => "/root/.npm",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Cargo => "cargo-registry",
            Self::Npm => "npm",
        }
    }
}

/// Push a cache directory from host into the build VM (host -> VM).
///
/// Returns silently on any failure -- cache errors never abort a build.
pub async fn push_cache(
    kind: CacheKind,
    sess: &SshSession,
    ssh_key: &Path,
    ssh_port: u16,
    claw: &str,
    repo_root: &Path,
) {
    let host_dir = kind.host_dir(repo_root);
    if !host_dir.is_dir() {
        log_cache(claw, kind.label(), "host cache not found -- skipping push");
        return;
    }
    if !rsync_available() {
        log_cache(claw, kind.label(), "rsync not available -- skipping push");
        return;
    }

    let size = dir_size_human(&host_dir);
    log_cache(claw, kind.label(), &format!("pushing {size} -> VM..."));

    // Ensure remote dir exists (via russh session)
    let _ = sess.exec(&format!("mkdir -p {}", kind.vm_dir())).await;

    let ssh_cmd = build_rsync_ssh_cmd(ssh_key, ssh_port);

    let status = Command::new("rsync")
        .args(["-az", "--progress"])
        .args(["-e", &ssh_cmd])
        .arg(format!("{}/", host_dir.display()))
        .arg(format!("root@127.0.0.1:{}/", kind.vm_dir()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => log_cache(claw, kind.label(), "push done"),
        Ok(_) => log_cache(claw, kind.label(), "push had warnings (non-fatal)"),
        Err(e) => log_cache(claw, kind.label(), &format!("push error: {e} (non-fatal)")),
    }
}

/// Pull a cache directory from the build VM back to host (VM -> host).
///
/// Returns silently on any failure.
pub async fn pull_cache(
    kind: CacheKind,
    ssh_key: &Path,
    ssh_port: u16,
    claw: &str,
    repo_root: &Path,
) {
    let host_dir = kind.host_dir(repo_root);
    if !rsync_available() {
        return;
    }

    log_cache(claw, kind.label(), "pulling cache VM -> host...");
    std::fs::create_dir_all(&host_dir).ok();

    let ssh_cmd = build_rsync_ssh_cmd(ssh_key, ssh_port);

    let status = Command::new("rsync")
        .args(["-az"])
        .args(["-e", &ssh_cmd])
        .arg(format!("root@127.0.0.1:{}/", kind.vm_dir()))
        .arg(format!("{}/", host_dir.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => {
            let size = dir_size_human(&host_dir);
            log_cache(
                claw,
                kind.label(),
                &format!("pull done (host total: {size})"),
            );
        }
        Ok(_) => log_cache(claw, kind.label(), "pull had warnings (non-fatal)"),
        Err(e) => log_cache(claw, kind.label(), &format!("pull error: {e} (non-fatal)")),
    }
}

/// Build the `-e` argument for rsync that tells it how to invoke ssh.
fn build_rsync_ssh_cmd(ssh_key: &Path, ssh_port: u16) -> String {
    format!(
        "ssh -i {} -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=4 -p {}",
        ssh_key.to_string_lossy(),
        ssh_port,
    )
}

fn rsync_available() -> bool {
    Command::new("rsync")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn dir_size_human(path: &Path) -> String {
    core_rs::os::file_size_human(path)
}

fn log_cache(claw: &str, kind: &str, msg: &str) {
    eprintln!("[golden][{claw}] cache:{kind} -- {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_cache_kind_vm_dir() {
        assert_eq!(CacheKind::Cargo.vm_dir(), "/root/.cargo/registry");
    }

    #[test]
    fn npm_cache_kind_vm_dir() {
        assert_eq!(CacheKind::Npm.vm_dir(), "/root/.npm");
    }

    #[test]
    fn cache_kind_labels() {
        assert_eq!(CacheKind::Cargo.label(), "cargo-registry");
        assert_eq!(CacheKind::Npm.label(), "npm");
    }
}
