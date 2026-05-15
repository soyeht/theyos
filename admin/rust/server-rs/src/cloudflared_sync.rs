//! Cloudflared config synchronization.
//!
//! On tailscale-only hosts (devs) the public-claw-sites feature publishes user
//! services to the internet through a Cloudflare Tunnel instead of Caddy. This
//! module owns the full lifecycle of the cloudflared `config.yml`:
//!
//!   * regenerate the file from the `public_sites` DB table after every
//!     create/delete and once at startup;
//!   * write atomically (tempfile + rename in the same dir);
//!   * trigger a cloudflared reload via a configurable shell command.
//!
//! Both behaviours are env-gated and **silently no-op when unset**, so the
//! module is harmless on dev hosts without cloudflared installed.

use crate::state::SharedState;
use core_rs::error::blocking;
use std::fmt::Write as _;
use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use store_rs::PublicSiteRow;

const ENV_CONFIG_PATH: &str = "THEYOS_CLOUDFLARED_CONFIG";
const ENV_RELOAD_CMD: &str = "THEYOS_CLOUDFLARED_RELOAD_CMD";

/// Resolve the configured cloudflared `config.yml` path.
///
/// `THEYOS_CLOUDFLARED_CONFIG` overrides the default. The default
/// `distro/cloudflared/config.yml` is the in-repo path used for the static
/// warning check in dev environments; production overrides via env (see
/// `nix/module.nix`).
#[must_use]
pub fn cloudflared_config_path() -> String {
    std::env::var(ENV_CONFIG_PATH).unwrap_or_else(|_| "distro/cloudflared/config.yml".to_string())
}

/// Regenerate cloudflared `config.yml` from the `public_sites` DB rows and
/// reload cloudflared if `THEYOS_CLOUDFLARED_RELOAD_CMD` is set.
///
/// Fire-and-forget: errors are logged but never bubble up to the caller. A
/// failed sync degrades gracefully — the operator sees `journalctl -u
/// cloudflared` or the warning banner in the UI.
pub async fn sync_cloudflared_config(state: &SharedState) {
    // Gate 1: env var must be set. Dev machines without cloudflared installed
    // skip the entire path silently.
    let path = match std::env::var(ENV_CONFIG_PATH) {
        Ok(p) if !p.is_empty() => p,
        _ => return,
    };

    let st = state.clone();
    let sites = match blocking(move || st.instance_db.list_all_enabled_public_sites()).await {
        Ok(Ok(sites)) => sites,
        Ok(Err(e)) => {
            tracing::error!("[cloudflared-sync] db error: {e}");
            return;
        }
        Err(e) => {
            tracing::error!("[cloudflared-sync] task join error: {e}");
            return;
        }
    };

    let yaml = generate_config_yaml(&sites);

    if let Err(e) = atomic_write(&path, &yaml) {
        tracing::error!("[cloudflared-sync] write {path}: {e}");
        return;
    }

    // Best-effort ARP warmup before cloudflared reloads. macOS 26 + VZ
    // bridged networking returns `EHOSTUNREACH` from kernel-level connect
    // calls when the host's ARP cache is cold for the guest IP, even though
    // the guest is reachable — same root cause as the `wait_for_ssh` `nc`
    // workaround in `vmrunner-macos-rs`. cloudflared (Go's `net.Dialer`)
    // hits the same flake on first request after a VM boot. A single
    // `ping -c 1 -W 1` from this host populates the bridge ARP entry so
    // the first proxied request finds a populated next-hop.
    //
    // No-op on Linux hosts (route 127.0.0.1 / netns peers don't suffer
    // from this) and silently skipped if `ping` is unavailable.
    warm_arp_cache(&sites);

    let count = sites.len();
    let reload_status = run_reload();
    tracing::info!("[cloudflared-sync] wrote {path} with {count} site(s), reload={reload_status}");
}

/// Best-effort host-side ARP warmup for every non-loopback `target_host`.
/// Errors are deliberately swallowed — failure here only loses us the
/// optimization, never the reload.
#[cfg(target_os = "macos")]
fn warm_arp_cache(sites: &[PublicSiteRow]) {
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    for site in sites {
        let host = site.target_host.as_str();
        // Skip loopback targets — those are netns/Caddy forwards, not VMs.
        if host == "127.0.0.1" || host == "localhost" || host == "::1" {
            continue;
        }
        if !seen.insert(host) {
            continue;
        }
        // 1 packet, 1s timeout. Fire-and-forget; we don't even consume the
        // child's stdout (small enough that the kernel pipe buffer absorbs
        // it before the process exits).
        let _ = std::process::Command::new("ping")
            .args(["-c", "1", "-W", "1000", host])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

#[cfg(not(target_os = "macos"))]
fn warm_arp_cache(_sites: &[PublicSiteRow]) {}

/// Build the cloudflared `config.yml` ingress block.
///
/// The output is deterministic (alphabetical by hostname) so diffs across
/// runs are reviewable, and always ends with a catch-all `404` rule which
/// cloudflared requires.
fn generate_config_yaml(sites: &[PublicSiteRow]) -> String {
    let mut sorted: Vec<&PublicSiteRow> = sites.iter().collect();
    sorted.sort_by(|a, b| a.domain.cmp(&b.domain));

    let mut out = String::new();
    out.push_str("# Auto-generated by theyOS — do not edit manually.\n");
    out.push_str("# Source: public_sites table; regenerated on every add/remove.\n");
    out.push_str("ingress:\n");
    for site in sorted {
        // unwrap: writing to a String never fails
        let _ = writeln!(
            out,
            "  - hostname: {}\n    service: http://{}:{}",
            site.domain, site.target_host, site.target_port
        );
    }
    out.push_str("  - service: http_status:404\n");
    out
}

/// Atomic write: tmpfile in the same directory + rename(2). Mode 644 so the
/// cloudflared service user can read it regardless of umask.
fn atomic_write(path: &str, content: &str) -> std::io::Result<()> {
    let path_buf = Path::new(path);
    let dir = path_buf.parent().unwrap_or_else(|| Path::new("."));

    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.as_file_mut().write_all(content.as_bytes())?;
    tmp.as_file_mut().sync_all()?;
    tmp.as_file_mut()
        .set_permissions(Permissions::from_mode(0o644))?;
    tmp.persist(path_buf).map_err(|e| e.error)?;
    Ok(())
}

/// Run the configured reload command, if any. Returns a status string for
/// logging.
fn run_reload() -> &'static str {
    let cmd = match std::env::var(ENV_RELOAD_CMD) {
        Ok(c) if !c.is_empty() => c,
        _ => return "skipped",
    };

    // Use absolute /bin/sh — the admin systemd service's PATH does not
    // include a shell (it lists coreutils, curl, etc. but no bash/dash).
    // /bin/sh exists on every supported OS via the systemd link or a
    // distro-managed symlink (NixOS provides /bin/sh via security.wrappers).
    match std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&cmd)
        .output()
    {
        Ok(out) if out.status.success() => "ok",
        Ok(out) => {
            tracing::warn!(
                "[cloudflared-sync] reload failed (exit {}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            "failed"
        }
        Err(e) => {
            tracing::warn!("[cloudflared-sync] reload spawn error: {e}");
            "failed"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static RELOAD_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn site(domain: &str, host: &str, port: i64) -> PublicSiteRow {
        PublicSiteRow {
            domain: domain.into(),
            instance_id: "inst-x".into(),
            guest_port: 3000,
            target_host: host.into(),
            target_port: port,
            enabled: true,
            created_at: "2026-04-25 00:00:00".into(),
            updated_at: "2026-04-25 00:00:00".into(),
            cloudflare_dns_record_id: None,
        }
    }

    #[test]
    fn empty_yaml_has_only_catchall() {
        let yaml = generate_config_yaml(&[]);
        assert!(yaml.contains("ingress:"));
        assert!(yaml.contains("- service: http_status:404"));
        assert!(!yaml.contains("hostname:"));
    }

    #[test]
    fn sites_render_in_alphabetical_order() {
        let sites = vec![
            site("zeta.example.com", "127.0.0.1", 24010),
            site("alpha.example.com", "127.0.0.1", 24001),
            site("mid.example.com", "127.0.0.1", 24005),
        ];
        let yaml = generate_config_yaml(&sites);
        let alpha = yaml.find("alpha.example.com").unwrap();
        let mid = yaml.find("mid.example.com").unwrap();
        let zeta = yaml.find("zeta.example.com").unwrap();
        assert!(
            alpha < mid && mid < zeta,
            "ingress order must be alphabetical"
        );
        // catch-all must be last
        let catchall = yaml.find("- service: http_status:404").unwrap();
        assert!(catchall > zeta, "catch-all must follow all hostnames");
    }

    #[test]
    fn site_renders_correct_target_url() {
        let yaml = generate_config_yaml(&[site("app.example.com", "127.0.0.1", 24042)]);
        assert!(
            yaml.contains("- hostname: app.example.com\n    service: http://127.0.0.1:24042\n"),
            "actual yaml:\n{yaml}"
        );
    }

    #[test]
    fn macos_target_uses_vm_ip_directly() {
        let yaml = generate_config_yaml(&[site("mac.example.com", "192.168.64.10", 8080)]);
        assert!(yaml.contains("service: http://192.168.64.10:8080"));
    }

    #[test]
    fn atomic_write_creates_file_with_644_perms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        atomic_write(
            path.to_str().unwrap(),
            "ingress:\n  - service: http_status:404\n",
        )
        .unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        // mask out file-type bits, just keep rwxrwxrwx
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "ingress:\n  - service: http_status:404\n"
        );
    }

    #[test]
    fn atomic_write_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        std::fs::write(&path, "old content").unwrap();
        atomic_write(path.to_str().unwrap(), "new content").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new content");
    }

    #[test]
    fn run_reload_skipped_when_env_unset() {
        let _guard = RELOAD_ENV_LOCK.lock().unwrap();
        // SAFETY: guarded by RELOAD_ENV_LOCK so the process-wide env mutation
        // cannot race with the sibling reload test.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(ENV_RELOAD_CMD);
        }
        assert_eq!(run_reload(), "skipped");
    }

    #[test]
    fn run_reload_ok_when_command_succeeds() {
        let _guard = RELOAD_ENV_LOCK.lock().unwrap();
        // SAFETY: guarded by RELOAD_ENV_LOCK; restored before the lock drops.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(ENV_RELOAD_CMD, "true");
        }
        let status = run_reload();
        // SAFETY: guarded by RELOAD_ENV_LOCK.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(ENV_RELOAD_CMD);
        }
        assert_eq!(status, "ok");
    }
}
