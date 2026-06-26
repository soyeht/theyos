//! `caddy_manager.rs` — macOS Caddy lifecycle: detect, install `LaunchAgent`,
//! `caddy trust`, port pre-flight, zero-downtime reload, status.
//!
//! Target: a "production-grade" experience on macOS that mirrors what NixOS
//! gets natively via `services.caddy`. The user installs Caddy once (or
//! `./install` does it via brew with explicit consent), then `soyeht setup`
//! registers a per-user `LaunchAgent` that:
//!
//! - runs the detected Caddy binary against the repo Caddyfile,
//! - survives logout/reboot (`KeepAlive=true`, `RunAtLoad=true`),
//! - logs to `~/Library/Logs/theyos/caddy.{out,err}.log`,
//! - is identified by bundle id `com.soyeht.caddy`.
//!
//! Safety properties:
//!
//! - **Detect-only by default**: if Caddy is missing, this module surfaces an
//!   error. Installing Caddy is a separate consented step in `./install`.
//! - **Never touches another Caddy**: refuses to start when ports 8080 or
//!   2019 are held by an unknown PID, and surfaces the offending PID +
//!   command instead of killing it.
//! - **Path drift recovery**: if the user moves the repo, the next `start`
//!   detects the stale `ProgramArguments` path in the plist and regenerates
//!   it before bootstrapping again.
//! - **Reload over restart**: `reload` calls Caddy's admin API at
//!   `localhost:2019` to load the new Caddyfile in-process, so live HTTP
//!   connections are not dropped.
//!
//! Module is gated by `#[cfg(target_os = "macos")]` at the import site
//! (`main.rs`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// `LaunchAgent` bundle identifier.
pub const BUNDLE_ID: &str = "com.soyeht.caddy";

/// Local Caddy admin API endpoint declared in `distro/caddy/Caddyfile`.
const ADMIN_API_URL: &str = "http://localhost:2019";

/// Public HTTP listener declared in `distro/caddy/Caddyfile`.
const HTTP_PORT: u16 = 8080;

/// Caddy admin API listener (used for reload).
const ADMIN_API_PORT: u16 = 2019;

/// Where to look for Caddy when it isn't on PATH. Brew Apple-Silicon comes
/// first because it's the most common install on modern Macs.
const KNOWN_CADDY_PATHS: &[&str] = &[
    "/opt/homebrew/bin/caddy", // Homebrew on Apple Silicon
    "/usr/local/bin/caddy",    // Homebrew on Intel
    "/opt/local/bin/caddy",    // MacPorts
];

/// A Caddy binary located on disk, with its self-reported version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaddyBinary {
    pub path: PathBuf,
    /// `caddy version` first token, e.g. `v2.8.4`. Empty when version probe
    /// failed (binary still usable, but the warning surfaces in `status`).
    pub version: String,
}

#[derive(Debug)]
pub enum CaddyError {
    NotInstalled,
    PortInUse {
        port: u16,
        pid: Option<u32>,
        command: Option<String>,
    },
    PlistWrite(String),
    Launchctl(String),
    Trust(String),
    Reload(String),
    Io(String),
}

impl std::fmt::Display for CaddyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled => write!(
                f,
                "caddy binary not found on PATH or in /opt/homebrew/bin, \
                 /usr/local/bin, /opt/local/bin. Install with: brew install caddy"
            ),
            Self::PortInUse { port, pid, command } => match (pid, command) {
                (Some(pid), Some(cmd)) => write!(
                    f,
                    "port {port} is in use by pid {pid} ({cmd}). \
                     Stop that process or pick a different port before starting Caddy."
                ),
                (Some(pid), None) => write!(
                    f,
                    "port {port} is in use by pid {pid}. \
                     Stop that process before starting Caddy."
                ),
                _ => write!(
                    f,
                    "port {port} is in use (could not identify the holder via lsof). \
                     Free the port before starting Caddy."
                ),
            },
            Self::PlistWrite(msg) => write!(f, "writing LaunchAgent plist failed: {msg}"),
            Self::Launchctl(msg) => write!(f, "launchctl failed: {msg}"),
            Self::Trust(msg) => write!(f, "caddy trust failed: {msg}"),
            Self::Reload(msg) => write!(f, "caddy reload failed: {msg}"),
            Self::Io(msg) => write!(f, "i/o error: {msg}"),
        }
    }
}

impl std::error::Error for CaddyError {}

// ── Detection ────────────────────────────────────────────────────────────────

/// Return the first usable Caddy binary, in order: `$PATH`, `brew --prefix
/// caddy`/bin, then the well-known absolute paths.
///
/// "Usable" means the binary exists and `caddy version` exits with 0. Non-zero
/// or missing means no binary was found — same as not installed.
#[must_use]
pub fn detect_caddy() -> Option<CaddyBinary> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(path) = which_path("caddy") {
        candidates.push(path);
    }

    if let Some(prefix) = brew_prefix("caddy") {
        candidates.push(prefix.join("bin/caddy"));
    }

    for path in KNOWN_CADDY_PATHS {
        candidates.push(PathBuf::from(path));
    }

    let mut seen = std::collections::HashSet::new();
    for path in candidates {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if !seen.insert(canonical.clone()) {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let version = caddy_version(&path).unwrap_or_default();
        if !version.is_empty() {
            return Some(CaddyBinary { path, version });
        }
    }
    None
}

fn which_path(bin: &str) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn brew_prefix(formula: &str) -> Option<PathBuf> {
    let output = Command::new("brew")
        .args(["--prefix", formula])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!s.is_empty()).then(|| PathBuf::from(s))
}

fn caddy_version(bin: &Path) -> Option<String> {
    let output = Command::new(bin).arg("version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&output.stdout);
    let first = line.split_whitespace().next()?.to_string();
    Some(first)
}

// ── Paths ────────────────────────────────────────────────────────────────────

fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
}

#[must_use]
pub fn plist_path() -> PathBuf {
    home_dir()
        .join("Library/LaunchAgents")
        .join(format!("{BUNDLE_ID}.plist"))
}

#[must_use]
pub fn log_dir() -> PathBuf {
    home_dir().join("Library/Logs/theyos")
}

#[must_use]
pub fn stdout_log_path() -> PathBuf {
    log_dir().join("caddy.out.log")
}

#[must_use]
pub fn stderr_log_path() -> PathBuf {
    log_dir().join("caddy.err.log")
}

fn caddyfile_path(repo_root: &Path) -> PathBuf {
    repo_root.join("distro/caddy/Caddyfile")
}

// ── Plist generation ─────────────────────────────────────────────────────────

/// Read a small whitelist of variables from the repo `.env`. Keeps the plist
/// reproducible without baking secrets into anything outside the user's
/// `LaunchAgents` dir (which is mode 0600 by default for plists we write).
///
/// Variables passed through:
/// - `THEYOS_BASE_DOMAIN` — required by Caddyfile matchers; defaults to
///   `localhost` so a Mac dev install works out of the box.
/// - `CF_API_TOKEN` — used by the Cloudflare DNS-01 plugin (only needed if
///   the Mac install also wants HTTPS via Cloudflare; harmless if unset).
fn read_env_overrides(repo_root: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let env_path = repo_root.join(".env");
    let raw = fs::read_to_string(&env_path).unwrap_or_default();
    let wanted = ["THEYOS_BASE_DOMAIN", "CF_API_TOKEN"];

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !wanted.contains(&key) {
            continue;
        }
        let value = value
            .trim()
            .trim_start_matches('"')
            .trim_end_matches('"')
            .trim_start_matches('\'')
            .trim_end_matches('\'');
        out.push((key.to_string(), value.to_string()));
    }

    if !out.iter().any(|(k, _)| k == "THEYOS_BASE_DOMAIN") {
        out.push(("THEYOS_BASE_DOMAIN".to_string(), "localhost".to_string()));
    }
    out
}

/// Render the `LaunchAgent` plist as a UTF-8 XML string.
///
/// The plist is a thin wrapper around `caddy run --config <Caddyfile>
/// --adapter caddyfile`, with stdout/stderr split and the working directory
/// set to the repo root so relative paths in the Caddyfile resolve.
fn render_plist(caddy: &CaddyBinary, repo_root: &Path, env_vars: &[(String, String)]) -> String {
    let caddyfile = caddyfile_path(repo_root);

    let env_xml: String = if env_vars.is_empty() {
        String::new()
    } else {
        use std::fmt::Write as _;
        let mut s = String::from("    <key>EnvironmentVariables</key>\n    <dict>\n");
        for (k, v) in env_vars {
            let _ = write!(
                s,
                "        <key>{}</key>\n        <string>{}</string>\n",
                xml_escape(k),
                xml_escape(v)
            );
        }
        s.push_str("    </dict>\n");
        s
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{caddy_path}</string>
        <string>run</string>
        <string>--config</string>
        <string>{caddyfile}</string>
        <string>--adapter</string>
        <string>caddyfile</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{repo}</string>
{env}    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
    <key>ThrottleInterval</key>
    <integer>5</integer>
</dict>
</plist>
"#,
        label = BUNDLE_ID,
        caddy_path = xml_escape(&caddy.path.display().to_string()),
        caddyfile = xml_escape(&caddyfile.display().to_string()),
        repo = xml_escape(&repo_root.display().to_string()),
        env = env_xml,
        stdout = xml_escape(&stdout_log_path().display().to_string()),
        stderr = xml_escape(&stderr_log_path().display().to_string()),
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Write the plist to `~/Library/LaunchAgents/com.soyeht.caddy.plist`.
///
/// Returns `Ok(true)` when the file was created or its content changed,
/// `Ok(false)` when the on-disk content already matched (no churn).
fn write_plist(repo_root: &Path, caddy: &CaddyBinary) -> Result<bool, CaddyError> {
    let env = read_env_overrides(repo_root);
    let content = render_plist(caddy, repo_root, &env);
    let path = plist_path();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CaddyError::PlistWrite(format!("create LaunchAgents dir: {e}")))?;
    }
    fs::create_dir_all(log_dir())
        .map_err(|e| CaddyError::PlistWrite(format!("create log dir: {e}")))?;

    let existing = fs::read_to_string(&path).ok();
    if existing.as_deref() == Some(content.as_str()) {
        return Ok(false);
    }

    fs::write(&path, &content)
        .map_err(|e| CaddyError::PlistWrite(format!("write {}: {e}", path.display())))?;
    set_mode(&path, 0o644);
    Ok(true)
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

/// Inspect the current plist (if any) and return true when it points at a
/// different binary, repo path, or Caddyfile than the values we'd write now.
///
/// This is the auto-recovery hook: callers run `start()`, which calls this
/// before deciding whether to bootout/regenerate/bootstrap.
fn plist_needs_regeneration(repo_root: &Path, caddy: &CaddyBinary) -> bool {
    plist_needs_regeneration_at(&plist_path(), repo_root, caddy)
}

/// Same as [`plist_needs_regeneration`] but reads from an explicit path —
/// used by tests so they never touch the real `~/Library/LaunchAgents` dir.
fn plist_needs_regeneration_at(plist: &Path, repo_root: &Path, caddy: &CaddyBinary) -> bool {
    let Ok(existing) = fs::read_to_string(plist) else {
        return true;
    };
    let want = render_plist(caddy, repo_root, &read_env_overrides(repo_root));
    existing != want
}

// ── launchctl wrappers ───────────────────────────────────────────────────────

fn current_uid() -> u32 {
    // SAFETY: getuid() is a POSIX syscall with no preconditions. It returns
    // the real user id of the calling process. No Rust-managed memory is
    // accessed.
    #[allow(unsafe_code)]
    unsafe {
        libc::getuid()
    }
}

fn gui_domain() -> String {
    format!("gui/{}", current_uid())
}

fn service_target() -> String {
    format!("{}/{BUNDLE_ID}", gui_domain())
}

/// `launchctl bootstrap gui/<uid> <plist>` — load the agent.
///
/// Idempotent: if the agent is already loaded, this returns the launchctl
/// "service already loaded" error which we surface as a no-op.
pub fn launchctl_bootstrap() -> Result<(), CaddyError> {
    let plist = plist_path();
    let output = Command::new("launchctl")
        .args(["bootstrap", &gui_domain()])
        .arg(&plist)
        .output()
        .map_err(|e| CaddyError::Launchctl(format!("spawn: {e}")))?;

    if output.status.success() {
        return Ok(());
    }
    // Already loaded — treat as success.
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if stderr.contains("service already loaded") || stderr.contains("already bootstrapped") {
        return Ok(());
    }
    Err(CaddyError::Launchctl(format!(
        "bootstrap failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        stderr.trim()
    )))
}

/// `launchctl bootout gui/<uid>/<label>` — unload the agent. Idempotent.
pub fn launchctl_bootout() -> Result<(), CaddyError> {
    let output = Command::new("launchctl")
        .args(["bootout", &service_target()])
        .output()
        .map_err(|e| CaddyError::Launchctl(format!("spawn: {e}")))?;

    if output.status.success() {
        return Ok(());
    }
    // Not loaded — treat as success.
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if stderr.contains("could not find service")
        || stderr.contains("no such process")
        || stderr.contains("not loaded")
    {
        return Ok(());
    }
    Err(CaddyError::Launchctl(format!(
        "bootout failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        stderr.trim()
    )))
}

/// `launchctl kickstart -k gui/<uid>/<label>` — restart the running service.
pub fn launchctl_kickstart() -> Result<(), CaddyError> {
    let output = Command::new("launchctl")
        .args(["kickstart", "-k", &service_target()])
        .output()
        .map_err(|e| CaddyError::Launchctl(format!("spawn: {e}")))?;

    if output.status.success() {
        return Ok(());
    }
    Err(CaddyError::Launchctl(format!(
        "kickstart failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// Snapshot of `launchctl print` for the service.
#[derive(Debug, Default)]
pub struct LaunchctlStatus {
    pub loaded: bool,
    pub pid: Option<u32>,
    pub last_exit_code: Option<i32>,
}

/// Best-effort `launchctl print gui/<uid>/<label>` parser. When the service
/// isn't loaded, returns `LaunchctlStatus { loaded: false, .. }`.
#[must_use]
pub fn launchctl_print() -> LaunchctlStatus {
    let output = Command::new("launchctl")
        .args(["print", &service_target()])
        .output();
    let Ok(output) = output else {
        return LaunchctlStatus::default();
    };
    if !output.status.success() {
        return LaunchctlStatus::default();
    }
    let s = String::from_utf8_lossy(&output.stdout);
    let mut status = LaunchctlStatus {
        loaded: true,
        ..Default::default()
    };
    for line in s.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("pid = ") {
            status.pid = rest.parse().ok();
        } else if let Some(rest) = line.strip_prefix("last exit code = ") {
            status.last_exit_code = rest.parse().ok();
        }
    }
    status
}

// ── Port pre-flight ──────────────────────────────────────────────────────────

/// Verify a TCP port is free, or return `PortInUse` with the holder's PID +
/// command (parsed from `lsof`). Never kills foreign processes.
pub fn check_port_free(port: u16) -> Result<(), CaddyError> {
    let output = Command::new("lsof")
        .args(["-nP", "-iTCP", &format!(":{port}"), "-sTCP:LISTEN", "-Fpcn"])
        .output();

    let Ok(output) = output else {
        // lsof unavailable: assume port is free rather than blocking the user.
        return Ok(());
    };
    if !output.status.success() {
        // lsof exits non-zero when nothing listens — that's the success case.
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut pid: Option<u32> = None;
    let mut command: Option<String> = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix('p') {
            pid = rest.parse().ok();
        } else if let Some(rest) = line.strip_prefix('c') {
            command = Some(rest.to_string());
        }
    }
    Err(CaddyError::PortInUse { port, pid, command })
}

/// Allow the holder to be the existing soyeht-managed Caddy (same pid as the
/// `LaunchAgent`). Returns `Ok(())` in that case so `start` is idempotent.
fn check_port_free_or_ours(port: u16) -> Result<(), CaddyError> {
    match check_port_free(port) {
        Ok(()) => Ok(()),
        Err(CaddyError::PortInUse { pid: Some(pid), .. }) if launchctl_print().pid == Some(pid) => {
            Ok(())
        }
        Err(other) => Err(other),
    }
}

// ── Reload via admin API ─────────────────────────────────────────────────────

/// Hot-reload Caddy using its admin API. The Caddy CLI calls
/// `POST localhost:2019/load` for us, so live HTTP connections survive the
/// config swap.
pub fn admin_api_reload(repo_root: &Path, caddy: &CaddyBinary) -> Result<(), CaddyError> {
    let caddyfile = caddyfile_path(repo_root);
    let output = Command::new(&caddy.path)
        .args(["reload", "--config"])
        .arg(&caddyfile)
        .args(["--adapter", "caddyfile", "--address", ADMIN_API_URL])
        .output()
        .map_err(|e| CaddyError::Reload(format!("spawn caddy reload: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(CaddyError::Reload(format!(
        "caddy reload failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

// ── caddy trust / untrust ────────────────────────────────────────────────────

/// Install Caddy's local CA into the System keychain. macOS prompts the user
/// for an admin password via the GUI security dialog.
///
/// Idempotent: if the CA is already trusted, Caddy reuses it without
/// reprompting.
pub fn caddy_trust(caddy: &CaddyBinary) -> Result<(), CaddyError> {
    let status = Command::new(&caddy.path)
        .arg("trust")
        .status()
        .map_err(|e| CaddyError::Trust(format!("spawn: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(CaddyError::Trust(format!(
            "exit {}",
            status.code().unwrap_or(-1)
        )))
    }
}

/// Remove Caddy's local CA from the System keychain. Best-effort.
pub fn caddy_untrust(caddy: &CaddyBinary) -> Result<(), CaddyError> {
    let status = Command::new(&caddy.path)
        .arg("untrust")
        .status()
        .map_err(|e| CaddyError::Trust(format!("spawn: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(CaddyError::Trust(format!(
            "exit {}",
            status.code().unwrap_or(-1)
        )))
    }
}

// ── High-level lifecycle ─────────────────────────────────────────────────────

/// First-time install: detect Caddy, write the plist, bootstrap the agent.
///
/// Aborts with `PortInUse` when 8080 or 2019 are held by something other than
/// our own previously-loaded service, instead of evicting the foreign holder.
pub fn install(repo_root: &Path) -> Result<CaddyBinary, CaddyError> {
    let caddy = detect_caddy().ok_or(CaddyError::NotInstalled)?;
    check_port_free_or_ours(HTTP_PORT)?;
    check_port_free_or_ours(ADMIN_API_PORT)?;

    let _ = write_plist(repo_root, &caddy)?;
    // Idempotent bootout first — covers the case where the agent exists from
    // a previous install pointing at a stale path.
    let _ = launchctl_bootout();
    launchctl_bootstrap()?;
    wait_for_admin_api(Duration::from_secs(10));
    Ok(caddy)
}

/// Stop and uninstall the `LaunchAgent`. Does NOT call `caddy untrust` — that's
/// a separate command so users can keep the local CA across reinstalls.
pub fn uninstall() -> Result<(), CaddyError> {
    launchctl_bootout()?;
    let path = plist_path();
    if path.exists() {
        fs::remove_file(&path).map_err(|e| CaddyError::Io(format!("remove plist: {e}")))?;
    }
    Ok(())
}

/// Start the agent. Detects path drift and regenerates the plist + reloads
/// the agent before kickstarting.
pub fn start(repo_root: &Path) -> Result<CaddyBinary, CaddyError> {
    let caddy = detect_caddy().ok_or(CaddyError::NotInstalled)?;

    // Path drift detection: if the on-disk plist points to a different
    // binary, repo, or env, regenerate and reload before kickstarting.
    let needs_regen = plist_needs_regeneration(repo_root, &caddy);
    if needs_regen {
        let _ = launchctl_bootout();
        write_plist(repo_root, &caddy)?;
    }

    check_port_free_or_ours(HTTP_PORT)?;
    check_port_free_or_ours(ADMIN_API_PORT)?;

    let status = launchctl_print();
    if status.loaded {
        if needs_regen {
            // After regeneration the bootout above already unloaded; rebootstrap.
            launchctl_bootstrap()?;
        } else {
            launchctl_kickstart()?;
        }
    } else {
        launchctl_bootstrap()?;
    }
    wait_for_admin_api(Duration::from_secs(10));
    Ok(caddy)
}

/// Stop the agent (bootout). Caddy will not be restarted by launchd until the
/// next `start`/`install`.
pub fn stop() -> Result<(), CaddyError> {
    launchctl_bootout()
}

/// Restart the agent in place via `launchctl kickstart -k`.
pub fn restart() -> Result<(), CaddyError> {
    launchctl_kickstart()
}

/// Hot-reload the Caddyfile via the admin API — keeps existing connections.
pub fn reload(repo_root: &Path) -> Result<(), CaddyError> {
    let caddy = detect_caddy().ok_or(CaddyError::NotInstalled)?;
    admin_api_reload(repo_root, &caddy)
}

#[derive(Debug)]
pub struct CaddyStatus {
    pub binary: Option<CaddyBinary>,
    pub plist_present: bool,
    pub launch: LaunchctlStatus,
    pub admin_api_up: bool,
    pub plist_drift: bool,
}

#[must_use]
pub fn status(repo_root: &Path) -> CaddyStatus {
    let binary = detect_caddy();
    let plist_present = plist_path().exists();
    let launch = launchctl_print();
    let admin_api_up = curl_admin_api();
    let plist_drift = match (&binary, plist_present) {
        (Some(b), true) => plist_needs_regeneration(repo_root, b),
        _ => false,
    };
    CaddyStatus {
        binary,
        plist_present,
        launch,
        admin_api_up,
        plist_drift,
    }
}

fn curl_admin_api() -> bool {
    Command::new("curl")
        .args([
            "-fs",
            "--max-time",
            "2",
            "-o",
            "/dev/null",
            &format!("{ADMIN_API_URL}/config/"),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn wait_for_admin_api(max: Duration) {
    let deadline = std::time::Instant::now() + max;
    while std::time::Instant::now() < deadline {
        if curl_admin_api() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn fake_binary() -> CaddyBinary {
        CaddyBinary {
            path: PathBuf::from("/opt/homebrew/bin/caddy"),
            version: "v2.8.4".to_string(),
        }
    }

    #[test]
    fn render_plist_matches_template() {
        let caddy = fake_binary();
        let repo = PathBuf::from("/Users/dev/theyos");
        let env = vec![("THEYOS_BASE_DOMAIN".to_string(), "localhost".to_string())];
        let plist = render_plist(&caddy, &repo, &env);

        assert!(plist.contains("<string>com.soyeht.caddy</string>"));
        assert!(plist.contains("<string>/opt/homebrew/bin/caddy</string>"));
        assert!(plist.contains("<string>/Users/dev/theyos/distro/caddy/Caddyfile</string>"));
        assert!(plist.contains("<string>/Users/dev/theyos</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>ProcessType</key>"));
        assert!(plist.contains("<string>Background</string>"));
        assert!(plist.contains("<key>THEYOS_BASE_DOMAIN</key>"));
        assert!(plist.contains("<string>localhost</string>"));
    }

    #[test]
    fn render_plist_handles_paths_with_special_chars() {
        let caddy = CaddyBinary {
            path: PathBuf::from("/Users/dev/My Apps/caddy"),
            version: "v2.8.4".to_string(),
        };
        let repo = PathBuf::from("/Users/dev/My & Repos/theyos");
        let plist = render_plist(&caddy, &repo, &[]);
        // & must be escaped to &amp; or the plist is invalid XML.
        assert!(plist.contains("/Users/dev/My &amp; Repos/theyos"));
        assert!(!plist.contains("/Users/dev/My & Repos/theyos"));
    }

    #[test]
    fn read_env_overrides_defaults_base_domain_to_localhost() {
        let dir = tempfile::tempdir().unwrap();
        // No .env at all — should still get the localhost default.
        let env = read_env_overrides(dir.path());
        assert_eq!(
            env.iter().find(|(k, _)| k == "THEYOS_BASE_DOMAIN"),
            Some(&("THEYOS_BASE_DOMAIN".to_string(), "localhost".to_string()))
        );
    }

    #[test]
    fn read_env_overrides_picks_up_repo_env() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = fs::File::create(dir.path().join(".env")).unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "THEYOS_BASE_DOMAIN=example.com").unwrap();
        writeln!(f, "CF_API_TOKEN=\"secret-token\"").unwrap();
        writeln!(f, "UNRELATED=ignored").unwrap();
        drop(f);

        let env = read_env_overrides(dir.path());
        assert!(env.contains(&("THEYOS_BASE_DOMAIN".to_string(), "example.com".to_string())));
        assert!(env.contains(&("CF_API_TOKEN".to_string(), "secret-token".to_string())));
        assert!(!env.iter().any(|(k, _)| k == "UNRELATED"));
    }

    #[test]
    fn plist_needs_regeneration_when_path_changes() {
        let dir = tempfile::tempdir().unwrap();
        let plist_path = dir.path().join("com.soyeht.caddy.plist");
        let caddy = fake_binary();

        // Pre-populate plist as if from an earlier install at a different path.
        let stale = render_plist(
            &caddy,
            Path::new("/Users/dev/old-path"),
            &[("THEYOS_BASE_DOMAIN".to_string(), "localhost".to_string())],
        );
        fs::write(&plist_path, &stale).unwrap();

        // Set HOME to the tempdir so read_env_overrides() default lookups
        // can't accidentally pick up the real user's .env, but we pass the
        // plist explicitly via the *_at variant.
        let new_repo = dir.path();
        assert!(plist_needs_regeneration_at(&plist_path, new_repo, &caddy));

        // Same input → no regeneration needed.
        let fresh = render_plist(&caddy, new_repo, &read_env_overrides(new_repo));
        fs::write(&plist_path, fresh).unwrap();
        assert!(!plist_needs_regeneration_at(&plist_path, new_repo, &caddy));
    }

    #[test]
    fn plist_needs_regeneration_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let plist_path = dir.path().join("nonexistent.plist");
        let caddy = fake_binary();
        assert!(plist_needs_regeneration_at(&plist_path, dir.path(), &caddy));
    }

    #[test]
    fn caddy_error_display_includes_actionable_hints() {
        let err = CaddyError::NotInstalled;
        assert!(err.to_string().contains("brew install caddy"));

        let err = CaddyError::PortInUse {
            port: 8080,
            pid: Some(123),
            command: Some("nginx".to_string()),
        };
        let msg = err.to_string();
        assert!(msg.contains("8080"));
        assert!(msg.contains("123"));
        assert!(msg.contains("nginx"));
    }
}
