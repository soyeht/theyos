//! `cloudflared_manager.rs` — macOS Cloudflare Tunnel lifecycle: detect,
//! install `LaunchAgent`, bootstrap/bootout, status.
//!
//! Mirrors `caddy_manager.rs` and gives Mac installs the equivalent of what
//! NixOS gets natively via `services.cloudflared` declared in
//! `nix/module.nix`. The admin backend (`server-rs/src/cloudflare_admin.rs`)
//! drives this module via env-var commands set in the Homebrew formula's
//! launchd service block:
//!
//! ```text
//! THEYOS_CLOUDFLARED_START_CMD   = "soyeht cloudflared start"
//! THEYOS_CLOUDFLARED_STOP_CMD    = "soyeht cloudflared stop"
//! THEYOS_CLOUDFLARED_RELOAD_CMD  = "soyeht cloudflared reload"
//! THEYOS_CLOUDFLARED_RESTART_CMD = "soyeht cloudflared restart"
//! ```
//!
//! Properties:
//!
//! - **Plist exists ⇔ feature is enabled** (imperative pattern, not
//!   `KeepAlive.PathState`). Setup writes plist + bootstraps; Disconnect
//!   bootouts + removes plist. Stray plist on disk = visible state.
//! - **Restart parity with NixOS systemd unit**: `KeepAlive=true` so launchd
//!   restarts cloudflared if it crashes; `RunAtLoad=true` so the next user
//!   session brings it up automatically.
//! - **`--metrics 127.0.0.1:2000` is mandatory** — the admin backend's
//!   `cloudflared_is_running()` probe relies on it. Don't drop it.
//! - **Synchronous stop**: bootout + poll until the metrics port is gone, then
//!   remove the plist. Caller (`handle_disconnect`) needs cloudflared fully
//!   dead before deleting the tunnel via the API.
//!
//! Module is gated by `#[cfg(target_os = "macos")]` at the import site
//! (`main.rs`).

use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// `LaunchAgent` bundle identifier.
pub const BUNDLE_ID: &str = "com.theyos.cloudflared";

/// Cloudflared metrics endpoint declared in the plist `ProgramArguments`.
/// The admin backend's `cloudflared_is_running()` probe also dials this port.
const METRICS_HOST: &str = "127.0.0.1";
const METRICS_PORT: u16 = 2000;

/// Where to look for cloudflared when it isn't on `$PATH`. Brew Apple-Silicon
/// first because Homebrew is the only supported install path on Mac
/// (`homebrew/Formula/theyos.rb` errors on Intel).
const KNOWN_CLOUDFLARED_PATHS: &[&str] = &[
    "/opt/homebrew/bin/cloudflared", // Homebrew on Apple Silicon
    "/usr/local/bin/cloudflared",    // Homebrew on Intel (legacy fallback)
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflaredBinary {
    pub path: PathBuf,
    /// `cloudflared --version` first useful token (e.g. `2026.3.0`). Empty when
    /// the version probe failed; the binary is still usable but the warning
    /// surfaces in `status`.
    pub version: String,
}

#[derive(Debug)]
pub enum CloudflaredError {
    NotInstalled,
    PlistWrite(String),
    ConfigWrite(String),
    Launchctl(String),
    Io(String),
}

impl std::fmt::Display for CloudflaredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled => write!(
                f,
                "cloudflared binary not found on PATH or in /opt/homebrew/bin, \
                 /usr/local/bin. Install with: brew install cloudflared"
            ),
            Self::PlistWrite(msg) => write!(f, "writing LaunchAgent plist failed: {msg}"),
            Self::ConfigWrite(msg) => write!(f, "writing cloudflared config failed: {msg}"),
            Self::Launchctl(msg) => write!(f, "launchctl failed: {msg}"),
            Self::Io(msg) => write!(f, "i/o error: {msg}"),
        }
    }
}

impl std::error::Error for CloudflaredError {}

// ── Detection ────────────────────────────────────────────────────────────────

/// Resolve the cloudflared binary path with a cascade fallback:
/// 1. `THEYOS_CLOUDFLARED_BIN` env var (escape hatch for non-standard installs)
/// 2. `cloudflared` on `$PATH`
/// 3. `brew --prefix cloudflared`/bin/cloudflared
/// 4. Hardcoded fallbacks in [`KNOWN_CLOUDFLARED_PATHS`]
///
/// `which` alone isn't enough because the launchd-managed admin backend has a
/// minimal `PATH` — the cascade ensures the subcommand resolves the binary
/// regardless of the calling context.
#[must_use]
pub fn detect_cloudflared() -> Option<CloudflaredBinary> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(p) = std::env::var_os("THEYOS_CLOUDFLARED_BIN") {
        candidates.push(PathBuf::from(p));
    }

    if let Some(path) = which_path("cloudflared") {
        candidates.push(path);
    }

    if let Some(prefix) = brew_prefix("cloudflared") {
        candidates.push(prefix.join("bin/cloudflared"));
    }

    for path in KNOWN_CLOUDFLARED_PATHS {
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
        let version = cloudflared_version(&path).unwrap_or_default();
        return Some(CloudflaredBinary { path, version });
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

fn cloudflared_version(bin: &Path) -> Option<String> {
    let output = Command::new(bin).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&output.stdout);
    // Output looks like: `cloudflared version 2026.3.0 (built 2026-03-15-1234 UTC)`
    line.split_whitespace().nth(2).map(str::to_string)
}

// ── Paths ────────────────────────────────────────────────────────────────────

fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
}

fn theyos_dir() -> PathBuf {
    std::env::var_os("THEYOS_DIR").map_or_else(|| home_dir().join(".theyos"), PathBuf::from)
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
    log_dir().join("cloudflared.out.log")
}

#[must_use]
pub fn stderr_log_path() -> PathBuf {
    log_dir().join("cloudflared.err.log")
}

/// Cloudflared connector token file path. Source of truth is the env var the
/// admin backend reads (`THEYOS_CLOUDFLARED_TOKEN_FILE`); when unset we default
/// to `$THEYOS_DIR/cloudflared/token` to match the brew formula's wrapper.
#[must_use]
pub fn token_file_path() -> PathBuf {
    std::env::var_os("THEYOS_CLOUDFLARED_TOKEN_FILE")
        .map_or_else(|| theyos_dir().join("cloudflared/token"), PathBuf::from)
}

/// Cloudflared config.yml path. Same env-var resolution rule as
/// [`token_file_path`].
#[must_use]
pub fn config_file_path() -> PathBuf {
    std::env::var_os("THEYOS_CLOUDFLARED_CONFIG").map_or_else(
        || theyos_dir().join("cloudflared/config.yml"),
        PathBuf::from,
    )
}

// ── Bootstrap dirs + stub config ─────────────────────────────────────────────

/// Empty cloudflared config — the admin backend (`cloudflared_sync.rs`)
/// rewrites this on every public-site change. Without a stub, cloudflared
/// refuses to start with `--config <missing-path>`. Mirror of NixOS bootstrap
/// in `nix/module.nix:471-477`.
const STUB_CONFIG_YAML: &str = "ingress:\n  - service: http_status:404\n";

fn ensure_dirs() -> Result<(), CloudflaredError> {
    let config = config_file_path();
    if let Some(parent) = config.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CloudflaredError::Io(format!("create config dir: {e}")))?;
        set_mode(parent, 0o700);
    }
    let token = token_file_path();
    if let Some(parent) = token.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CloudflaredError::Io(format!("create token dir: {e}")))?;
        set_mode(parent, 0o700);
    }
    fs::create_dir_all(log_dir())
        .map_err(|e| CloudflaredError::Io(format!("create log dir: {e}")))?;
    let plist_dir = plist_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    if !plist_dir.as_os_str().is_empty() {
        fs::create_dir_all(&plist_dir).map_err(|e| {
            CloudflaredError::Io(format!(
                "create LaunchAgents dir {}: {e}",
                plist_dir.display()
            ))
        })?;
    }
    Ok(())
}

fn write_stub_config_if_missing() -> Result<(), CloudflaredError> {
    let path = config_file_path();
    if path.exists() {
        return Ok(());
    }
    fs::write(&path, STUB_CONFIG_YAML)
        .map_err(|e| CloudflaredError::ConfigWrite(format!("write {}: {e}", path.display())))?;
    set_mode(&path, 0o644);
    Ok(())
}

// ── Plist generation ─────────────────────────────────────────────────────────

/// Render the `LaunchAgent` plist. The `ProgramArguments` mirror the systemd
/// `ExecStart` from `nix/module.nix:795` byte-for-byte — `--metrics
/// 127.0.0.1:2000` is mandatory or the admin backend's TCP-probe status check
/// silently breaks.
fn render_plist(bin: &CloudflaredBinary, config: &Path, token: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin_path}</string>
        <string>--no-autoupdate</string>
        <string>--metrics</string>
        <string>{METRICS_HOST}:{METRICS_PORT}</string>
        <string>tunnel</string>
        <string>--config</string>
        <string>{config_path}</string>
        <string>run</string>
        <string>--token-file</string>
        <string>{token_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>ExitTimeOut</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
</dict>
</plist>
"#,
        label = BUNDLE_ID,
        bin_path = xml_escape(&bin.path.display().to_string()),
        config_path = xml_escape(&config.display().to_string()),
        token_path = xml_escape(&token.display().to_string()),
        stdout = xml_escape(&stdout_log_path().display().to_string()),
        stderr = xml_escape(&stderr_log_path().display().to_string()),
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Write the plist to `~/Library/LaunchAgents/com.theyos.cloudflared.plist`.
/// Idempotent: returns `Ok(false)` when the existing file already matches.
fn write_plist(bin: &CloudflaredBinary) -> Result<bool, CloudflaredError> {
    let path = plist_path();
    let config = config_file_path();
    let token = token_file_path();
    let content = render_plist(bin, &config, &token);
    let existing = fs::read_to_string(&path).ok();
    if existing.as_deref() == Some(content.as_str()) {
        return Ok(false);
    }
    fs::write(&path, &content)
        .map_err(|e| CloudflaredError::PlistWrite(format!("write {}: {e}", path.display())))?;
    set_mode(&path, 0o644);
    Ok(true)
}

fn plist_needs_regeneration(bin: &CloudflaredBinary) -> bool {
    plist_needs_regeneration_at(&plist_path(), bin)
}

fn plist_needs_regeneration_at(plist: &Path, bin: &CloudflaredBinary) -> bool {
    let Ok(existing) = fs::read_to_string(plist) else {
        return true;
    };
    let want = render_plist(bin, &config_file_path(), &token_file_path());
    existing != want
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

// ── launchctl wrappers ───────────────────────────────────────────────────────

fn current_uid() -> u32 {
    // SAFETY: getuid() is a POSIX syscall with no preconditions. Mirror of
    // caddy_manager.rs:392.
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

/// `launchctl bootstrap gui/<uid> <plist>`. Idempotent: re-bootstrap returns
/// "already bootstrapped" which we surface as success.
pub fn launchctl_bootstrap() -> Result<(), CloudflaredError> {
    let plist = plist_path();
    let output = Command::new("launchctl")
        .args(["bootstrap", &gui_domain()])
        .arg(&plist)
        .output()
        .map_err(|e| CloudflaredError::Launchctl(format!("spawn: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if stderr.contains("service already loaded") || stderr.contains("already bootstrapped") {
        return Ok(());
    }
    Err(CloudflaredError::Launchctl(format!(
        "bootstrap failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        stderr.trim()
    )))
}

/// `launchctl bootout gui/<uid>/<label>`. Idempotent.
pub fn launchctl_bootout() -> Result<(), CloudflaredError> {
    let output = Command::new("launchctl")
        .args(["bootout", &service_target()])
        .output()
        .map_err(|e| CloudflaredError::Launchctl(format!("spawn: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if stderr.contains("could not find service")
        || stderr.contains("no such process")
        || stderr.contains("not loaded")
    {
        return Ok(());
    }
    Err(CloudflaredError::Launchctl(format!(
        "bootout failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        stderr.trim()
    )))
}

/// `launchctl kickstart -k gui/<uid>/<label>` — restart in place.
pub fn launchctl_kickstart() -> Result<(), CloudflaredError> {
    let output = Command::new("launchctl")
        .args(["kickstart", "-k", &service_target()])
        .output()
        .map_err(|e| CloudflaredError::Launchctl(format!("spawn: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(CloudflaredError::Launchctl(format!(
        "kickstart failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// `launchctl kill SIGHUP gui/<uid>/<label>` — cloudflared rereads config on
/// SIGHUP without dropping connections (matches systemd `ExecReload=kill -HUP`
/// in `nix/module.nix:797`).
pub fn launchctl_sighup() -> Result<(), CloudflaredError> {
    let output = Command::new("launchctl")
        .args(["kill", "SIGHUP", &service_target()])
        .output()
        .map_err(|e| CloudflaredError::Launchctl(format!("spawn: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(CloudflaredError::Launchctl(format!(
        "kill SIGHUP failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

#[derive(Debug, Default)]
pub struct LaunchctlStatus {
    pub loaded: bool,
    pub pid: Option<u32>,
    pub last_exit_code: Option<i32>,
}

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

// ── Status probes ────────────────────────────────────────────────────────────

/// TCP probe to `127.0.0.1:2000` — the cloudflared metrics endpoint. Mirror of
/// `cloudflare_admin::cloudflared_is_running()` so callers see the same truth
/// the admin backend does.
#[must_use]
pub fn metrics_port_open() -> bool {
    let addr: SocketAddr = format!("{METRICS_HOST}:{METRICS_PORT}")
        .parse()
        .expect("static metrics addr is valid");
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

/// Wait for cloudflared to fully exit after `bootout`. Returns when both
/// `launchctl print` reports the service is gone AND the metrics port is no
/// longer accepting connections — caller can then safely call the Cloudflare
/// API to clean up the tunnel without racing a still-active connector.
fn wait_for_dead(timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let still_loaded = launchctl_print().loaded;
        let still_listening = metrics_port_open();
        if !still_loaded && !still_listening {
            return;
        }
        if Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ── High-level lifecycle ─────────────────────────────────────────────────────

/// Idempotent: ensure dirs exist, write stub config if missing, write plist.
/// Does NOT bootstrap — that's `start`.
pub fn install() -> Result<CloudflaredBinary, CloudflaredError> {
    let bin = detect_cloudflared().ok_or(CloudflaredError::NotInstalled)?;
    ensure_dirs()?;
    write_stub_config_if_missing()?;
    let _ = write_plist(&bin)?;
    Ok(bin)
}

/// `install` + bootstrap. Auto-regenerates plist if drift detected (binary
/// path moved, config/token paths changed via env).
pub fn start() -> Result<CloudflaredBinary, CloudflaredError> {
    let bin = detect_cloudflared().ok_or(CloudflaredError::NotInstalled)?;
    ensure_dirs()?;
    write_stub_config_if_missing()?;

    let needs_regen = plist_needs_regeneration(&bin);
    if needs_regen {
        let _ = launchctl_bootout();
        write_plist(&bin)?;
    }

    let already_loaded = launchctl_print().loaded;
    if already_loaded && needs_regen {
        launchctl_bootstrap()?;
    } else if already_loaded {
        // No drift, already loaded → kickstart in place to apply any token
        // changes the backend just wrote.
        launchctl_kickstart()?;
    } else {
        launchctl_bootstrap()?;
    }
    Ok(bin)
}

/// Stop the agent. Bootouts, polls until cloudflared is fully dead (so the
/// caller can safely delete the tunnel via API), then removes the plist.
pub fn stop() -> Result<(), CloudflaredError> {
    launchctl_bootout()?;
    wait_for_dead(Duration::from_secs(10));
    let path = plist_path();
    if path.exists() {
        fs::remove_file(&path).map_err(|e| CloudflaredError::Io(format!("remove plist: {e}")))?;
    }
    Ok(())
}

/// Restart in place via `launchctl kickstart -k`.
pub fn restart() -> Result<(), CloudflaredError> {
    launchctl_kickstart()
}

/// Hot-reload via SIGHUP — cloudflared rereads its config without dropping
/// connections.
pub fn reload() -> Result<(), CloudflaredError> {
    launchctl_sighup()
}

#[derive(Debug)]
pub struct CloudflaredStatus {
    pub binary: Option<CloudflaredBinary>,
    pub plist_present: bool,
    pub launch: LaunchctlStatus,
    pub metrics_up: bool,
    pub plist_drift: bool,
}

#[must_use]
pub fn status() -> CloudflaredStatus {
    let binary = detect_cloudflared();
    let plist_present = plist_path().exists();
    let launch = launchctl_print();
    let metrics_up = metrics_port_open();
    let plist_drift = match (&binary, plist_present) {
        (Some(b), true) => plist_needs_regeneration(b),
        _ => false,
    };
    CloudflaredStatus {
        binary,
        plist_present,
        launch,
        metrics_up,
        plist_drift,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_bin() -> CloudflaredBinary {
        CloudflaredBinary {
            path: PathBuf::from("/opt/homebrew/bin/cloudflared"),
            version: "2026.3.0".to_string(),
        }
    }

    #[test]
    fn render_plist_contains_required_args() {
        let bin = fake_bin();
        let config = PathBuf::from("/Users/x/.theyos/cloudflared/config.yml");
        let token = PathBuf::from("/Users/x/.theyos/cloudflared/token");
        let plist = render_plist(&bin, &config, &token);

        // Bundle id + binary
        assert!(plist.contains("<string>com.theyos.cloudflared</string>"));
        assert!(plist.contains("<string>/opt/homebrew/bin/cloudflared</string>"));

        // Mandatory --metrics flag for the admin backend's TCP probe
        assert!(plist.contains("<string>--metrics</string>"));
        assert!(plist.contains("<string>127.0.0.1:2000</string>"));

        // Tunnel command + config + token-file
        assert!(plist.contains("<string>tunnel</string>"));
        assert!(plist.contains("<string>--config</string>"));
        assert!(plist.contains("<string>/Users/x/.theyos/cloudflared/config.yml</string>"));
        assert!(plist.contains("<string>--token-file</string>"));
        assert!(plist.contains("<string>/Users/x/.theyos/cloudflared/token</string>"));

        // Lifecycle keys
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>Crashed</key>"));
        assert!(plist.contains("<key>ProcessType</key>"));
        assert!(plist.contains("<string>Background</string>"));
        assert!(plist.contains("<key>ExitTimeOut</key>"));
    }

    #[test]
    fn render_plist_xml_escapes_paths() {
        let bin = CloudflaredBinary {
            path: PathBuf::from("/Users/x/My & Apps/cloudflared"),
            version: "2026.3.0".to_string(),
        };
        let plist = render_plist(
            &bin,
            Path::new("/Users/x/conf"),
            Path::new("/Users/x/token"),
        );
        assert!(plist.contains("/Users/x/My &amp; Apps/cloudflared"));
        assert!(!plist.contains("/Users/x/My & Apps/cloudflared"));
    }

    #[test]
    fn plist_needs_regeneration_when_missing() {
        // Use an explicit path so we don't touch the user's real LaunchAgents.
        let dir = std::env::temp_dir().join(format!("cf-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("nonexistent.plist");
        assert!(plist_needs_regeneration_at(&path, &fake_bin()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn error_display_includes_actionable_hints() {
        let err = CloudflaredError::NotInstalled;
        assert!(err.to_string().contains("brew install cloudflared"));
    }

    #[test]
    fn stub_config_is_valid_minimal_yaml() {
        // Smoke check: must contain `ingress:` and a service line so cloudflared
        // doesn't choke on first start before any public site exists.
        assert!(STUB_CONFIG_YAML.contains("ingress:"));
        assert!(STUB_CONFIG_YAML.contains("http_status:404"));
    }
}
