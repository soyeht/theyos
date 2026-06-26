//! Deploy pipeline — 4 independent commands: build, test, deploy, validate.
//!
//! ```text
//! soyeht build [--skip-frontend]          # No sudo. Compile + stage binaries.
//! soyeht test  [--skip-clippy]            # No sudo. Clippy + cargo test.
//! sudo soyeht deploy [--skip-restart]     # Stage → release, restart, smoke test.
//! sudo soyeht validate [--rebuild-snapshots]  # Warm pool + E2E installed claws.
//! ```
//!
//! `build` compiles the workspace and stages the runtime key binaries in
//! `.deploy-staging/`.
//! `deploy` copies from staging to `target/release/`, restarts the service, runs
//! a smoke test.  If smoke fails, deploy auto-rolls back to `.deploy-backup/`.
//! `validate` does NOT rollback on failure — admin stays running for debugging.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::admin_backend::{start_admin_backend, stop_admin_backend};
use crate::cli::UpdateArgs;
use crate::util::{admin_health_url, admin_port, curl_ok};

/// Resolve the real user home from `THEYOS_HOME` in `.env`.
///
/// Delegates to [`core_rs::env::theyos_home`] — the single source of truth
/// for sudo-safe home resolution.
fn theyos_home(root: &Path) -> String {
    core_rs::env::theyos_home(root)
}

/// Release-profile e2e-runner binary.
fn e2e_runner_bin(root: &Path) -> PathBuf {
    release_dir(root).join("e2e-runner")
}

const SYSTEMD_UNIT: &str = "soyeht-admin-host.service";

// ── Runtime binaries that the deploy pipeline tracks ────────────────────────

const KEY_BINS: &[&str] = &[
    "server",
    "theyos-admin-host",
    "vmrunner_ipc",
    "fc-ssh",
    "soyeht",
];

// macOS Homebrew: VZ-specific binaries (replaces Firecracker set above).
// Matches scripts/make.sh macOS staging list.
#[cfg(target_os = "macos")]
const KEY_BINS_MACOS: &[&str] = &[
    "soyeht",
    "theyos",
    "theyos-admin-host",
    "server",
    "theyos-ssh",
    "init_macos_guest",
    "executor_ipc",
    "store-ipc",
    "terminal-ipc",
    "vmrunner_macos_ipc",
    "theyos-provision-inject",
];

/// All supported claw types from the manifest — snapshots and validation
/// cover every `Tier::Supported` claw (the ones with goldens + warm pool).
/// Non-supported tiers don't need deploy-time snapshot/validation coverage.
#[cfg(not(target_os = "macos"))]
fn all_claws() -> Vec<&'static str> {
    core_rs::manifest::supported_names()
}

/// Query the running admin server for installed ("ready") claws.
///
/// For validate, the admin backend MUST be running. If the server is not
/// reachable, exit with error — do not silently proceed with 0 claws.
///
/// `/api/v1/claws` lives under the cookie-auth subtree (`auth_middleware`
/// in server-rs `main.rs:515`), so this helper logs in with the admin
/// credentials from `.env` before reading. The `ureq` probe that used to
/// live here was broken against any deployment with real auth enforced —
/// it treated 401 as "backend not reachable" and aborted validate before
/// the warm-pool/E2E phase could run.
#[cfg(not(target_os = "macos"))]
fn ready_claws_from_server(root: &Path) -> Vec<String> {
    // Reachability sanity check first — use the unauthenticated /healthz so
    // a failure here means "server is truly down", not "auth missing".
    let health_url = crate::util::admin_health_url(root);
    let health_ok = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .get(&health_url)
        .call()
        .is_ok();
    if !health_ok {
        eprintln!("[validate] ERROR: admin backend not reachable at {health_url}");
        eprintln!("[validate] The admin backend must be running for validate.");
        eprintln!("[validate] Start it with: sudo systemctl start soyeht-admin-host");
        std::process::exit(1);
    }

    // Authenticate against the admin session cookie. Credentials come from
    // `.env` via `admin_login` — same path used by the warm-pool helpers
    // elsewhere in this file.
    let Some(cookie) = admin_login(root) else {
        eprintln!("[validate] ERROR: failed to authenticate against admin backend");
        eprintln!("[validate] Check SOYEHT_ADMIN_USER / SOYEHT_ADMIN_PASSWORD in .env");
        std::process::exit(1);
    };

    let Some(parsed) = admin_get(root, &cookie, "/claws") else {
        eprintln!("[validate] ERROR: /api/v1/claws request failed (auth or network)");
        std::process::exit(1);
    };

    let Some(items) = parsed["data"].as_array() else {
        eprintln!("[validate] ERROR: unexpected /api/v1/claws response format");
        std::process::exit(1);
    };

    let ready: Vec<String> = items
        .iter()
        .filter(|item| item["status"].as_str() == Some("ready"))
        .filter_map(|item| item["name"].as_str().map(String::from))
        .collect();

    if ready.is_empty() {
        println!("[validate] 0 installed claws");
    } else {
        println!(
            "[validate] {} installed claw(s): {}",
            ready.len(),
            ready.join(", ")
        );
    }
    ready
}

// ── Directory helpers ───────────────────────────────────────────────────────

fn release_dir(root: &Path) -> PathBuf {
    root.join("admin/rust/target/release")
}

fn staging_dir(root: &Path) -> PathBuf {
    root.join("admin/rust/target/release/.deploy-staging")
}

fn backup_dir(root: &Path) -> PathBuf {
    root.join("admin/rust/target/release/.deploy-backup")
}

fn previous_dir(root: &Path) -> PathBuf {
    root.join("admin/rust/target/release/.deploy-previous")
}

// ── Pre-build snapshot ──────────────────────────────────────────────────────

/// Snapshot the current production binaries from `target/release/` into
/// `.deploy-previous/` **before** `cargo build` overwrites them.
///
/// This is the actual rollback source — `cmd_deploy` copies from here into
/// `.deploy-backup/` so a failed smoke test restores the real previous release,
/// not the just-built version.
fn snapshot_previous(root: &Path) -> bool {
    let src = release_dir(root);
    let dst = previous_dir(root);

    // Clean stale snapshot
    if dst.exists() {
        let _ = fs::remove_dir_all(&dst);
    }
    if let Err(e) = fs::create_dir_all(&dst) {
        eprintln!("[build]   failed to create .deploy-previous/ dir: {e}");
        return false;
    }

    let mut count = 0;
    for bin in KEY_BINS {
        let from = src.join(bin);
        let to = dst.join(bin);
        if from.is_file() {
            if let Err(e) = fs::copy(&from, &to) {
                eprintln!("[build]   failed to snapshot {bin}: {e}");
                return false;
            }
            count += 1;
        }
        // First-ever build: no existing binaries — nothing to snapshot.
    }
    println!("[build]   snapshotted {count} production binaries to .deploy-previous/");
    true
}

fn cleanup_previous(root: &Path) {
    let prev = previous_dir(root);
    if prev.exists() {
        let _ = fs::remove_dir_all(&prev);
    }
}

// ── Backup / rollback ───────────────────────────────────────────────────────

/// Copy the pre-build binaries from `.deploy-previous/` to `.deploy-backup/`
/// so we can roll back on smoke failure.
///
/// This copies from `.deploy-previous/` (not from `target/release/`) because
/// `cargo build --release` has already overwritten `target/release/` by the
/// time `cmd_deploy` runs.
fn backup_binaries(root: &Path) -> bool {
    let src = previous_dir(root);
    let dst = backup_dir(root);

    if !src.is_dir() {
        // No previous snapshot — first-ever deploy, nothing to roll back to.
        println!(
            "[deploy]   no .deploy-previous/ found (first deploy?) — rollback will not be available"
        );
        return true;
    }

    // Remove stale backup if present
    if dst.exists() {
        let _ = fs::remove_dir_all(&dst);
    }
    if let Err(e) = fs::create_dir_all(&dst) {
        eprintln!("[deploy]   failed to create backup dir: {e}");
        return false;
    }

    let mut count = 0;
    for bin in KEY_BINS {
        let from = src.join(bin);
        let to = dst.join(bin);
        if from.is_file() {
            if let Err(e) = fs::copy(&from, &to) {
                eprintln!("[deploy]   failed to backup {bin}: {e}");
                return false;
            }
            count += 1;
        }
    }
    println!("[deploy]   backed up {count} previous binaries to .deploy-backup/");
    true
}

/// Restore the runtime key binaries from `.deploy-backup/`.
fn restore_binaries(root: &Path) -> bool {
    let bak = backup_dir(root);
    let dst = release_dir(root);

    if !bak.is_dir() {
        eprintln!("[deploy]   no backup directory found — cannot rollback binaries");
        return false;
    }

    let mut count = 0;
    for bin in KEY_BINS {
        let from = bak.join(bin);
        let to = dst.join(bin);
        if from.is_file() {
            // Unlink first to avoid ETXTBSY on running binaries.
            if to.exists() {
                let _ = fs::remove_file(&to);
            }
            if let Err(e) = fs::copy(&from, &to) {
                eprintln!("[deploy]   failed to restore {bin}: {e}");
                return false;
            }
            count += 1;
        }
    }
    println!("[deploy]   restored {count} binaries from .deploy-backup/");
    true
}

fn cleanup_backup(root: &Path) {
    let bak = backup_dir(root);
    if bak.exists() {
        let _ = fs::remove_dir_all(&bak);
    }
}

// ── Staging area ────────────────────────────────────────────────────────────

/// Copy the runtime key binaries from `target/release/` to `.deploy-staging/`.
fn stage_binaries(root: &Path) -> bool {
    let src = release_dir(root);
    let dst = staging_dir(root);

    // Clean stale staging
    if dst.exists() {
        let _ = fs::remove_dir_all(&dst);
    }
    if let Err(e) = fs::create_dir_all(&dst) {
        eprintln!("[build]   failed to create staging dir: {e}");
        return false;
    }

    let mut count = 0;
    for bin in KEY_BINS {
        let from = src.join(bin);
        let to = dst.join(bin);
        if !from.is_file() {
            eprintln!("[build]   GATE: binary missing: {}", from.display());
            return false;
        }
        if let Err(e) = fs::copy(&from, &to) {
            eprintln!("[build]   failed to stage {bin}: {e}");
            return false;
        }
        count += 1;
    }

    // Print sizes
    println!("[build]   staged {count} binaries to .deploy-staging/:");
    for bin in KEY_BINS {
        let path = dst.join(bin);
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        #[allow(clippy::cast_precision_loss)] // display-only: sub-byte precision not needed
        let mb = size as f64 / (1024.0 * 1024.0);
        println!("[build]     {bin:<24} {mb:.1}M");
    }
    true
}

/// Copy binaries from `.deploy-staging/` to `target/release/`.
///
/// On Linux, a running binary cannot be overwritten in-place (ETXTBSY).
/// We unlink the target inode first, then copy the new file.  The running
/// process keeps its old inode until it exits.
fn promote_staging(root: &Path) -> bool {
    let src = staging_dir(root);
    let dst = release_dir(root);

    let mut count = 0;
    for bin in KEY_BINS {
        let from = src.join(bin);
        let to = dst.join(bin);
        if !from.is_file() {
            eprintln!("[deploy]   GATE: staged binary missing: {bin}");
            return false;
        }
        // Remove target first to avoid ETXTBSY on running binaries.
        if to.exists() {
            let _ = fs::remove_file(&to);
        }
        if let Err(e) = fs::copy(&from, &to) {
            eprintln!("[deploy]   failed to promote {bin}: {e}");
            return false;
        }
        count += 1;
    }
    println!("[deploy]   promoted {count} binaries from staging to release");
    true
}

fn cleanup_staging(root: &Path) {
    let stg = staging_dir(root);
    if stg.exists() {
        let _ = fs::remove_dir_all(&stg);
    }
}

// ── Backend lifecycle helpers ───────────────────────────────────────────────

/// Check if the backend is managed by a systemd unit.
fn is_systemd_managed() -> bool {
    Command::new("systemctl")
        .args(["is-active", SYSTEMD_UNIT])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if the systemd unit exists (enabled, disabled, or static).
fn systemd_unit_exists() -> bool {
    let output = Command::new("systemctl")
        .args(["list-unit-files", SYSTEMD_UNIT, "--no-legend"])
        .output();
    match output {
        Ok(o) => !o.stdout.is_empty(),
        Err(_) => false,
    }
}

/// Drain the warm pool before restarting, so pre-warmed VMs don't survive as
/// orphan processes after the backend exits.
fn drain_warm_pool_pre_restart(root: &Path) {
    let Some(cookie) = admin_login(root) else {
        println!("[deploy]   warm pool drain: backend not reachable (skipped)");
        return;
    };

    println!("[deploy]   draining warm pool before restart ...");
    match admin_post(root, &cookie, "/admin/drain-warm-pool", None) {
        Some(v) => println!("[deploy]   warm pool drain result: {v}"),
        None => println!("[deploy]   warm pool drain: failed or timed out (continuing)"),
    }
}

/// Restart backend via systemd or fallback to PID-file based stop/start.
fn restart_backend(root: &Path) -> bool {
    let health = admin_health_url(root);

    // Drain warm-pool VMs before restarting so they don't become orphans.
    drain_warm_pool_pre_restart(root);

    if is_systemd_managed() || systemd_unit_exists() {
        println!("[deploy]   systemctl restart {SYSTEMD_UNIT} ...");
        let ok = Command::new("systemctl")
            .args(["restart", SYSTEMD_UNIT])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            // Try with sudo
            println!("[deploy]   retrying with sudo ...");
            let ok = Command::new("/run/wrappers/bin/sudo")
                .args(["systemctl", "restart", SYSTEMD_UNIT])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                eprintln!("[deploy]   systemctl restart FAILED");
                return false;
            }
        }
    } else {
        // Fallback: PID-file based lifecycle
        println!("[deploy]   no systemd unit found, using PID-file lifecycle ...");
        stop_admin_backend(root);
        // Verify it's actually down
        if curl_ok(&health, 2) {
            println!("[deploy]   backend still responding, waiting 3s ...");
            std::thread::sleep(std::time::Duration::from_secs(3));
            if curl_ok(&health, 2) {
                eprintln!("[deploy]   GATE: backend still running after stop");
                return false;
            }
        }
        if !start_admin_backend(root) {
            eprintln!("[deploy]   GATE: backend did not become healthy in 30s");
            return false;
        }
        return true;
    }

    // Wait for healthz (up to 60s for systemd restart — VMs can slow it down)
    println!("[deploy]   waiting for backend to become healthy ...");
    for i in 0..60 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if curl_ok(&health, 2) {
            println!("[deploy]   backend healthy after {i}s");
            return true;
        }
        if i == 15 {
            println!("[deploy]   still waiting for backend ...");
        }
    }
    eprintln!("[deploy]   GATE: backend did not become healthy in 60s");
    false
}

// ── Admin API helpers (for warm pool convergence) ───────────────────────────

/// Authenticate with the admin backend and return a session cookie string.
/// Returns `None` if login fails.
fn admin_login(root: &Path) -> Option<String> {
    let port = admin_port(root);
    let login_url = format!("http://127.0.0.1:{port}/api/v1/auth/login");
    let env_file = root.join(".env");
    let username = std::env::var("SOYEHT_ADMIN_USER")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| core_rs::env::read_env_field(&env_file, "SOYEHT_ADMIN_USER"))
        .unwrap_or_else(|| "admin".into());
    let password = std::env::var("SOYEHT_ADMIN_PASSWORD")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| core_rs::env::read_env_field(&env_file, "SOYEHT_ADMIN_PASSWORD"))
        .unwrap_or_default();
    let out = Command::new("curl")
        .args([
            "-s",
            "-c",
            "-", // cookie jar to stdout
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            &format!(r#"{{"username":"{username}","password":"{password}"}}"#),
            "--max-time",
            "5",
            &login_url,
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|l| l.contains("session"))
        .and_then(|l| l.split('\t').next_back())
        .map(|v| format!("soyeht_session={v}"))
}

/// Make an authenticated GET request to the admin API and return the JSON body.
#[cfg(not(target_os = "macos"))]
fn admin_get(root: &Path, cookie: &str, path: &str) -> Option<serde_json::Value> {
    let port = admin_port(root);
    let url = format!("http://127.0.0.1:{port}/api/v1{path}");
    let out = Command::new("curl")
        .args(["-s", "-b", cookie, "--max-time", "10", &url])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

/// Make an authenticated POST request to the admin API and return the JSON body.
fn admin_post(
    root: &Path,
    cookie: &str,
    path: &str,
    body: Option<&str>,
) -> Option<serde_json::Value> {
    let port = admin_port(root);
    let url = format!("http://127.0.0.1:{port}/api/v1{path}");
    let mut args = vec!["-s", "-X", "POST", "-b", cookie, "--max-time", "30"];
    if let Some(b) = body {
        args.extend_from_slice(&["-H", "Content-Type: application/json", "-d", b]);
    }
    args.push(&url);
    let out = Command::new("curl").args(&args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

/// Wait for warm pool slots to converge to `"warm"`.
///
/// Algorithm (progress-oriented, not blind timeout):
/// 1. Poll `GET /admin/warm-pool-status` every 5s.
/// 2. If all slots are `"warm"` -> success.
/// 3. If any are `"empty"` -> trigger `POST /admin/warm-pool-refill` for them.
/// 4. Progress = `warm_count` increased above previous best. State flapping
///    (empty/filling) without increasing `warm_count` is NOT progress.
/// 5. If stalled for 180s -> attempt recovery: drain + re-init.
/// 6. If stalled again for 180s after recovery, or total > 900s -> fail.
#[cfg(not(target_os = "macos"))]
fn ensure_warm_pool_ready(root: &Path) -> bool {
    let claws = all_claws();
    println!(
        "[validate] ensuring warm pool is ready for all {} claws ...",
        claws.len()
    );

    let Some(cookie) = admin_login(root) else {
        eprintln!("[validate] warm pool: cannot authenticate with backend");
        return false;
    };

    let start = Instant::now();
    let mut last_progress = Instant::now();
    let mut best_warm_count: usize = 0;
    let mut recovery_attempted = false;
    let stall_limit = std::time::Duration::from_secs(180);
    let total_limit = std::time::Duration::from_secs(900);

    loop {
        // Check total timeout
        if start.elapsed() > total_limit {
            eprintln!(
                "[validate] warm pool: total timeout exceeded ({}s)",
                total_limit.as_secs()
            );
            return false;
        }

        // Poll status
        let Some(status) = admin_get(root, &cookie, "/admin/warm-pool-status") else {
            eprintln!("[validate] warm pool: failed to query status, retrying ...");
            std::thread::sleep(std::time::Duration::from_secs(5));
            continue;
        };

        // Parse states for each claw
        let mut all_warm = true;
        let mut states_display = Vec::new();

        for claw in &claws {
            let state = status[*claw].as_str().unwrap_or("unknown");
            states_display.push(format!("{claw}={state}"));

            if state != "warm" {
                all_warm = false;
            }

            // If empty, trigger refill
            if state == "empty" {
                let body = format!(r#"{{"claw_type":"{claw}"}}"#);
                if let Some(r) = admin_post(root, &cookie, "/admin/warm-pool-refill", Some(&body)) {
                    let action = r["warm_pool_refill"].as_str().unwrap_or("unknown");
                    println!("[validate]   refill triggered for {claw}: {action}");
                }
            }
        }

        if all_warm {
            let elapsed = start.elapsed().as_secs();
            println!(
                "[validate] warm pool ready: all {} claws warm ({elapsed}s)",
                claws.len()
            );
            return true;
        }

        // Check for real progress: warm_count must increase to reset the
        // stall timer. This prevents empty↔filling flapping from masking
        // a stall where no slot actually converges to warm.
        let warm_count = states_display
            .iter()
            .filter(|s| s.ends_with("=warm"))
            .count();
        if warm_count > best_warm_count {
            best_warm_count = warm_count;
            last_progress = Instant::now();
        }

        // Check stall
        if last_progress.elapsed() > stall_limit {
            if recovery_attempted {
                eprintln!(
                    "[validate] warm pool stalled after recovery: {}",
                    states_display.join(", ")
                );
                return false;
            }

            // Attempt recovery: drain + re-init
            println!(
                "[validate] warm pool stalled for {}s, attempting recovery (drain + init) ...",
                stall_limit.as_secs()
            );
            admin_post(root, &cookie, "/admin/drain-warm-pool", None);
            std::thread::sleep(std::time::Duration::from_secs(3));
            admin_post(root, &cookie, "/admin/warm-pool-init", None);
            recovery_attempted = true;
            best_warm_count = 0; // drain cleared all slots — reset baseline
            last_progress = Instant::now();
            println!("[validate] recovery initiated, continuing to wait ...");
        }

        // Status line
        let elapsed = start.elapsed().as_secs();
        println!(
            "[validate]   [{elapsed}s] {warm_count}/{} warm: {}",
            claws.len(),
            states_display.join(", ")
        );

        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

// ── Output helpers ──────────────────────────────────────────────────────────

fn separator() {
    println!("================================================================");
}

// ── Public entry points ─────────────────────────────────────────────────────

/// `soyeht build` — compile release workspace + stage runtime binaries.
///
/// Runs as normal user (no sudo). Produces `.deploy-staging/` with the runtime
/// binaries that the production service actually uses.
///
/// **Important**: snapshots the current production binaries into
/// `.deploy-previous/` *before* `cargo build` overwrites `target/release/`.
/// This ensures `cmd_deploy` can roll back to the real previous release.
pub fn cmd_build(root: &Path, skip_frontend: bool) {
    let t = Instant::now();
    let rust_dir = root.join("admin/rust");

    if !rust_dir.is_dir() {
        eprintln!(
            "[build] admin/rust/ not found in {} — run from repo dir or set THEYOS_REPO_DIR",
            root.display()
        );
        std::process::exit(1);
    }

    // Snapshot current production binaries BEFORE cargo build overwrites them.
    // This is the rollback source for cmd_deploy if the smoke test fails.
    println!("[build] snapshotting current production binaries ...");
    if !snapshot_previous(root) {
        eprintln!(
            "[build] WARNING: could not snapshot previous binaries — rollback will not be available"
        );
        // Non-fatal: first-ever build has nothing to snapshot.
    }

    println!("[build] cargo build --release --workspace ...");
    let ok = Command::new("cargo")
        .args(["build", "--release", "--workspace"])
        .current_dir(&rust_dir)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("[build] cargo build --release --workspace FAILED");
        std::process::exit(1);
    }

    // Frontend
    if skip_frontend {
        println!("[build] frontend build skipped (--skip-frontend)");
    } else {
        let frontend_dir = root.join("admin/frontend");

        println!("[build] npm ci ...");
        let ok = Command::new("npm")
            .arg("ci")
            .current_dir(&frontend_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[build] npm ci FAILED");
            std::process::exit(1);
        }

        println!("[build] npm run build ...");
        let ok = Command::new("npm")
            .args(["run", "build"])
            .current_dir(&frontend_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[build] npm run build FAILED");
            std::process::exit(1);
        }
    }

    // Stage binaries
    if !stage_binaries(root) {
        eprintln!("[build] staging FAILED");
        std::process::exit(1);
    }

    let elapsed = t.elapsed().as_secs();
    println!();
    separator();
    println!("[build] BUILD COMPLETE ({elapsed}s) — run `soyeht test` next");
    separator();
}

// ── Update helpers ────────────────────────────────────────────────────────

/// Get the short HEAD commit hash.
fn git_short_head(root: &Path) -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Pre-flight: ensure working tree is clean, remote is reachable.
/// Returns the current HEAD hash.
fn update_preflight(root: &Path) -> String {
    // 1. Check for uncommitted changes to tracked files
    println!("[update] checking for uncommitted changes ...");
    let diff_status = Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .current_dir(root)
        .status();
    match diff_status {
        Ok(s) if !s.success() => {
            eprintln!("[update] ERROR: you have uncommitted changes to tracked files");
            eprintln!("[update] Commit or stash them before running update.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[update] ERROR: failed to check git status: {e}");
            std::process::exit(1);
        }
        _ => {}
    }

    // 2. Check remote is reachable
    println!("[update] checking remote ...");
    let fetch_ok = Command::new("git")
        .args(["fetch", "--dry-run"])
        .current_dir(root)
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !fetch_ok {
        eprintln!("[update] ERROR: cannot reach remote — check your network connection");
        std::process::exit(1);
    }

    git_short_head(root)
}

/// Pull latest code via `git pull --ff-only`.
/// Returns `(old_head, new_head)` or `None` if already up to date.
fn update_pull(root: &Path, old_head: &str) -> Option<String> {
    println!("[update] pulling from origin ...");
    let pull = Command::new("git")
        .args(["pull", "--ff-only"])
        .current_dir(root)
        .status();
    match pull {
        Ok(s) if !s.success() => {
            let branch = Command::new("git")
                .args(["rev-parse", "--abbrev-ref", "HEAD"])
                .current_dir(root)
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map_or_else(|| "main".to_string(), |s| s.trim().to_string());
            eprintln!("[update] ERROR: git pull --ff-only failed (history has diverged?)");
            eprintln!("[update] Resolve manually: git fetch && git rebase origin/{branch}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[update] ERROR: git pull failed: {e}");
            std::process::exit(1);
        }
        _ => {}
    }

    let new_head = git_short_head(root);
    if old_head == new_head {
        println!("[update] already up to date ({old_head})");
        return None;
    }

    println!("[update] updated {old_head} → {new_head}");

    // Print short summary of changes
    let shortlog = Command::new("git")
        .args(["log", "--oneline", &format!("{old_head}..{new_head}")])
        .current_dir(root)
        .output();
    if let Ok(o) = shortlog {
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines() {
            println!("[update]   {line}");
        }
    }

    Some(new_head)
}

/// Build step for update: snapshot, cargo build, optional frontend, stage.
#[cfg(not(target_os = "macos"))]
fn update_build(root: &Path, skip_frontend: bool) {
    let rust_dir = root.join("admin/rust");

    println!("[update] snapshotting current production binaries ...");
    if !snapshot_previous(root) {
        eprintln!(
            "[update] WARNING: could not snapshot previous binaries — rollback will not be available"
        );
    }

    println!("[update] building (cargo build --release --workspace) ...");
    let ok = Command::new("cargo")
        .args(["build", "--release", "--workspace"])
        .current_dir(&rust_dir)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("[update] cargo build FAILED");
        std::process::exit(1);
    }

    if skip_frontend {
        println!("[update] frontend build skipped (--skip-frontend)");
    } else {
        let frontend_dir = root.join("admin/frontend");
        println!("[update] npm ci ...");
        let ok = Command::new("npm")
            .arg("ci")
            .current_dir(&frontend_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[update] npm ci FAILED");
            std::process::exit(1);
        }

        println!("[update] npm run build ...");
        let ok = Command::new("npm")
            .args(["run", "build"])
            .current_dir(&frontend_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[update] npm run build FAILED");
            std::process::exit(1);
        }
    }

    if !stage_binaries(root) {
        eprintln!("[update] staging FAILED");
        std::process::exit(1);
    }
}

/// Deploy step for update: backup, promote, restart, smoke test with rollback.
#[cfg(not(target_os = "macos"))]
fn update_deploy(root: &Path) {
    println!("[update] backing up current binaries ...");
    backup_binaries(root);

    println!("[update] promoting staged binaries ...");
    if !promote_staging(root) {
        eprintln!("[update] promotion FAILED — binaries unchanged");
        std::process::exit(1);
    }

    println!("[update] restarting backend ...");
    if !restart_backend(root) {
        eprintln!("[update] restart FAILED — rolling back ...");
        rollback(root);
        std::process::exit(1);
    }

    let runner = e2e_runner_bin(root);
    if runner.is_file() {
        println!("[update] running smoke test ...");
        let smoke_ok = Command::new(&runner)
            .arg("smoke")
            .env("HOME", theyos_home(root))
            .env("THEYOS_DIR", root)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !smoke_ok {
            eprintln!("[update] smoke test FAILED — rolling back ...");
            rollback(root);
            std::process::exit(1);
        }
    } else {
        println!("[update] e2e-runner not found, skipping smoke test");
    }

    cleanup_backup(root);
    cleanup_staging(root);
    cleanup_previous(root);
}

/// `soyeht update` — git pull + build + deploy in one command (Linux).
///
/// Wraps the full pipeline for end users who just want to update.
/// Runs `git pull --ff-only`, then build, then deploy (unless `--skip-deploy`).
/// On macOS, use `cmd_update_macos` instead.
#[cfg(not(target_os = "macos"))]
pub fn cmd_update(root: &Path, args: &UpdateArgs) {
    let t = Instant::now();

    let old_head = update_preflight(root);

    let Some(new_head) = update_pull(root, &old_head) else {
        println!("[update] nothing to build or deploy");
        return;
    };

    update_build(root, args.skip_frontend);

    // Optional test gate
    if args.test {
        let rust_dir = root.join("admin/rust");
        println!("[update] running clippy ...");
        let ok = Command::new("cargo")
            .args(["clippy", "--workspace", "--", "-D", "warnings"])
            .current_dir(&rust_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[update] clippy FAILED");
            std::process::exit(1);
        }

        println!("[update] running tests ...");
        let ok = Command::new("cargo")
            .args(["test", "--workspace"])
            .current_dir(&rust_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[update] cargo test FAILED");
            std::process::exit(1);
        }
    }

    // Optional artifact sync (DAG-based golden image reconciliation)
    if args.sync_artifacts {
        println!("[update] syncing artifacts (DAG reconciliation)...");
        crate::artifacts::cmd_artifacts_sync(root, false, false, &[]);
    }

    if args.skip_deploy {
        let elapsed = t.elapsed().as_secs();
        println!();
        separator();
        println!("[update] BUILD COMPLETE ({elapsed}s) — {old_head} → {new_head} (deploy skipped)");
        separator();
        return;
    }

    update_deploy(root);

    let elapsed = t.elapsed().as_secs();
    println!();
    separator();
    println!("[update] UPDATE COMPLETE ({elapsed}s) — {old_head} → {new_head}");
    separator();
}

/// `soyeht test` — run clippy + cargo test.
///
/// Runs as normal user (no sudo).
pub fn cmd_test(root: &Path, skip_clippy: bool) {
    let t = Instant::now();
    let rust_dir = root.join("admin/rust");

    if !rust_dir.is_dir() {
        eprintln!(
            "[test] admin/rust/ not found in {} — run from repo dir or set THEYOS_REPO_DIR",
            root.display()
        );
        std::process::exit(1);
    }

    // Clippy
    if skip_clippy {
        println!("[test] clippy skipped (--skip-clippy)");
    } else {
        println!("[test] cargo clippy --workspace -- -D warnings ...");
        let ok = Command::new("cargo")
            .args(["clippy", "--workspace", "--", "-D", "warnings"])
            .current_dir(&rust_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[test] cargo clippy FAILED");
            std::process::exit(1);
        }
    }

    // Tests
    println!("[test] cargo test --workspace ...");
    let ok = Command::new("cargo")
        .args(["test", "--workspace", "--", "--test-threads=1"])
        .current_dir(&rust_dir)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("[test] cargo test FAILED");
        std::process::exit(1);
    }

    let elapsed = t.elapsed().as_secs();
    println!();
    separator();
    println!("[test] TEST COMPLETE ({elapsed}s) — run `sudo soyeht deploy` next");
    separator();
}

/// `soyeht deploy` — promote staged binaries, restart, smoke test.
///
/// Requires sudo.  Rolls back automatically if smoke test fails.
pub fn cmd_deploy(root: &Path, skip_restart: bool) {
    let t = Instant::now();

    if !root.join("admin/rust").is_dir() {
        eprintln!(
            "[deploy] admin/rust/ not found in {} — run from repo dir or set THEYOS_REPO_DIR",
            root.display()
        );
        std::process::exit(1);
    }

    // Gate: staging must exist
    let stg = staging_dir(root);
    if !stg.is_dir() {
        eprintln!(
            "[deploy] ERROR: no staged binaries found at {}",
            stg.display()
        );
        eprintln!("[deploy] Run `soyeht build` first.");
        std::process::exit(1);
    }
    for bin in KEY_BINS {
        if !stg.join(bin).is_file() {
            eprintln!("[deploy] ERROR: staged binary missing: {bin}");
            eprintln!("[deploy] Run `soyeht build` first.");
            std::process::exit(1);
        }
    }

    // Backup current binaries (for rollback)
    println!("[deploy] backing up current binaries ...");
    backup_binaries(root);

    // Promote staging -> release
    println!("[deploy] promoting staged binaries ...");
    if !promote_staging(root) {
        eprintln!("[deploy] promotion FAILED — binaries unchanged");
        std::process::exit(1);
    }

    if skip_restart {
        cleanup_staging(root);
        let elapsed = t.elapsed().as_secs();
        println!();
        separator();
        println!("[deploy] DEPLOY COMPLETE ({elapsed}s) — binaries copied, restart skipped");
        separator();
        return;
    }

    // Restart + smoke test
    println!("[deploy] restarting backend ...");
    if !restart_backend(root) {
        eprintln!("[deploy] restart FAILED — rolling back ...");
        rollback(root);
        std::process::exit(1);
    }

    // Smoke test
    let runner = e2e_runner_bin(root);
    if !runner.is_file() {
        eprintln!(
            "[deploy] e2e-runner not found: {} — rolling back ...",
            runner.display()
        );
        rollback(root);
        std::process::exit(1);
    }

    println!("[deploy] running smoke test ...");
    let smoke_ok = Command::new(&runner)
        .arg("smoke")
        .env("HOME", theyos_home(root))
        .env("THEYOS_DIR", root)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !smoke_ok {
        eprintln!("[deploy] smoke test FAILED — rolling back ...");
        rollback(root);
        std::process::exit(1);
    }

    // Success — clean up all transient directories
    cleanup_backup(root);
    cleanup_staging(root);
    cleanup_previous(root);
    let elapsed = t.elapsed().as_secs();
    println!();
    separator();
    println!("[deploy] DEPLOY COMPLETE ({elapsed}s) — run `sudo soyeht validate` next");
    separator();
}

/// `soyeht validate` — warm pool convergence + E2E tests.
///
/// Requires sudo (Firecracker VMs).  Does NOT rollback on failure.
#[cfg(not(target_os = "macos"))]
#[allow(clippy::too_many_lines)]
pub fn cmd_validate(
    root: &Path,
    rebuild_snapshots: bool,
    sync_artifacts: bool,
    settle: u64,
    timeout: u64,
) {
    let t = Instant::now();

    // Query running server for installed ("ready") claws.
    // Fails if the admin backend is not reachable (required for validate).
    let claws = ready_claws_from_server(root);

    let runner = e2e_runner_bin(root);
    if !runner.is_file() {
        eprintln!("[validate] e2e-runner not found: {}", runner.display());
        std::process::exit(1);
    }

    let home = theyos_home(root);

    // Optional: DAG-based artifact sync (replaces --rebuild-snapshots)
    if sync_artifacts {
        println!("[validate] running artifact DAG sync...");
        crate::artifacts::cmd_artifacts_sync(root, false, false, &[]);
        println!("[validate] artifact sync complete");
    }

    // Optional: rebuild snapshots (legacy, prefer --sync-artifacts)
    if rebuild_snapshots {
        println!(
            "[validate] rebuilding snapshots for all {} claws ...",
            claws.len()
        );
        let snap_base = PathBuf::from(&home).join("firecracker/assets/snapshots");

        let mut args: Vec<&str> = vec!["snapshot", "--force"];
        for c in &claws {
            args.push(c);
        }
        let ok = Command::new(&runner)
            .args(&args)
            .env("HOME", &home)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[validate] snapshot creation FAILED");
            std::process::exit(1);
        }

        // Gate: verify snapshot.ready for each installed claw.
        // Check versionated layout (via `current` symlink) first, then legacy flat.
        let assets_dir = PathBuf::from(&home).join("firecracker/assets");
        for claw in &claws {
            let versionated_ok = {
                let current_link = core_rs::artifact_meta::snapshot_current_link(&assets_dir, claw);
                if let Ok(target) = std::fs::read_link(&current_link) {
                    let resolved = if target.is_relative() {
                        current_link
                            .parent()
                            .unwrap_or(Path::new("."))
                            .join(&target)
                    } else {
                        target
                    };
                    resolved.join("snapshot.ready").is_file()
                } else {
                    false
                }
            };
            let legacy_ok = snap_base.join(claw).join("snapshot.ready").is_file();
            if !versionated_ok && !legacy_ok {
                eprintln!("[validate] GATE: missing snapshot.ready for {claw}");
                std::process::exit(1);
            }
        }
        println!("[validate] all {} snapshots ready", claws.len());
    }

    // D6: If no claws are installed, skip warm pool + E2E
    if claws.is_empty() {
        println!("[validate] WARNING: no claws installed — skipping warm pool and E2E");
        println!("[validate] Install claws via the admin panel claw store, then re-run validate.");
        let elapsed = t.elapsed().as_secs();
        println!();
        separator();
        println!("[validate] VALIDATE COMPLETE ({elapsed}s) — smoke only (no claws installed)");
        separator();
        return;
    }

    // Warm pool convergence
    if !ensure_warm_pool_ready(root) {
        eprintln!("[validate] warm pool convergence FAILED");
        eprintln!("[validate] Admin backend is still running — debug with:");
        eprintln!("[validate]   curl -s http://localhost:8892/healthz");
        eprintln!("[validate]   sudo journalctl -u {SYSTEMD_UNIT} -n 50");
        std::process::exit(1);
    }

    // E2E test only installed claws
    let claws_list = claws.join(", ");
    println!("[validate] e2e-runner test {claws_list} ...");
    let settle_str = settle.to_string();
    let timeout_str = timeout.to_string();
    let mut args: Vec<&str> = vec!["test"];
    for c in &claws {
        args.push(c);
    }
    args.extend_from_slice(&["--settle", &settle_str, "--timeout", &timeout_str]);
    // Propagate THEYOS_DIR so the e2e-runner child can resolve the repo
    // root even under sudo (HOME is /root, SUDO_USER may not be set if the
    // child predates the sudo-invoker fallback commit 56a422c). We already
    // have `root` in this scope — pass it down explicitly.
    let ok = Command::new(&runner)
        .args(&args)
        .env("HOME", &home)
        .env("THEYOS_DIR", root)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("[validate] E2E validation FAILED");
        eprintln!("[validate] Admin backend is still running — no rollback performed.");
        std::process::exit(1);
    }

    let elapsed = t.elapsed().as_secs();
    println!();
    separator();
    println!(
        "[validate] VALIDATE COMPLETE ({elapsed}s) — {} claws passed E2E",
        claws.len()
    );
    separator();
}

// ── macOS validate ──────────────────────────────────────────────────────────

/// `soyeht validate` on macOS — smoke tests + per-claw e2e (sequential).
///
/// Unlike Linux, macOS VMs are limited to 2 concurrent, so we test one claw
/// at a time. Default: picoclaw only. Pass claw names to test more.
#[cfg(target_os = "macos")]
pub fn cmd_validate_macos(_root: &Path, claw_types: &[String], settle: u64, timeout: u64) {
    use std::time::{Duration, Instant};

    let t = Instant::now();
    let default_claws = vec!["picoclaw".to_string()];
    let claws = if claw_types.is_empty() {
        &default_claws
    } else {
        claw_types
    };

    // macOS needs more settle time between claws (VZ slot release is async)
    let settle = if settle < 15 { 15 } else { settle };
    println!(
        "[validate-macos] Testing {} claw(s): {}",
        claws.len(),
        claws.join(", ")
    );

    // ── Precheck ──────────────────────────────────────────────────────
    // 1. Base snapshot exists
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let init_state_path = std::path::PathBuf::from(&home)
        .join("Library/Application Support/theyos/vms/macos-base/init-state.json");
    if !init_state_path.exists() {
        eprintln!("[validate-macos] FAIL: base snapshot not found. Run: init_macos_guest");
        std::process::exit(1);
    }
    let init_content = std::fs::read_to_string(&init_state_path).unwrap_or_default();
    if !init_content.contains("\"complete\"") {
        eprintln!(
            "[validate-macos] FAIL: base image not complete. Run: init_macos_guest --force-provision"
        );
        std::process::exit(1);
    }
    println!("[validate-macos] precheck: base snapshot OK");

    // 2. Admin server healthy
    let health = std::process::Command::new("curl")
        .args(["-sf", "http://localhost:8892/healthz"])
        .output();
    let server_ok = health.map(|o| o.status.success()).unwrap_or(false);
    if !server_ok {
        eprintln!("[validate-macos] FAIL: admin server not responding on :8892");
        std::process::exit(1);
    }
    println!("[validate-macos] precheck: admin server OK");

    // ── Smoke ─────────────────────────────────────────────────────────
    println!("[validate-macos] running smoke tests...");
    let smoke_ok = run_macos_smoke();
    if !smoke_ok {
        eprintln!("[validate-macos] SMOKE FAILED");
        std::process::exit(1);
    }
    println!("[validate-macos] smoke: PASS");

    // ── Per-claw E2E ──────────────────────────────────────────────────
    let ssh_key = std::path::PathBuf::from(&home).join(".theyos/keys/id_ed25519");
    let mut results: Vec<(String, bool, u64, String)> = Vec::new();

    for (i, claw) in claws.iter().enumerate() {
        if i > 0 {
            println!("[validate-macos] settling {settle}s...");
            std::thread::sleep(Duration::from_secs(settle));
        }

        let claw_start = Instant::now();
        println!("[validate-macos] testing {claw}...");

        match run_macos_claw_e2e(claw, &ssh_key, Duration::from_secs(timeout)) {
            Ok(details) => {
                #[allow(clippy::cast_possible_truncation)]
                let ms = claw_start.elapsed().as_millis() as u64;
                println!("[validate-macos]   {claw}: PASS ({ms}ms) {details}");
                results.push((claw.clone(), true, ms, details));
            }
            Err(e) => {
                #[allow(clippy::cast_possible_truncation)]
                let ms = claw_start.elapsed().as_millis() as u64;
                println!("[validate-macos]   {claw}: FAIL ({ms}ms) — {e}");
                results.push((claw.clone(), false, ms, e.clone()));
            }
        }
    }

    // ── Summary ───────────────────────────────────────────────────────
    let elapsed = t.elapsed().as_secs();
    let passed = results.iter().filter(|r| r.1).count();
    let total = results.len();
    println!();
    separator();
    println!("[validate-macos] === Summary ===");
    for (claw, ok, ms, detail) in &results {
        let status = if *ok { "PASS" } else { "FAIL" };
        #[allow(clippy::cast_precision_loss)]
        let secs = *ms as f64 / 1000.0;
        println!("[validate-macos]   {claw:<16} {status:<6} {secs:.1}s  {detail}");
    }
    if passed == total {
        println!("[validate-macos] All {total} test(s) passed ({elapsed}s total)");
    } else {
        println!(
            "[validate-macos] {passed}/{total} passed, {} FAILED ({elapsed}s total)",
            total - passed
        );
    }
    separator();

    if passed < total {
        std::process::exit(1);
    }
}

/// Run macOS smoke tests (no VMs).
#[cfg(target_os = "macos")]
fn run_macos_smoke() -> bool {
    // 1. healthz (GET, no auth)
    let health_ok = std::process::Command::new("curl")
        .args(["-sf", "-o", "/dev/null", "http://localhost:8892/healthz"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    println!(
        "[smoke]   healthz: {}",
        if health_ok { "OK" } else { "FAIL" }
    );

    // 2. login (POST with body)
    let login_ok = std::process::Command::new("curl")
        .args([
            "-sf",
            "-o",
            "/dev/null",
            "-c",
            "/tmp/e2e-smoke-cookies.txt",
            "-H",
            "Content-Type: application/json",
            "-d",
            r#"{"username":"admin","password":"admin"}"#,
            "http://localhost:8892/api/v1/auth/login",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    println!("[smoke]   login: {}", if login_ok { "OK" } else { "FAIL" });

    // 3. network status (GET with auth cookie)
    let net_ok = std::process::Command::new("curl")
        .args([
            "-sf",
            "-o",
            "/dev/null",
            "-b",
            "/tmp/e2e-smoke-cookies.txt",
            "http://localhost:8892/api/v1/network/status",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    println!("[smoke]   network: {}", if net_ok { "OK" } else { "FAIL" });

    health_ok && login_ok && net_ok
}

/// Run full e2e for one macOS claw: create, SSH, verify, delete.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_lines)]
fn run_macos_claw_e2e(
    claw_type: &str,
    ssh_key: &std::path::Path,
    timeout: std::time::Duration,
) -> Result<String, String> {
    use e2e_rs::error::E2eError;
    use e2e_rs::ssh_target::{SshTarget, wait_until_guest_ready};
    use std::time::{Duration, Instant};

    let instance_name = format!("e2e-mac-{claw_type}");
    let container = format!("{claw_type}-{instance_name}");
    let state_dir = resolve_state_dir();

    // 1. Login
    let login_out = std::process::Command::new("curl")
        .args([
            "-sf",
            "-c",
            "/tmp/e2e-cookies.txt",
            "-H",
            "Content-Type: application/json",
            "-d",
            r#"{"username":"admin","password":"admin"}"#,
            "http://localhost:8892/api/v1/auth/login",
        ])
        .output()
        .map_err(|e| format!("login: {e}"))?;
    if !login_out.status.success() {
        return Err("login failed".into());
    }

    // 2. Delete stale instance if it exists from a previous run
    let _ = std::process::Command::new("curl")
        .args([
            "-s",
            "-b",
            "/tmp/e2e-cookies.txt",
            "-X",
            "DELETE",
            &format!("http://localhost:8892/api/v1/instances/inst-{instance_name}"),
        ])
        .output();
    std::thread::sleep(Duration::from_secs(3));

    // 3. Create instance
    let create_body = format!(r#"{{"name":"{instance_name}","claw_type":"{claw_type}"}}"#);
    let create_out = std::process::Command::new("curl")
        .args([
            "-s",
            "-b",
            "/tmp/e2e-cookies.txt",
            "-H",
            "Content-Type: application/json",
            "-d",
            &create_body,
            "http://localhost:8892/api/v1/instances",
        ])
        .output()
        .map_err(|e| format!("create: {e}"))?;
    let body = String::from_utf8_lossy(&create_out.stdout);
    if body.contains("\"error\"") {
        return Err(format!("create failed: {body}"));
    }
    let create_json: serde_json::Value = serde_json::from_slice(&create_out.stdout)
        .map_err(|e| format!("parse create response: {e}"))?;
    let job_id = create_json["job_id"].as_str().unwrap_or("").to_string();
    let instance_id = create_json["instance"]["id"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if job_id.is_empty() {
        return Err("no job_id in create response".into());
    }

    // 3. Poll job
    let deadline = Instant::now() + timeout;
    loop {
        std::thread::sleep(Duration::from_secs(3));
        let poll_out = std::process::Command::new("curl")
            .args([
                "-sf",
                "-b",
                "/tmp/e2e-cookies.txt",
                &format!("http://localhost:8892/api/v1/jobs/{job_id}"),
            ])
            .output()
            .map_err(|e| format!("poll job: {e}"))?;
        if poll_out.status.success() {
            let job: serde_json::Value =
                serde_json::from_slice(&poll_out.stdout).unwrap_or_default();
            let status = job["item"]["status"].as_str().unwrap_or("");
            if status == "completed" {
                break;
            }
            if status == "failed" {
                let err = job["item"]["error"].as_str().unwrap_or("unknown");
                // Cleanup
                let _ = delete_instance(&instance_id);
                return Err(format!("job failed: {err}"));
            }
        }
        if Instant::now() >= deadline {
            let _ = delete_instance(&instance_id);
            return Err("job timeout".into());
        }
    }

    // 4. SSH reachable
    let target = SshTarget::from_macos(&container, &state_dir, ssh_key)
        .map_err(|e| format!("resolve SSH target: {e}"))?;
    if !target.is_reachable(Duration::from_secs(10)) {
        let _ = delete_instance(&instance_id);
        return Err("SSH not reachable".into());
    }

    // 5. Wait for guest ready (claw binary)
    let _t2 = target.host.clone();
    let ct = claw_type.to_string();
    let key = ssh_key.to_path_buf();
    wait_until_guest_ready(
        || {
            let t = SshTarget::from_macos(&format!("{ct}-e2e-mac-{ct}"), &state_dir, &key)
                .map_err(|e| E2eError::Setup { detail: e.to_string() })?;
            // Find the claw binary — try multiple paths since pip/npm install to different locations
            let check = format!(
                "command -v {ct} 2>/dev/null || ls /opt/homebrew/bin/{ct} 2>/dev/null || ls /usr/local/bin/{ct} 2>/dev/null"
            );
            t.exec_ok(&check)?;
            Ok(())
        },
        Duration::from_secs(120),  // ironclaw needs brew install postgresql (~60s)
        Duration::from_secs(3),
    ).map_err(|e| {
        let _ = delete_instance(&instance_id);
        format!("guest not ready: {e}")
    })?;

    // 6. tmux check
    let tmux = target.exec_ok("tmux -V").map_err(|e| {
        let _ = delete_instance(&instance_id);
        format!("tmux: {e}")
    })?;
    let tmux_ok = !tmux.trim().is_empty();

    // 7. Tools check
    let codex_ok = target
        .exec_ok("codex --version 2>/dev/null || codex version 2>/dev/null")
        .is_ok();
    let claude_ok = target.exec_ok("claude --version").is_ok();
    let opencode_ok = target.exec_ok("opencode --version").is_ok();

    // 9. Delete
    let _ = delete_instance(&instance_id);

    // 10. Verify deleted
    std::thread::sleep(Duration::from_secs(2));

    let details = format!(
        "(ssh=ok, tmux={}, codex={}, claude={}, opencode={})",
        if tmux_ok { "ok" } else { "FAIL" },
        if codex_ok { "ok" } else { "FAIL" },
        if claude_ok { "ok" } else { "FAIL" },
        if opencode_ok { "ok" } else { "FAIL" },
    );

    if tmux_ok { Ok(details) } else { Err(details) }
}

#[cfg(target_os = "macos")]
#[allow(clippy::unnecessary_wraps)]
fn delete_instance(instance_id: &str) -> Result<(), String> {
    let _ = std::process::Command::new("curl")
        .args([
            "-sf",
            "-b",
            "/tmp/e2e-cookies.txt",
            "-X",
            "DELETE",
            &format!("http://localhost:8892/api/v1/instances/{instance_id}"),
        ])
        .output();
    Ok(())
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Rollback: restore old binaries + restart backend.
fn rollback(root: &Path) {
    separator();
    eprintln!("[deploy] ROLLING BACK to previous binaries...");

    if restore_binaries(root) {
        eprintln!("[deploy] restarting admin backend (previous version) ...");
        if restart_backend(root) {
            eprintln!("[deploy] ROLLBACK COMPLETE — backend running previous version");
        } else {
            eprintln!("[deploy] ROLLBACK WARNING — backend did not become healthy after restore");
            eprintln!("[deploy] Manual intervention: systemctl restart {SYSTEMD_UNIT}");
        }
    } else {
        eprintln!("[deploy] ROLLBACK FAILED — could not restore binaries");
        eprintln!("[deploy] Manual intervention required");
    }
    separator();
}

// ── macOS Homebrew update ──────────────────────────────────────────────────
//
// On macOS, THEYOS_DIR (~/.theyos) is a config/state dir, NOT the git repo.
// The git repo, Homebrew libexec, and state dir are three separate locations.
// These functions implement `soyeht update` for this model.

/// State directory: ~/.theyos (config, .env, PID files, logs).
#[cfg(target_os = "macos")]
fn resolve_state_dir() -> PathBuf {
    if let Ok(d) = std::env::var("THEYOS_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".theyos")
}

/// Git repo directory: where source code lives.
#[cfg(target_os = "macos")]
fn resolve_repo_dir() -> PathBuf {
    // 1. Explicit env var
    if let Ok(d) = std::env::var("THEYOS_REPO_DIR") {
        if !d.is_empty() {
            let p = PathBuf::from(&d);
            if p.join(".git").is_dir() && p.join("admin").is_dir() && p.join("flake.nix").is_file()
            {
                return p;
            }
        }
    }
    // 2. Walk up from executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(r) = walk_up_for_repo(exe.as_path()) {
            return r;
        }
    }
    // 3. Well-known paths
    if let Ok(home) = std::env::var("HOME") {
        for candidate in &["Documents/theyos", "theyos"] {
            let p = PathBuf::from(&home).join(candidate);
            if p.join(".git").is_dir() && p.join("admin").is_dir() && p.join("flake.nix").is_file()
            {
                return p;
            }
        }
    }
    // 4. Walk up from CWD
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(r) = walk_up_for_repo(&cwd) {
            return r;
        }
    }
    eprintln!("[update] cannot find theyos git repository");
    eprintln!("[update] set THEYOS_REPO_DIR=/path/to/theyos");
    std::process::exit(1);
}

/// Walk up from `start` looking for `.git/` + `admin/` + `flake.nix`.
#[cfg(target_os = "macos")]
fn walk_up_for_repo(start: &Path) -> Option<PathBuf> {
    let mut dir = start;
    for _ in 0..12 {
        if dir.join(".git").is_dir()
            && dir.join("admin").is_dir()
            && dir.join("flake.nix").is_file()
        {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
    None
}

/// Homebrew libexec: where production binaries live.
#[cfg(target_os = "macos")]
fn resolve_bin_dir() -> PathBuf {
    if let Ok(d) = std::env::var("THEYOS_BIN_DIR") {
        if !d.is_empty() {
            let p = PathBuf::from(&d);
            if p.join("server").is_file() {
                return p;
            }
        }
    }
    let default = PathBuf::from("/opt/homebrew/opt/theyos/libexec");
    if default.join("server").is_file() {
        return default;
    }
    eprintln!("[update] cannot find Homebrew libexec directory");
    eprintln!("[update] set THEYOS_BIN_DIR or install via Homebrew");
    std::process::exit(1);
}

/// Frontend assets directory.
#[cfg(target_os = "macos")]
fn resolve_web_dir(bin_dir: &Path) -> PathBuf {
    if let Ok(d) = std::env::var("WEB_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    bin_dir.join("web")
}

/// Set process env vars and persist to `state_dir/.env`.
///
/// This is critical for the restart: `theyos-admin-host` calls
/// `resolve_repo_root()` (which reads `THEYOS_DIR`) BEFORE loading `.env`.
#[cfg(target_os = "macos")]
fn ensure_env_vars(state_dir: &Path, bin_dir: &Path, web_dir: &Path) {
    let bin_str = bin_dir.to_string_lossy();
    let web_str = web_dir.to_string_lossy();
    let state_str = state_dir.to_string_lossy();

    // SAFETY: Runs in main thread before spawning the admin backend.
    // No other threads read the environment concurrently.
    // Pattern: launcher-rs/src/main.rs:192-197
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("THEYOS_DIR", state_str.as_ref());
        std::env::set_var("THEYOS_BIN_DIR", bin_str.as_ref());
        std::env::set_var("WEB_DIR", web_str.as_ref());
    }

    // Persist to .env (survives reboots)
    let env_file = state_dir.join(".env");
    let content = fs::read_to_string(&env_file).unwrap_or_default();
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    let mut changed = false;

    for (key, val) in [("THEYOS_BIN_DIR", &*bin_str), ("WEB_DIR", &*web_str)] {
        let prefix = format!("{key}=");
        let target = format!("{key}={val}");
        if let Some(pos) = lines.iter().position(|l| l.starts_with(&prefix)) {
            if lines[pos] != target {
                println!("[update] .env: updating {key}");
                lines[pos] = target;
                changed = true;
            }
        } else {
            println!("[update] .env: adding {key}");
            lines.push(target);
            changed = true;
        }
    }

    if changed {
        let out = lines.join("\n") + "\n";
        if let Err(e) = fs::write(&env_file, &out) {
            eprintln!("[update] WARNING: failed to write .env: {e}");
        }
    }
}

/// Rewrite Homebrew wrapper scripts so future CLI invocations have correct env.
#[cfg(target_os = "macos")]
fn ensure_wrapper(bin_dir: &Path) {
    let brew_bin = bin_dir.parent().map(|p| p.join("bin"));
    let Some(brew_bin) = brew_bin else { return };
    if !brew_bin.is_dir() {
        return;
    }

    let bin_str = bin_dir.to_string_lossy();
    let vmrunner_exports = format!(
        r#"export THEYOS_VMRUNNER_RS_BIN="{bin_str}/vmrunner_macos_ipc"
export THEYOS_VMRUNNER_MACOS_RS_BIN="$THEYOS_VMRUNNER_RS_BIN""#
    );

    // soyeht wrapper
    let wrapper = format!(
        r#"#!/bin/sh
: "${{THEYOS_DIR:=$HOME/.theyos}}"
export THEYOS_DIR
export THEYOS_BIN_DIR="{bin_str}"
export WEB_DIR="{bin_str}/web"
export THEYOS_SSH_CTL="{bin_str}/theyos-ssh"
{vmrunner_exports}
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
exec "{bin_str}/soyeht" "$@"
"#
    );
    let soyeht_path = brew_bin.join("soyeht");
    if let Err(e) = fs::write(&soyeht_path, &wrapper) {
        eprintln!(
            "[update] WARNING: failed to write wrapper {}: {e}",
            soyeht_path.display()
        );
    } else {
        set_executable(&soyeht_path);
        println!("[update] wrapper: {}", soyeht_path.display());
    }

    // theyos wrapper (Homebrew service runs `theyos start --foreground`)
    let theyos_wrapper = format!(
        r#"#!/bin/sh
: "${{THEYOS_DIR:=$HOME/.theyos}}"
export THEYOS_DIR
export THEYOS_BIN_DIR="{bin_str}"
export WEB_DIR="{bin_str}/web"
export THEYOS_SSH_CTL="{bin_str}/theyos-ssh"
{vmrunner_exports}
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
exec "{bin_str}/theyos" "$@"
"#
    );
    let theyos_path = brew_bin.join("theyos");
    if let Err(e) = fs::write(&theyos_path, &theyos_wrapper) {
        eprintln!(
            "[update] WARNING: failed to write wrapper {}: {e}",
            theyos_path.display()
        );
    } else {
        set_executable(&theyos_path);
        println!("[update] wrapper: {}", theyos_path.display());
    }

    // init_macos_guest wrapper
    let init_wrapper = format!(
        r#"#!/bin/sh
: "${{THEYOS_DIR:=$HOME/.theyos}}"
export THEYOS_DIR
export THEYOS_BIN_DIR="{bin_str}"
{vmrunner_exports}
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
exec "{bin_str}/init_macos_guest" "$@"
"#
    );
    let init_path = brew_bin.join("init_macos_guest");
    if let Err(e) = fs::write(&init_path, &init_wrapper) {
        eprintln!(
            "[update] WARNING: failed to write wrapper {}: {e}",
            init_path.display()
        );
    } else {
        set_executable(&init_path);
    }
}

#[cfg(target_os = "macos")]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        let _ = fs::set_permissions(path, perms);
    }
}

/// Backup current Homebrew binaries for rollback.
#[cfg(target_os = "macos")]
fn backup_macos_binaries(bin_dir: &Path) -> bool {
    let dst = bin_dir.join(".deploy-backup");
    if dst.exists() {
        let _ = fs::remove_dir_all(&dst);
    }
    if let Err(e) = fs::create_dir_all(&dst) {
        eprintln!("[update] failed to create backup dir: {e}");
        return false;
    }

    let mut count = 0;
    for bin in KEY_BINS_MACOS {
        let src = bin_dir.join(bin);
        if src.is_file() {
            if let Err(e) = fs::copy(&src, dst.join(bin)) {
                eprintln!("[update] WARNING: failed to backup {bin}: {e}");
            } else {
                count += 1;
            }
        }
    }

    // Backup web/
    let web_src = bin_dir.join("web");
    if web_src.is_dir() {
        let _ = Command::new("cp")
            .args(["-r"])
            .arg(&web_src)
            .arg(dst.join("web"))
            .status();
    }

    if count == 0 {
        println!("[update] first install — no existing binaries to backup");
    } else {
        println!("[update] backed up {count} binaries");
    }
    true
}

/// Restore binaries from backup after failed deploy.
#[cfg(target_os = "macos")]
fn restore_macos_binaries(bin_dir: &Path) -> bool {
    let backup = bin_dir.join(".deploy-backup");
    if !backup.is_dir() {
        eprintln!("[update] no backup directory — cannot restore");
        return false;
    }

    let mut count = 0;
    for bin in KEY_BINS_MACOS {
        let src = backup.join(bin);
        let dst = bin_dir.join(bin);
        if src.is_file() {
            let _ = fs::remove_file(&dst);
            if let Err(e) = fs::copy(&src, &dst) {
                eprintln!("[update] WARNING: failed to restore {bin}: {e}");
            } else {
                count += 1;
            }
        }
    }

    // Restore web/
    let web_backup = backup.join("web");
    let web_dst = bin_dir.join("web");
    if web_backup.is_dir() {
        let _ = fs::remove_dir_all(&web_dst);
        let _ = Command::new("cp")
            .args(["-r"])
            .arg(&web_backup)
            .arg(&web_dst)
            .status();
    }

    println!("[update] restored {count} binaries from backup");
    count > 0
}

/// Copy newly built binaries to Homebrew libexec.
#[cfg(target_os = "macos")]
fn promote_macos_binaries(repo_dir: &Path, bin_dir: &Path) -> bool {
    let src = repo_dir.join("admin/rust/target/release");
    let mut count = 0;

    for bin in KEY_BINS_MACOS {
        let from = src.join(bin);
        let to = bin_dir.join(bin);
        if !from.is_file() {
            eprintln!(
                "[update] GATE: binary missing from build: {}",
                from.display()
            );
            return false;
        }
        let _ = fs::remove_file(&to);
        if let Err(e) = fs::copy(&from, &to) {
            eprintln!("[update] failed to promote {bin}: {e}");
            return false;
        }
        count += 1;
    }

    println!(
        "[update] promoted {count} binaries to {}",
        bin_dir.display()
    );
    true
}

/// Codesign `vmrunner_macos_ipc` with Virtualization Framework entitlement.
/// Returns false on failure (FATAL — VMs won't work without it).
#[cfg(target_os = "macos")]
fn codesign_vmrunner(bin_dir: &Path, repo_dir: &Path) -> bool {
    let binary = bin_dir.join("vmrunner_macos_ipc");
    if !binary.is_file() {
        eprintln!(
            "[update] vmrunner_macos_ipc not found in {}",
            bin_dir.display()
        );
        return false;
    }

    // Try repo entitlements first, then Homebrew-packaged copy
    let ent_repo = repo_dir.join("scripts/entitlements/vmrunner-macos.entitlements");
    let ent_brew = bin_dir.join("vmrunner-macos.entitlements");
    let entitlements = if ent_repo.is_file() {
        ent_repo
    } else if ent_brew.is_file() {
        ent_brew
    } else {
        eprintln!("[update] entitlements file not found");
        return false;
    };

    println!("[update] codesigning vmrunner_macos_ipc ...");
    let ok = Command::new("codesign")
        .args(["--force", "--entitlements"])
        .arg(&entitlements)
        .args(["-s", "-"])
        .arg(&binary)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("[update] CODESIGN FAILED — VMs will not work");
    }
    ok
}

/// Copy frontend build output to web dir.
#[cfg(target_os = "macos")]
fn promote_macos_frontend(repo_dir: &Path, web_dir: &Path) -> bool {
    let src = repo_dir.join("admin/web");
    if !src.is_dir() {
        eprintln!("[update] admin/web/ not found — frontend not built?");
        return false;
    }
    let _ = fs::remove_dir_all(web_dir);
    let ok = Command::new("cp")
        .args(["-r"])
        .arg(&src)
        .arg(web_dir)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        println!("[update] frontend promoted to {}", web_dir.display());
    } else {
        eprintln!("[update] failed to copy frontend");
    }
    ok
}

/// Stop backend: tries PID file in `state_dir`, then `repo_dir`, then kill-by-port.
#[cfg(target_os = "macos")]
fn stop_macos_backend(state_dir: &Path, repo_dir: &Path) {
    let health = admin_health_url(state_dir);

    // 1. Try PID file in state dir
    stop_admin_backend(state_dir);
    if !curl_ok(&health, 2) {
        return; // stopped
    }

    // 2. Try PID file in repo dir
    println!("[update] backend still running, trying repo PID file ...");
    stop_admin_backend(repo_dir);
    std::thread::sleep(std::time::Duration::from_secs(1));
    if !curl_ok(&health, 2) {
        return; // stopped
    }

    // 3. Kill by port
    println!("[update] backend still running, killing by port ...");
    let port = admin_port(state_dir);
    let output = Command::new("lsof")
        .args(["-i", &format!(":{port}"), "-t"])
        .output();
    if let Ok(o) = output {
        let pids = String::from_utf8_lossy(&o.stdout);
        for pid_str in pids.split_whitespace() {
            if let Ok(pid) = pid_str.parse::<u32>() {
                core_rs::os::kill_pid(pid);
            }
        }
    }

    // Wait for it to die
    for _ in 0..5 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if !curl_ok(&health, 1) {
            println!("[update] backend stopped");
            return;
        }
    }

    // Force kill
    if let Ok(o) = Command::new("lsof")
        .args(["-i", &format!(":{port}"), "-t"])
        .output()
    {
        let pids = String::from_utf8_lossy(&o.stdout);
        for pid_str in pids.split_whitespace() {
            if let Ok(pid) = pid_str.parse::<u32>() {
                core_rs::os::kill_pid_force(pid);
            }
        }
    }
    println!("[update] backend force-stopped");
}

/// Smoke test: healthz + login with real credentials + authed API call.
#[cfg(target_os = "macos")]
fn update_smoke_macos(state_dir: &Path) -> bool {
    let port = admin_port(state_dir);
    let health_url = format!("http://127.0.0.1:{port}/healthz");

    // 1. healthz
    let health_ok = curl_ok(&health_url, 5);
    println!("[smoke] healthz: {}", if health_ok { "OK" } else { "FAIL" });
    if !health_ok {
        return false;
    }

    // 2. login with real credentials
    let cookie = admin_login(state_dir);
    let login_ok = cookie.is_some();
    println!("[smoke] login: {}", if login_ok { "OK" } else { "FAIL" });
    if !login_ok {
        return false;
    }

    // 3. authed API call
    let cookie = cookie.unwrap();
    let net_url = format!("http://127.0.0.1:{port}/api/v1/network/status");
    let net_ok = Command::new("curl")
        .args(["-sf", "-o", "/dev/null", "-b", &cookie, &net_url])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    println!("[smoke] network: {}", if net_ok { "OK" } else { "FAIL" });

    health_ok && login_ok && net_ok
}

/// Rollback: restore binaries + restart backend.
#[cfg(target_os = "macos")]
fn rollback_macos(state_dir: &Path, repo_dir: &Path, bin_dir: &Path) {
    separator();
    eprintln!("[update] ROLLING BACK to previous binaries...");

    if restore_macos_binaries(bin_dir) {
        stop_macos_backend(state_dir, repo_dir);
        if start_admin_backend(state_dir) {
            eprintln!("[update] ROLLBACK COMPLETE — backend running previous version");
        } else {
            eprintln!("[update] ROLLBACK WARNING — backend did not become healthy");
        }
    } else {
        eprintln!("[update] ROLLBACK FAILED — no backup available");
    }
    separator();
}

/// `soyeht update` on macOS — git pull → build → promote → restart → smoke.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_lines)]
pub fn cmd_update_macos(_root: &Path, args: &UpdateArgs) {
    let t = Instant::now();

    // 1. Resolve paths independently
    let state_dir = resolve_state_dir();
    let repo_dir = resolve_repo_dir();
    let bin_dir = resolve_bin_dir();
    let web_dir = resolve_web_dir(&bin_dir);

    println!("[update] state:  {}", state_dir.display());
    println!("[update] repo:   {}", repo_dir.display());
    println!("[update] deploy: {}", bin_dir.display());
    println!("[update] web:    {}", web_dir.display());

    // 2. Ensure env vars (process env + .env persistence)
    ensure_env_vars(&state_dir, &bin_dir, &web_dir);

    // 3. Preflight + pull (in repo dir)
    let old_head = update_preflight(&repo_dir);

    let Some(new_head) = update_pull(&repo_dir, &old_head) else {
        println!("[update] nothing to build or deploy");
        return;
    };

    // 4. Build
    let rust_dir = repo_dir.join("admin/rust");
    println!("[update] building (cargo build --release --workspace) ...");
    let ok = Command::new("cargo")
        .args(["build", "--release", "--workspace"])
        .current_dir(&rust_dir)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("[update] cargo build FAILED");
        std::process::exit(1);
    }

    // 5. Frontend
    if args.skip_frontend {
        println!("[update] frontend build skipped (--skip-frontend)");
    } else {
        let frontend_dir = repo_dir.join("admin/frontend");
        println!("[update] npm ci ...");
        let ok = Command::new("npm")
            .arg("ci")
            .current_dir(&frontend_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[update] npm ci FAILED");
            std::process::exit(1);
        }
        println!("[update] npm run build ...");
        let ok = Command::new("npm")
            .args(["run", "build"])
            .current_dir(&frontend_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[update] npm run build FAILED");
            std::process::exit(1);
        }
    }

    // 6. Optional test gate
    if args.test {
        println!("[update] running clippy ...");
        let ok = Command::new("cargo")
            .args(["clippy", "--workspace", "--", "-D", "warnings"])
            .current_dir(&rust_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[update] clippy FAILED");
            std::process::exit(1);
        }
        println!("[update] running tests ...");
        let ok = Command::new("cargo")
            .args(["test", "--workspace"])
            .current_dir(&rust_dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[update] cargo test FAILED");
            std::process::exit(1);
        }
    }

    // 7. Optional artifact sync
    if args.sync_artifacts {
        println!("[update] syncing artifacts (DAG reconciliation) ...");
        crate::artifacts::cmd_artifacts_sync(&state_dir, false, false, &[]);
    }

    // 8. Skip deploy?
    if args.skip_deploy {
        let elapsed = t.elapsed().as_secs();
        println!();
        separator();
        println!("[update] BUILD COMPLETE ({elapsed}s) — {old_head} → {new_head} (deploy skipped)");
        separator();
        return;
    }

    // ── Deploy ────────────────────────────────────────────────────────

    // 9. Backup current installation
    if !backup_macos_binaries(&bin_dir) {
        eprintln!("[update] backup FAILED");
        std::process::exit(1);
    }

    // 10. Promote binaries
    if !promote_macos_binaries(&repo_dir, &bin_dir) {
        eprintln!("[update] promotion FAILED — restoring backup ...");
        restore_macos_binaries(&bin_dir);
        std::process::exit(1);
    }

    // 11. Codesign (FATAL)
    if !codesign_vmrunner(&bin_dir, &repo_dir) {
        eprintln!("[update] codesign FAILED — rolling back ...");
        rollback_macos(&state_dir, &repo_dir, &bin_dir);
        std::process::exit(1);
    }

    // 12. Frontend
    if !args.skip_frontend && !promote_macos_frontend(&repo_dir, &web_dir) {
        eprintln!("[update] WARNING: frontend promotion failed (continuing)");
    }

    // 13. Entitlements file
    let ent_src = repo_dir.join("scripts/entitlements/vmrunner-macos.entitlements");
    if ent_src.is_file() {
        let _ = fs::copy(&ent_src, bin_dir.join("vmrunner-macos.entitlements"));
    }

    // 14. Wrapper
    ensure_wrapper(&bin_dir);

    // 15. Restart backend
    println!("[update] restarting backend ...");
    stop_macos_backend(&state_dir, &repo_dir);
    if !start_admin_backend(&state_dir) {
        eprintln!("[update] restart FAILED — rolling back ...");
        rollback_macos(&state_dir, &repo_dir, &bin_dir);
        std::process::exit(1);
    }

    // 16. Smoke test
    println!("[update] running smoke test ...");
    if !update_smoke_macos(&state_dir) {
        eprintln!("[update] smoke test FAILED — rolling back ...");
        rollback_macos(&state_dir, &repo_dir, &bin_dir);
        std::process::exit(1);
    }

    // 17. Cleanup
    let backup = bin_dir.join(".deploy-backup");
    if backup.exists() {
        let _ = fs::remove_dir_all(&backup);
    }

    let elapsed = t.elapsed().as_secs();
    println!();
    separator();
    println!("[update] UPDATE COMPLETE ({elapsed}s) — {old_head} → {new_head}");
    separator();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)]
    fn set_test_env_var(key: &str, value: &str) {
        // SAFETY: these test helpers are used in narrow, synchronous tests and
        // restore state immediately after the assertion window.
        unsafe { std::env::set_var(key, value) };
    }

    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)]
    fn remove_test_env_var(key: &str) {
        // SAFETY: paired with `set_test_env_var` in test-only code.
        unsafe { std::env::remove_var(key) };
    }

    /// Create a fake root with release dir and populate it with dummy binaries.
    fn setup_fake_root(tmpdir: &Path) -> PathBuf {
        let root = tmpdir.to_path_buf();
        let rel = release_dir(&root);
        fs::create_dir_all(&rel).expect("create release dir");

        // Create fake binaries with known content
        for (i, bin) in KEY_BINS.iter().enumerate() {
            let content = format!("binary-v1-{bin}-{i}");
            fs::write(rel.join(bin), content.as_bytes()).expect("write fake binary");
        }
        root
    }

    #[test]
    fn snapshot_previous_copies_all_binaries() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = setup_fake_root(tmpdir.path());

        assert!(snapshot_previous(&root));

        let prev = previous_dir(&root);
        assert!(prev.is_dir());

        for bin in KEY_BINS {
            let snapped = prev.join(bin);
            assert!(snapped.is_file(), "previous should contain {bin}");
            let original = fs::read_to_string(release_dir(&root).join(bin)).unwrap();
            let copy = fs::read_to_string(&snapped).unwrap();
            assert_eq!(original, copy, "snapshot of {bin} should match original");
        }
    }

    #[test]
    fn backup_copies_from_previous() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = setup_fake_root(tmpdir.path());

        // Snapshot v1 into .deploy-previous/
        assert!(snapshot_previous(&root));

        // Now backup reads from .deploy-previous/, not release_dir
        assert!(backup_binaries(&root));

        let bak = backup_dir(&root);
        assert!(bak.is_dir());

        for bin in KEY_BINS {
            let backed_up = bak.join(bin);
            assert!(backed_up.is_file(), "backup should contain {bin}");
            let prev_content = fs::read_to_string(previous_dir(&root).join(bin)).unwrap();
            let bak_content = fs::read_to_string(&backed_up).unwrap();
            assert_eq!(
                prev_content, bak_content,
                "backup of {bin} should match previous"
            );
        }
    }

    #[test]
    fn backup_succeeds_without_previous_dir() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = setup_fake_root(tmpdir.path());

        // No .deploy-previous/ dir — first-ever deploy scenario
        // backup_binaries should succeed (return true) but not create a backup
        assert!(backup_binaries(&root));
        assert!(
            !backup_dir(&root).exists(),
            "no backup should be created without previous"
        );
    }

    #[test]
    fn backup_partial_previous() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = tmpdir.path().to_path_buf();
        let rel = release_dir(&root);
        fs::create_dir_all(&rel).expect("create release dir");

        // Only create 3 out of the tracked runtime binaries
        for bin in &KEY_BINS[..3] {
            fs::write(rel.join(bin), b"data").expect("write");
        }

        // Snapshot the 3 binaries
        assert!(snapshot_previous(&root));

        // Backup from previous
        assert!(backup_binaries(&root));

        let bak = backup_dir(&root);
        let mut count = 0;
        for bin in KEY_BINS {
            if bak.join(bin).is_file() {
                count += 1;
            }
        }
        assert_eq!(
            count, 3,
            "should backup only existing binaries from previous"
        );
    }

    #[test]
    fn restore_copies_from_backup() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = setup_fake_root(tmpdir.path());

        // Snapshot v1, then backup from snapshot
        assert!(snapshot_previous(&root));
        assert!(backup_binaries(&root));

        // Overwrite release dir with v2
        let rel = release_dir(&root);
        for bin in KEY_BINS {
            fs::write(rel.join(bin), b"binary-v2").expect("overwrite");
        }

        // Restore should bring back v1
        assert!(restore_binaries(&root));

        for (i, bin) in KEY_BINS.iter().enumerate() {
            let content = fs::read_to_string(rel.join(bin)).unwrap();
            let expected = format!("binary-v1-{bin}-{i}");
            assert_eq!(
                content, expected,
                "restored {bin} should be v1, got: {content}"
            );
        }
    }

    #[test]
    fn restore_fails_when_no_backup() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = setup_fake_root(tmpdir.path());

        // No backup created -> restore should fail
        assert!(!restore_binaries(&root));
    }

    #[test]
    fn cleanup_removes_backup_dir() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = setup_fake_root(tmpdir.path());

        assert!(snapshot_previous(&root));
        assert!(backup_binaries(&root));
        assert!(backup_dir(&root).is_dir());

        cleanup_backup(&root);
        assert!(!backup_dir(&root).exists());
    }

    #[test]
    fn backup_overwrites_stale_backup() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = setup_fake_root(tmpdir.path());

        // Snapshot + backup v1
        assert!(snapshot_previous(&root));
        assert!(backup_binaries(&root));

        // Modify a binary in release and re-snapshot
        let rel = release_dir(&root);
        fs::write(rel.join(KEY_BINS[0]), b"modified-v2").expect("modify");
        assert!(snapshot_previous(&root));

        // Backup again — should overwrite with modified-v2
        assert!(backup_binaries(&root));

        let bak_content = fs::read_to_string(backup_dir(&root).join(KEY_BINS[0])).unwrap();
        assert_eq!(
            bak_content, "modified-v2",
            "stale backup should be overwritten"
        );
    }

    #[test]
    fn full_cycle_snapshot_build_deploy_rollback() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = setup_fake_root(tmpdir.path());
        let rel = release_dir(&root);

        // 1. Snapshot v1 (simulates cmd_build saving production binaries)
        assert!(snapshot_previous(&root));

        // 2. Simulate cargo build overwriting release with v2
        for bin in KEY_BINS {
            fs::write(rel.join(bin), b"new-build-v2").expect("overwrite");
        }

        // 3. cmd_deploy: backup from .deploy-previous/ (the real v1)
        assert!(backup_binaries(&root));

        // 4. Simulate staging -> release promotion (v2 already in release)

        // 5. Smoke test fails — rollback restores v1 from backup
        assert!(restore_binaries(&root));

        // 6. Verify all binaries are the original v1 (not v2)
        for (i, bin) in KEY_BINS.iter().enumerate() {
            let content = fs::read_to_string(rel.join(bin)).unwrap();
            let expected = format!("binary-v1-{bin}-{i}");
            assert_eq!(content, expected, "{bin} should be restored to v1, not v2");
        }

        // 7. Cleanup
        cleanup_backup(&root);
        assert!(!backup_dir(&root).exists());
        cleanup_previous(&root);
        assert!(!previous_dir(&root).exists());
    }

    #[test]
    fn key_bins_has_five_runtime_entries() {
        assert_eq!(KEY_BINS.len(), 5, "deploy tracks 5 runtime key binaries");
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn all_claws_has_eight_entries() {
        assert_eq!(all_claws().len(), 8, "should cover all 8 claw types");
    }

    #[test]
    fn stage_copies_all_binaries() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = setup_fake_root(tmpdir.path());

        assert!(stage_binaries(&root));

        let stg = staging_dir(&root);
        assert!(stg.is_dir());

        for bin in KEY_BINS {
            let staged = stg.join(bin);
            assert!(staged.is_file(), "staging should contain {bin}");
            let original = fs::read_to_string(release_dir(&root).join(bin)).unwrap();
            let copy = fs::read_to_string(&staged).unwrap();
            assert_eq!(original, copy, "staged {bin} should match original");
        }
    }

    #[test]
    fn promote_copies_staging_to_release() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = setup_fake_root(tmpdir.path());

        // Stage v1
        assert!(stage_binaries(&root));

        // Overwrite release with v2
        let rel = release_dir(&root);
        for bin in KEY_BINS {
            fs::write(rel.join(bin), b"binary-v2").expect("overwrite");
        }

        // Promote should restore staged v1
        assert!(promote_staging(&root));

        for (i, bin) in KEY_BINS.iter().enumerate() {
            let content = fs::read_to_string(rel.join(bin)).unwrap();
            let expected = format!("binary-v1-{bin}-{i}");
            assert_eq!(
                content, expected,
                "promoted {bin} should be v1 from staging"
            );
        }
    }

    #[test]
    fn promote_fails_without_staging() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let root = setup_fake_root(tmpdir.path());

        // No staging dir -> promote should fail
        assert!(!promote_staging(&root));
    }

    // ── macOS-specific tests ──────────────────────────────────────────────────

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_state_dir_uses_env() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let state = tmpdir.path().join("state");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join(".env"), "FOO=bar\n").unwrap();

        // SAFETY: single-threaded test context
        set_test_env_var("THEYOS_DIR", state.to_str().unwrap());
        let result = resolve_state_dir();
        remove_test_env_var("THEYOS_DIR");

        assert_eq!(result, state);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_repo_dir_from_env() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(repo.join("admin")).unwrap();
        fs::write(repo.join("flake.nix"), "# test").unwrap();

        set_test_env_var("THEYOS_REPO_DIR", repo.to_str().unwrap());
        let result = resolve_repo_dir();
        remove_test_env_var("THEYOS_REPO_DIR");

        assert_eq!(result, repo);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn backup_restore_macos_roundtrip() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let bin_dir = tmpdir.path().join("libexec");
        fs::create_dir_all(&bin_dir).unwrap();

        // Create fake binaries
        for bin in KEY_BINS_MACOS {
            fs::write(bin_dir.join(bin), format!("original-{bin}")).unwrap();
        }

        // Backup
        assert!(backup_macos_binaries(&bin_dir));
        assert!(bin_dir.join(".deploy-backup").is_dir());

        // Modify originals
        for bin in KEY_BINS_MACOS {
            fs::write(bin_dir.join(bin), format!("modified-{bin}")).unwrap();
        }

        // Restore
        assert!(restore_macos_binaries(&bin_dir));

        // Verify originals restored
        for bin in KEY_BINS_MACOS {
            let content = fs::read_to_string(bin_dir.join(bin)).unwrap();
            assert_eq!(
                content,
                format!("original-{bin}"),
                "restore should bring back original {bin}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn backup_handles_first_install() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let bin_dir = tmpdir.path().join("libexec");
        fs::create_dir_all(&bin_dir).unwrap();

        // No binaries exist yet — should succeed gracefully
        assert!(backup_macos_binaries(&bin_dir));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn promote_macos_fails_missing_binary() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        let release = repo.join("admin/rust/target/release");
        fs::create_dir_all(&release).unwrap();
        let bin_dir = tmpdir.path().join("libexec");
        fs::create_dir_all(&bin_dir).unwrap();

        // Only create 1 binary — should fail because others are missing
        fs::write(release.join("soyeht"), "fake").unwrap();

        assert!(!promote_macos_binaries(&repo, &bin_dir));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ensure_env_vars_idempotent() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let state = tmpdir.path().join("state");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join(".env"), "EXISTING=value\n").unwrap();

        let bin = PathBuf::from("/opt/test/libexec");
        let web = PathBuf::from("/opt/test/libexec/web");

        // Call twice — should not duplicate entries
        // SAFETY: single-threaded test
        set_test_env_var("THEYOS_DIR", state.to_str().unwrap());
        ensure_env_vars(&state, &bin, &web);
        ensure_env_vars(&state, &bin, &web);
        remove_test_env_var("THEYOS_DIR");

        let content = fs::read_to_string(state.join(".env")).unwrap();
        let bin_dir_count = content
            .lines()
            .filter(|l| l.starts_with("THEYOS_BIN_DIR="))
            .count();
        assert_eq!(
            bin_dir_count, 1,
            "THEYOS_BIN_DIR should appear exactly once"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ensure_env_vars_corrects_stale() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let state = tmpdir.path().join("state");
        fs::create_dir_all(&state).unwrap();
        fs::write(
            state.join(".env"),
            "THEYOS_BIN_DIR=/old/path\nWEB_DIR=/old/web\n",
        )
        .unwrap();

        let bin = PathBuf::from("/new/path");
        let web = PathBuf::from("/new/web");

        set_test_env_var("THEYOS_DIR", state.to_str().unwrap());
        ensure_env_vars(&state, &bin, &web);
        remove_test_env_var("THEYOS_DIR");

        let content = fs::read_to_string(state.join(".env")).unwrap();
        assert!(
            content.contains("THEYOS_BIN_DIR=/new/path"),
            "should update stale value"
        );
        assert!(
            content.contains("WEB_DIR=/new/web"),
            "should update stale WEB_DIR"
        );
        assert!(!content.contains("/old/"), "stale values should be gone");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ensure_wrapper_always_rewrites() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        // Simulate Homebrew layout: bin/ and libexec/ (parent of bin_dir is the
        // Homebrew prefix, bin/ is a sibling)
        let prefix = tmpdir.path().join("theyos");
        let bin_dir = prefix.join("libexec");
        let brew_bin = prefix.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&brew_bin).unwrap();

        // Write a raw binary (simulating overwritten wrapper)
        fs::write(brew_bin.join("soyeht"), b"\xCF\xFA\xED\xFE").unwrap();
        fs::write(brew_bin.join("theyos"), b"\xCF\xFA\xED\xFE").unwrap();
        fs::write(brew_bin.join("init_macos_guest"), b"\xCF\xFA\xED\xFE").unwrap();

        ensure_wrapper(&bin_dir);

        for name in ["soyeht", "theyos", "init_macos_guest"] {
            let content = fs::read_to_string(brew_bin.join(name)).unwrap();
            assert!(
                content.starts_with("#!/bin/sh"),
                "{name} should be a shell wrapper"
            );
            assert!(
                content.contains("THEYOS_BIN_DIR"),
                "{name} wrapper should set THEYOS_BIN_DIR"
            );
            assert!(
                content.contains("export THEYOS_VMRUNNER_RS_BIN="),
                "{name} wrapper should set canonical vmrunner env"
            );
            assert!(
                content.contains("export THEYOS_VMRUNNER_MACOS_RS_BIN=\"$THEYOS_VMRUNNER_RS_BIN\""),
                "{name} wrapper should alias legacy vmrunner env to canonical env"
            );
        }
    }
}
