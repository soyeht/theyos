//! `install_worker.rs` — Separate background task that processes `InstallClaw`
//! and `UninstallClaw` jobs.
//!
//! Runs independently from the main `jobs_worker.rs` (D4) so that long-running
//! artifact resolution/download/install work never blocks instance
//! create/delete/restart operations.

use crate::state::SharedState;
#[cfg(not(target_os = "macos"))]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const ERROR_BACKOFF: Duration = Duration::from_secs(10);

/// Job types this worker handles.
const INSTALL_TYPES: &[&str] = &["install_claw", "uninstall_claw"];

/// Spawns the install worker as a background tokio task.
pub fn start_install_worker(state: SharedState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_install_worker(state))
}

async fn run_install_worker(state: SharedState) {
    info!("[install-worker] started");

    // Reset any stale installing/uninstalling states from a previous crash.
    // The ClawStore reset handles the claw entries; the jobs-store reset
    // handles the paired install/uninstall jobs. Both must be reset
    // together to prevent drift — a stale `pending` job would be picked
    // up by the scheduler later and tried against a claw state that no
    // longer matches.
    state.claw_store.reset_stale_installing();
    match state.jobs.reset_stale_install_jobs() {
        Ok(0) => {}
        Ok(n) => {
            info!("[install-worker] reset {n} stale install/uninstall job(s) from previous run");
        }
        Err(e) => tracing::warn!("[install-worker] failed to reset stale install jobs: {e}"),
    }

    loop {
        if let Err(e) = process_one_install_job(&state).await {
            error!("[install-worker] loop error: {e}");
            sleep(ERROR_BACKOFF).await;
        }
    }
}

async fn process_one_install_job(state: &SharedState) -> Result<(), String> {
    let st = state.clone();
    let claimed = tokio::task::spawn_blocking(move || {
        st.jobs
            .claim_next_pending_by_types(INSTALL_TYPES)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("spawn_blocking join: {e}"))??;

    let Some(job) = claimed else {
        sleep(POLL_INTERVAL).await;
        return Ok(());
    };

    info!(
        "[install-worker] processing job={} type={} claw={}",
        job.id,
        job.job_type.as_str(),
        job.instance_id
    );

    match job.job_type {
        jobs_rs::JobType::InstallClaw => {
            #[cfg(target_os = "macos")]
            {
                run_install_claw_macos(state, &job).await
            }
            #[cfg(not(target_os = "macos"))]
            {
                run_install_claw(state, &job).await
            }
        }
        jobs_rs::JobType::UninstallClaw => {
            #[cfg(target_os = "macos")]
            {
                run_uninstall_claw_macos(state, &job).await
            }
            #[cfg(not(target_os = "macos"))]
            {
                run_uninstall_claw(state, &job).await
            }
        }
        _ => {
            warn!(
                "[install-worker] unexpected job type: {}",
                job.job_type.as_str()
            );
            Ok(())
        }
    }
}

// ─── Install (Linux) — prebuilt artifact download ──────────────────────────

/// Install a claw by downloading a pre-built golden rootfs artifact.
///
/// All HTTP and I/O happens inside `spawn_blocking` because the resolver and
/// installer use `ureq` (synchronous HTTP client).
#[cfg(not(target_os = "macos"))]
#[allow(clippy::too_many_lines)]
async fn run_install_claw_prebuilt(state: &SharedState, job: &jobs_rs::Job) -> Result<(), String> {
    use crate::artifact_installer::ArtifactInstaller;
    use crate::artifact_resolver::ArtifactResolver;

    let claw_name = job.instance_id.clone();
    let job_id = job.id.clone();

    let registry_url = std::env::var("THEYOS_ARTIFACT_REGISTRY_URL")
        .unwrap_or_else(|_| core_rs::constants::ARTIFACT_REGISTRY_DEFAULT_URL.to_string());

    if registry_url.is_empty() {
        let msg = "THEYOS_ARTIFACT_REGISTRY_URL not configured and no default set".to_string();
        error!("[install-worker] {claw_name}: {msg}");
        if let Err(e) = state.claw_store.mark_failed(&claw_name, &msg) {
            error!("[install-worker] {claw_name}: mark_failed failed: {e}");
        }
        mark_job_failed(state, &job_id, &msg).await;
        return Ok(());
    }

    // Derive assets_dir from locks_dir (same as uninstall path)
    let assets_dir = state
        .locks_dir
        .parent()
        .unwrap_or(std::path::Path::new("/tmp"))
        .parent()
        .unwrap_or(std::path::Path::new("/tmp"))
        .join("assets");

    // Step 1: Resolve manifest
    update_job_message(state, &job_id, "resolving artifact...").await;
    info!("[install-worker] {claw_name}: resolving artifact from {registry_url}");

    let claw_for_resolve = claw_name.clone();
    let registry_url_clone = registry_url.clone();
    let manifest = match tokio::task::spawn_blocking(move || {
        let resolver = ArtifactResolver::new(&registry_url_clone);
        resolver.resolve(&claw_for_resolve)
    })
    .await
    {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => {
            let msg = format!("artifact resolve failed: {e}");
            error!("[install-worker] {claw_name}: {msg}");
            if let Err(e) = state.claw_store.mark_failed(&claw_name, &msg) {
                error!("[install-worker] {claw_name}: mark_failed failed: {e}");
            }
            mark_job_failed(state, &job_id, &msg).await;
            return Ok(());
        }
        Err(e) => {
            let msg = format!("resolve task panicked: {e}");
            error!("[install-worker] {claw_name}: {msg}");
            if let Err(e) = state.claw_store.mark_failed(&claw_name, &msg) {
                error!("[install-worker] {claw_name}: mark_failed failed: {e}");
            }
            mark_job_failed(state, &job_id, &msg).await;
            return Ok(());
        }
    };

    info!(
        "[install-worker] {claw_name}: artifact found: v{} fp={} ({} MB)",
        manifest.version,
        &manifest.fingerprint[..12],
        manifest.size_bytes / 1024 / 1024,
    );

    // Step 2: Check if already up-to-date
    if ArtifactResolver::is_up_to_date(&manifest, &assets_dir) {
        info!("[install-worker] {claw_name}: artifact already installed, marking ready");
        if let Err(e) = state.claw_store.mark_ready(&claw_name) {
            error!("[install-worker] {claw_name}: mark_ready failed: {e}");
        }
        mark_job_completed(state, &job_id).await;
        return Ok(());
    }

    // Step 3: Download + verify + install
    let size_mb = manifest.size_bytes / 1024 / 1024;
    update_job_message(
        state,
        &job_id,
        &format!("downloading artifact ({size_mb} MB)..."),
    )
    .await;
    info!("[install-worker] {claw_name}: downloading {size_mb} MB...");

    let claw_for_install = claw_name.clone();
    let assets_dir_clone = assets_dir.clone();
    // Clone the Arc<AppState> so the blocking task can write progress to
    // state.jobs (jobs_rs::Store is !Clone — it holds a Mutex<Connection>).
    // Arc clone is cheap (refcount bump).
    let state_for_progress = state.clone();
    let job_id_for_progress = job_id.clone();
    // Capture `manifest.size_bytes` before the move so we can use it when
    // writing the terminal "finalizing/100%" progress marker below —
    // `manifest` itself is moved into the blocking closure and is gone
    // from this scope by the time the match arm runs.
    let manifest_size_bytes = manifest.size_bytes;
    // Throttle install-progress writes to 1 Hz so we don't hammer SQLite
    // during the download. Mutex because the FnMut-alike closure is
    // actually Fn+Sync under spawn_blocking.
    let now = std::time::Instant::now();
    let throttle = std::sync::Mutex::new(
        now.checked_sub(std::time::Duration::from_secs(2))
            .unwrap_or(now),
    );

    let install_result = tokio::task::spawn_blocking(move || {
        use core_rs::availability::{InstallPhase, InstallProgress};

        let installer = ArtifactInstaller::new(&assets_dir_clone);
        installer.install(&manifest, |downloaded, total| {
            if total == 0 {
                return;
            }

            // Throttle: at most one UPDATE per second.
            let now = std::time::Instant::now();
            let should_write = {
                let mut last = throttle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if now.duration_since(*last) >= std::time::Duration::from_millis(1000) {
                    *last = now;
                    true
                } else {
                    false
                }
            };
            if !should_write {
                return;
            }

            // Clamp percent to 0..=100 defensively.
            let percent_raw = downloaded.saturating_mul(100) / total;
            let percent = u8::try_from(percent_raw.min(100)).unwrap_or(100);

            tracing::debug!(
                "[install-worker] {claw_for_install}: download {percent}% ({}/{} MB)",
                downloaded / 1024 / 1024,
                total / 1024 / 1024,
            );

            let progress = InstallProgress {
                phase: InstallPhase::Downloading,
                percent,
                bytes_downloaded: downloaded,
                bytes_total: total,
                updated_at_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0),
            };
            if let Ok(json) = serde_json::to_string(&progress) {
                if let Err(e) = state_for_progress.jobs.update_result(&job_id_for_progress, &json)
                {
                    tracing::warn!(
                        "[install-worker] {claw_for_install}: failed to persist install progress: {e}"
                    );
                }
            }
        })
    })
    .await;

    match install_result {
        Ok(Ok(rootfs_path)) => {
            info!(
                "[install-worker] {claw_name}: artifact installed at {}",
                rootfs_path.display()
            );

            // Write a final "finalizing / 100%" progress marker so the iOS
            // client observes the transition from downloading → finalizing
            // before the claw flips to Succeeded. This progress is still
            // read by the availability projection until mark_ready below
            // flips the install status out of Installing.
            {
                use core_rs::availability::{InstallPhase, InstallProgress};
                let final_progress = InstallProgress {
                    phase: InstallPhase::Finalizing,
                    percent: 100,
                    bytes_downloaded: manifest_size_bytes,
                    bytes_total: manifest_size_bytes,
                    updated_at_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                        .unwrap_or(0),
                };
                if let Ok(json) = serde_json::to_string(&final_progress) {
                    let _ = state.jobs.update_result(&job_id, &json);
                }
            }

            if let Err(e) = state.claw_store.mark_ready(&claw_name) {
                error!("[install-worker] {claw_name}: mark_ready failed: {e}");
            }
            mark_job_completed(state, &job_id).await;
            info!("[install-worker] {claw_name}: install complete (prebuilt)");
        }
        Ok(Err(e)) => {
            let msg = format!("artifact install failed: {e}");
            error!("[install-worker] {claw_name}: {msg}");
            if let Err(e) = state.claw_store.mark_failed(&claw_name, &msg) {
                error!("[install-worker] {claw_name}: mark_failed failed: {e}");
            }
            mark_job_failed(state, &job_id, &msg).await;
        }
        Err(e) => {
            let msg = format!("install task panicked: {e}");
            error!("[install-worker] {claw_name}: {msg}");
            if let Err(e) = state.claw_store.mark_failed(&claw_name, &msg) {
                error!("[install-worker] {claw_name}: mark_failed failed: {e}");
            }
            mark_job_failed(state, &job_id, &msg).await;
        }
    }

    Ok(())
}

#[cfg(not(target_os = "macos"))]
async fn run_install_claw(state: &SharedState, job: &jobs_rs::Job) -> Result<(), String> {
    let claw_name = job.instance_id.clone();
    let job_id = job.id.clone();

    // Defense-in-depth tier gate — handlers also enforce this, but worker
    // must check again because jobs can be scheduled via direct DB writes
    // (tests, migrations) that bypass handlers.
    let Some(entry) = core_rs::manifest::get(&claw_name) else {
        let msg = format!("unknown claw type: {claw_name}");
        error!("[install-worker] {claw_name}: {msg}");
        if let Err(e) = state.claw_store.mark_failed(&claw_name, &msg) {
            error!("[install-worker] {claw_name}: mark_failed failed: {e}");
        }
        mark_job_failed(state, &job_id, &msg).await;
        return Ok(());
    };

    // Defense-in-depth installability check using the single-source-of-truth
    // API. Mirrors the HTTP handler gate so a job written directly to the
    // DB (tests, migrations) cannot bypass `ManifestEntry::installability()`.
    if let core_rs::manifest::ClawInstallability::Unavailable { code, message } =
        entry.installability()
    {
        let msg = format!("claw '{claw_name}' is not installable ({code:?}): {message}");
        error!("[install-worker] {claw_name}: {msg}");
        if let Err(e) = state.claw_store.mark_failed(&claw_name, &msg) {
            error!("[install-worker] {claw_name}: mark_failed failed: {e}");
        }
        mark_job_failed(state, &job_id, &msg).await;
        return Ok(());
    }

    // Dispatch order (P-46 Phase C):
    //   1. If the claw is marked `distribution: "prebuilt"` and the registry
    //      resolves a manifest for us → download + install (existing path).
    //   2. Else, if an `InstallerPlan` exists (builtin or template-rendered)
    //      → build locally via the `imagebuilder` subprocess, then install
    //      the resulting golden via the same prebuilt resolver flow.
    //   3. Else → fail loudly.
    if entry.distribution == "prebuilt" {
        return run_install_claw_prebuilt(state, job).await;
    }

    if vmrunner_rs::installer_plan::get_plan(&claw_name).is_some() {
        return run_install_claw_from_plan(state, job).await;
    }

    let msg = format!(
        "no install path available for '{claw_name}' (distribution={}, no installer plan)",
        entry.distribution
    );
    error!("[install-worker] {claw_name}: {msg}");
    if let Err(e) = state.claw_store.mark_failed(&claw_name, &msg) {
        error!("[install-worker] {claw_name}: mark_failed failed: {e}");
    }
    mark_job_failed(state, &job_id, &msg).await;
    Ok(())
}

// ─── Install (Linux) — build-from-plan via imagebuilder subprocess ──────────

/// Install a claw by invoking the `imagebuilder build <claw>` subprocess.
///
/// The subprocess copies the base rootfs, boots a disposable Firecracker VM,
/// executes the `InstallerPlan` (either builtin or template-rendered), then
/// writes `goldens/<claw>/<fingerprint>/rootfs.ext4` + `golden.meta.json`
/// under the `assets/` directory.  We then resolve + install through the
/// same prebuilt path (which is fingerprint-aware and idempotent).
///
/// The imagebuilder binary is resolved in this order:
///   1. `$THEYOS_IMAGEBUILDER_BIN` (explicit override, used by tests)
///   2. `imagebuilder` on `$PATH`
#[cfg(not(target_os = "macos"))]
async fn run_install_claw_from_plan(state: &SharedState, job: &jobs_rs::Job) -> Result<(), String> {
    let claw_name = job.instance_id.clone();
    let job_id = job.id.clone();

    update_job_message(state, &job_id, "building golden image from plan...").await;
    info!("[install-worker] {claw_name}: running imagebuilder build...");

    let bin = resolve_imagebuilder_bin();
    let theyos_dir = state.theyos_dir.clone();
    let claw_for_build = claw_name.clone();
    let bin_for_build = bin.clone();

    let build_result = tokio::task::spawn_blocking(move || {
        run_imagebuilder_build(&bin_for_build, &claw_for_build, &theyos_dir)
    })
    .await;

    match build_result {
        Ok(Ok(())) => {
            info!("[install-worker] {claw_name}: imagebuilder build succeeded");

            // The golden has been written locally. Mark ready directly —
            // the prebuilt resolver path doesn't apply here (we built from
            // plan, not downloaded from a registry), and the golden is
            // already sitting at goldens/<claw>/current/rootfs.ext4.
            if let Err(e) = state.claw_store.mark_ready(&claw_name) {
                error!("[install-worker] {claw_name}: mark_ready failed: {e}");
            }
            mark_job_completed(state, &job_id).await;
            info!("[install-worker] {claw_name}: install complete (built from plan)");
        }
        Ok(Err(msg)) => {
            error!("[install-worker] {claw_name}: {msg}");
            if let Err(e) = state.claw_store.mark_failed(&claw_name, &msg) {
                error!("[install-worker] {claw_name}: mark_failed failed: {e}");
            }
            mark_job_failed(state, &job_id, &msg).await;
        }
        Err(e) => {
            let msg = format!("imagebuilder task join error: {e}");
            error!("[install-worker] {claw_name}: {msg}");
            if let Err(e) = state.claw_store.mark_failed(&claw_name, &msg) {
                error!("[install-worker] {claw_name}: mark_failed failed: {e}");
            }
            mark_job_failed(state, &job_id, &msg).await;
        }
    }

    Ok(())
}

/// Resolve the imagebuilder binary path.
///
/// Prefers `$THEYOS_IMAGEBUILDER_BIN` (explicit override, used by tests),
/// falls back to `imagebuilder` on `$PATH`.
///
/// Cross-platform so the unit tests can exercise it on macOS CI too; the
/// actual subprocess is only spawned from the Linux install path.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn resolve_imagebuilder_bin() -> String {
    std::env::var("THEYOS_IMAGEBUILDER_BIN").unwrap_or_else(|_| "imagebuilder".to_string())
}

/// Spawn `imagebuilder build <claw>` synchronously and return a descriptive
/// error string on failure.
///
/// Callers run this inside `tokio::task::spawn_blocking` — the underlying
/// `std::process::Command::output()` is synchronous.
///
/// Pure helper: doesn't touch `SharedState`. Tested directly with a
/// shell-script fake imagebuilder in unit tests.
///
/// Cross-platform: the subprocess invocation itself is OS-agnostic. Callers
/// are still cfg-gated to the Linux install path.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn run_imagebuilder_build(
    bin: &str,
    claw: &str,
    theyos_dir: &std::path::Path,
) -> Result<(), String> {
    let mut cmd = std::process::Command::new(bin);
    cmd.arg("build").arg(claw);
    if theyos_dir.is_dir() {
        cmd.current_dir(theyos_dir);
    }

    let output = cmd
        .output()
        .map_err(|e| format!("failed to spawn imagebuilder ({bin}): {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::error!(
            "[install-worker] {claw}: imagebuilder failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        return Err(format!(
            "imagebuilder build {claw} failed (exit {:?}): {}",
            output.status.code(),
            stderr.trim()
        ));
    }

    Ok(())
}

// ─── Uninstall (Linux / Firecracker) ────────────────────────────────────────

#[cfg(not(target_os = "macos"))]
async fn run_uninstall_claw(state: &SharedState, job: &jobs_rs::Job) -> Result<(), String> {
    let claw_name = job.instance_id.clone();
    let job_id = job.id.clone();

    update_job_message(state, &job_id, "uninstalling...").await;
    info!("[install-worker] {claw_name}: uninstalling...");

    // Step 1: Delete golden artifacts
    let assets_dir = state
        .locks_dir
        .parent()
        .unwrap_or(Path::new("/tmp"))
        .parent()
        .unwrap_or(Path::new("/tmp"))
        .join("assets");

    let golden_dir = assets_dir.join("goldens").join(&claw_name);
    if golden_dir.is_dir() {
        if let Err(e) = std::fs::remove_dir_all(&golden_dir) {
            warn!("[install-worker] failed to remove goldens for {claw_name}: {e}");
        }
    }

    // Step 2: Delete snapshot artifacts
    let snapshot_dir = assets_dir.join("snapshots").join(&claw_name);
    if snapshot_dir.is_dir() {
        if let Err(e) = std::fs::remove_dir_all(&snapshot_dir) {
            warn!("[install-worker] failed to remove snapshots for {claw_name}: {e}");
        }
    }

    // Step 3: Update state
    if let Err(e) = state.claw_store.mark_not_installed(&claw_name) {
        error!("[install-worker] {claw_name}: mark_not_installed failed: {e}");
    }

    // Step 4: Release warm pool lease (if one exists for this claw type)
    match state
        .instance_db
        .release_lease("warm_pool", &format!("{claw_name}:slot:0"), "runtime")
    {
        Ok(true) => info!("[install-worker] {claw_name}: released warm pool lease"),
        Ok(false) => {} // no active lease — nothing to release
        Err(e) => warn!("[install-worker] {claw_name}: release warm pool lease failed: {e}"),
    }

    mark_job_completed(state, &job_id).await;

    info!("[install-worker] {claw_name}: uninstall complete");

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async fn update_job_message(state: &SharedState, job_id: &str, msg: &str) {
    let st = state.clone();
    let jid = job_id.to_string();
    let m = msg.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(mut job) = st.jobs.get(&jid) {
            job.message = Some(m);
            let _ = st.jobs.update(&job);
        }
    })
    .await;
}

async fn mark_job_failed(state: &SharedState, job_id: &str, error: &str) {
    let st = state.clone();
    let jid = job_id.to_string();
    let err = error.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(mut job) = st.jobs.get(&jid) {
            job.status = jobs_rs::Status::Failed;
            job.error = Some(err);
            job.completed_at = Some(jobs_rs::now_iso());
            let _ = st.jobs.update(&job);
        }
    })
    .await;
}

async fn mark_job_completed(state: &SharedState, job_id: &str) {
    let st = state.clone();
    let jid = job_id.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(mut job) = st.jobs.get(&jid) {
            job.status = jobs_rs::Status::Completed;
            job.completed_at = Some(jobs_rs::now_iso());
            let _ = st.jobs.update(&job);
        }
    })
    .await;
}

// ─── macOS: VZ-based install (shared base image model) ──────────────────────

#[cfg(target_os = "macos")]
async fn run_install_claw_macos(state: &SharedState, job: &jobs_rs::Job) -> Result<(), String> {
    let claw_name = job.instance_id.clone();
    let job_id = job.id.clone();

    update_job_message(state, &job_id, "checking macOS base image...").await;
    info!("[install-worker] {claw_name}: checking macOS base image...");

    if let Err(e) = check_macos_base_ready() {
        let msg = format!("macOS base image not ready: {e}");
        error!("[install-worker] {claw_name}: {msg}");
        if let Err(e) = state.claw_store.mark_failed(&claw_name, &msg) {
            error!("[install-worker] {claw_name}: mark_failed failed: {e}");
        }
        mark_job_failed(state, &job_id, &msg).await;
        return Ok(());
    }

    // Base image is ready with all claw binaries provisioned — mark ready immediately.
    if let Err(e) = state.claw_store.mark_ready(&claw_name) {
        error!("[install-worker] {claw_name}: mark_ready failed: {e}");
    }
    mark_job_completed(state, &job_id).await;

    info!("[install-worker] {claw_name}: macOS install complete (base image already provisioned)");
    Ok(())
}

#[cfg(target_os = "macos")]
async fn run_uninstall_claw_macos(state: &SharedState, job: &jobs_rs::Job) -> Result<(), String> {
    let claw_name = job.instance_id.clone();
    let job_id = job.id.clone();

    update_job_message(state, &job_id, "uninstalling...").await;
    info!("[install-worker] {claw_name}: macOS uninstall (state-only)...");

    // State-only: the binary remains in the shared base image (harmless).
    // It will be refreshed on next `init-macos-guest --force-provision`.
    if let Err(e) = state.claw_store.mark_not_installed(&claw_name) {
        error!("[install-worker] {claw_name}: mark_not_installed failed: {e}");
    }

    // Release warm pool lease (if one exists for this claw type)
    match state
        .instance_db
        .release_lease("warm_pool", &format!("{claw_name}:slot:0"), "runtime")
    {
        Ok(true) => info!("[install-worker] {claw_name}: released warm pool lease"),
        Ok(false) => {} // no active lease — nothing to release
        Err(e) => warn!("[install-worker] {claw_name}: release warm pool lease failed: {e}"),
    }

    mark_job_completed(state, &job_id).await;

    info!("[install-worker] {claw_name}: macOS uninstall complete");
    Ok(())
}

/// Resolve the macOS base image directory.
///
/// Search order:
/// 1. `THEYOS_VM_ASSETS_DIR` env var + `/macos-base/`
/// 2. `~/Library/Application Support/theyos/vms/macos-base/`
#[cfg(target_os = "macos")]
fn macos_base_dir() -> PathBuf {
    if let Ok(d) = std::env::var("THEYOS_VM_ASSETS_DIR") {
        return PathBuf::from(d).join("macos-base");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join("Library/Application Support/theyos/vms/macos-base")
}

/// Check that `init-macos-guest` has completed successfully.
///
/// Reads `init-state.json` from the base dir and verifies `phase == "complete"`.
/// Uses `serde_json::Value` to avoid pulling in `vmrunner-macos-rs` as a dependency.
#[cfg(target_os = "macos")]
fn check_macos_base_ready() -> Result<(), String> {
    let base_dir = macos_base_dir();
    let state_file = base_dir.join("init-state.json");

    if !state_file.exists() {
        return Err("not initialized — run 'theyos init-macos-guest'".into());
    }

    let content =
        std::fs::read_to_string(&state_file).map_err(|e| format!("read init-state.json: {e}"))?;
    let state: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("parse init-state.json: {e}"))?;

    match state.get("phase").and_then(|v| v.as_str()) {
        Some("complete") => Ok(()),
        Some(phase) => Err(format!(
            "init incomplete (phase: {phase}) — run 'theyos init-macos-guest'"
        )),
        None => Err("init-state.json missing phase field — run 'theyos init-macos-guest'".into()),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Write a shell-script fake imagebuilder at `path` with the given body.
    /// Returns the path; caller must keep the surrounding tempdir alive.
    fn write_fake_imagebuilder(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("fake-imagebuilder.sh");
        std::fs::write(&path, body).expect("write fake imagebuilder");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake imagebuilder");
        path
    }

    #[test]
    fn run_imagebuilder_build_success_returns_ok() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Script that checks args and writes a marker file to prove it ran.
        let marker = tmp.path().join("subprocess-ran");
        let body = format!(
            "#!/bin/sh\n\
             [ \"$1\" = build ] || {{ echo 'missing build arg' >&2; exit 2; }}\n\
             [ \"$2\" = testclaw ] || {{ echo 'wrong claw arg' >&2; exit 3; }}\n\
             touch {}\n\
             exit 0\n",
            marker.display()
        );
        let bin = write_fake_imagebuilder(tmp.path(), &body);

        let result = run_imagebuilder_build(bin.to_str().unwrap(), "testclaw", tmp.path());
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert!(
            marker.exists(),
            "fake imagebuilder should have written marker"
        );
    }

    #[test]
    fn run_imagebuilder_build_nonzero_exit_returns_err_with_stderr() {
        let tmp = tempfile::TempDir::new().unwrap();
        let body = "#!/bin/sh\n\
                    echo 'base rootfs missing' >&2\n\
                    exit 1\n";
        let bin = write_fake_imagebuilder(tmp.path(), body);

        let result = run_imagebuilder_build(bin.to_str().unwrap(), "picoclaw", tmp.path());
        assert!(result.is_err(), "expected Err, got {result:?}");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("picoclaw"),
            "error should name the claw, got: {msg}"
        );
        assert!(
            msg.contains("exit"),
            "error should mention exit code, got: {msg}"
        );
        assert!(
            msg.contains("base rootfs missing"),
            "error should include stderr, got: {msg}"
        );
    }

    #[test]
    fn run_imagebuilder_build_missing_binary_returns_err() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bogus = tmp.path().join("does-not-exist");
        let result = run_imagebuilder_build(bogus.to_str().unwrap(), "picoclaw", tmp.path());
        assert!(result.is_err(), "expected spawn-failure Err");
        assert!(
            result.unwrap_err().contains("failed to spawn imagebuilder"),
            "error should describe spawn failure"
        );
    }

    #[test]
    fn run_imagebuilder_build_tolerates_nonexistent_working_dir() {
        // When theyos_dir doesn't exist, the helper should NOT set
        // current_dir and should still invoke the binary successfully.
        let tmp = tempfile::TempDir::new().unwrap();
        let body = "#!/bin/sh\nexit 0\n";
        let bin = write_fake_imagebuilder(tmp.path(), body);

        let missing = tmp.path().join("definitely-not-a-dir");
        let result = run_imagebuilder_build(bin.to_str().unwrap(), "picoclaw", &missing);
        assert!(
            result.is_ok(),
            "helper should tolerate missing working dir, got {result:?}"
        );
    }

    #[test]
    fn resolve_imagebuilder_bin_respects_env_var() {
        // Use core_rs::env helpers so the `unsafe` contract around
        // std::env::set_var (2024 edition) is encapsulated there.
        //
        // Other tests in this module do not touch THEYOS_IMAGEBUILDER_BIN,
        // so there is no TOCTOU risk within this crate. `cargo test` runs
        // tests with `--test-threads=1` in CI; developer-local runs share
        // this env var only with the tests below.
        let sentinel = "/tmp/sentinel-imagebuilder-xyz-test";
        core_rs::env::set_test_env("THEYOS_IMAGEBUILDER_BIN", sentinel);
        let resolved = resolve_imagebuilder_bin();
        assert_eq!(resolved, sentinel);
        core_rs::env::remove_test_env("THEYOS_IMAGEBUILDER_BIN");

        // When unset, falls back to "imagebuilder" (on $PATH).
        let resolved = resolve_imagebuilder_bin();
        assert_eq!(resolved, "imagebuilder");
    }
}
