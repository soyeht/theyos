//! Claw availability projection — runtime glue between the pure types in
//! `core_rs::availability` and the live state in `AppState`.
//!
//! This module owns the probes that read filesystem state (golden rootfs,
//! base rootfs), the maintenance lockfile, and the install store/jobs store.
//! It produces a `ClawAvailability` value on demand (pull-based, no cache).
//!
//! All I/O happens here. The pure types and `compute_overall` live in
//! core-rs because they're trivially testable.
//!
//! # Probe cost
//!
//! Each `project_claw` call does approximately:
//!   - 1 `HashMap` lookup (`ClawStore` state)
//!   - 1-2 file `stat` syscalls (golden + base rootfs)
//!   - 1 `SQLite` query (`jobs.get(id)`) only when install status is `Installing`
//!   - 1 flock read (maintenance status)
//!
//! Total: microseconds under normal conditions. No cache or reconciler
//! necessary. If a bottleneck ever emerges under load (50+ rps per claw),
//! add a short-lived `Arc<RwLock<HostSnapshot>>` later — but measure first.

use crate::state::AppState;
use claw_rs::ClawStatus;
use core_rs::availability::{
    ClawAvailability, Degradation, HostProjection, InstallProgress, InstallProjection,
    InstallStatus, OverallState, UnavailReason, compute_overall,
};
use core_rs::{maintenance, manifest};

// ─── Public entry points ─────────────────────────────────────────────────────

/// Build a `ClawAvailability` for a single claw.
///
/// Called by every gate that needs to answer "can this claw be created?".
/// Returns `ClawAvailability` with `overall == OverallState::Unknown` when
/// the name is not in the manifest — callers should match on `overall`
/// instead of branching on "known or not" manually.
#[must_use]
pub fn project_claw(name: &str, state: &AppState) -> ClawAvailability {
    let shared_host = probe_shared_host(state);
    project_with_shared_host(name, state, &shared_host)
}

/// Project availability for **every** claw in the manifest regardless of tier.
///
/// Returns the full catalog — `Supported`, `Available`, `Detected`, and raw
/// `Catalog` entries alike. Mobile and admin list endpoints use this to
/// populate the store UI (clients decide which tier tab to render and
/// whether install is allowed). For a tier-filtered projection use
/// [`project_supported_claws`] instead.
///
/// Shares the expensive probes (base rootfs, maintenance) across all
/// claws, and only re-probes golden presence per claw (cheap: one stat).
/// Use this for list endpoints like `GET /api/v1/mobile/claws`.
#[must_use]
pub fn project_all_claws(state: &AppState) -> Vec<ClawAvailability> {
    let shared_host = probe_shared_host(state);
    manifest::all_names()
        .iter()
        .map(|name| project_with_shared_host(name, state, &shared_host))
        .collect()
}

/// Project availability only for claws at [`Tier::Supported`](core_rs::manifest::Tier::Supported).
///
/// Callers that need the "what's installable via the fast golden path right
/// now?" set (e.g. warm-pool planner, create endpoint auto-completion)
/// should use this instead of [`project_all_claws`] to avoid iterating over
/// discovery-only entries. Uses the same shared host probe as
/// `project_all_claws` so the per-claw cost is identical.
#[must_use]
pub fn project_supported_claws(state: &AppState) -> Vec<ClawAvailability> {
    let shared_host = probe_shared_host(state);
    manifest::catalog()
        .iter()
        .filter(|entry| entry.tier == core_rs::manifest::Tier::Supported)
        .map(|entry| project_with_shared_host(entry.name, state, &shared_host))
        .collect()
}

// ─── Projection core (internal) ──────────────────────────────────────────────

/// Build availability given a pre-computed `shared_host` (base rootfs,
/// maintenance, etc) and filling in `has_golden` per-claw.
fn project_with_shared_host(
    name: &str,
    state: &AppState,
    shared_host: &HostProjection,
) -> ClawAvailability {
    if !manifest::is_known(name) {
        return ClawAvailability {
            name: name.to_string(),
            install: InstallProjection::default_not_installed(),
            host: shared_host.clone(),
            overall: OverallState::Unknown,
            reasons: vec![UnavailReason::UnknownType],
            degradations: vec![],
        };
    }

    let install = project_install(state, name);
    let host = with_golden_for_claw(shared_host.clone(), state, name);
    let (overall, reasons) = compute_overall(&install, &host);
    let degradations = compute_degradations(&host);

    ClawAvailability {
        name: name.to_string(),
        install,
        host,
        overall,
        reasons,
        degradations,
    }
}

/// Read the install projection from `ClawStore` (and `jobs.result` for
/// progress when install is in progress).
fn project_install(state: &AppState, name: &str) -> InstallProjection {
    let store_state = state.claw_store.get_state(name);
    let status = match store_state.as_ref().map(|s| s.status) {
        None | Some(ClawStatus::NotInstalled) => InstallStatus::NotInstalled,
        Some(ClawStatus::Installing) => InstallStatus::Installing,
        Some(ClawStatus::Ready) => InstallStatus::Succeeded,
        Some(ClawStatus::Failed) => InstallStatus::Failed,
        Some(ClawStatus::Uninstalling) => InstallStatus::Uninstalling,
    };

    // Only consult the jobs store when install is actually in progress.
    // During other states the progress field is None by contract.
    let progress = if matches!(status, InstallStatus::Installing) {
        store_state
            .as_ref()
            .and_then(|s| s.job_id.as_ref())
            .and_then(|jid| {
                // jobs.get returns Err(NotFound) for missing jobs, not
                // Ok(None). Convert to Option to chain cleanly.
                state.jobs.get(jid).ok()
            })
            .and_then(|job| job.result)
            .and_then(|raw| serde_json::from_str::<InstallProgress>(&raw).ok())
    } else {
        None
    };

    InstallProjection {
        status,
        progress,
        installed_at: store_state.as_ref().and_then(|s| s.installed_at.clone()),
        error: store_state.as_ref().and_then(|s| s.error.clone()),
        job_id: store_state.as_ref().and_then(|s| s.job_id.clone()),
    }
}

// ─── Host probes ─────────────────────────────────────────────────────────────

/// Probe the shared host state (base rootfs + maintenance).
///
/// Does NOT include per-claw golden presence — that's filled in later
/// by `with_golden_for_claw`. Split so list endpoints can share the
/// expensive probes across all claws.
fn probe_shared_host(state: &AppState) -> HostProjection {
    let env = &state.vm_runner.env;
    let has_base_rootfs =
        env.base_rootfs.exists() || macos_linux_base_disk_exists() || macos_base_snapshot_exists();

    let maintenance_status = maintenance::read_status(&state.locks_dir);
    let maintenance_blocked = maintenance::creates_blocked(&state.locks_dir);

    HostProjection {
        // `cold_path_ready` and `has_golden` are filled in per-claw by
        // `with_golden_for_claw`. We initialize conservatively here.
        cold_path_ready: has_base_rootfs,
        has_golden: false,
        has_base_rootfs,
        maintenance_blocked,
        maintenance_retry_after_secs: if maintenance_blocked {
            Some(u64::from(maintenance_status.retry_after_secs))
        } else {
            None
        },
    }
}

/// On macOS the Linux guest base lives at
/// `$THEYOS_VM_ASSETS_DIR/linux-base/disk.img` (default
/// `~/Library/Application Support/theyos/vms/linux-base/disk.img`). The
/// Firecracker `base_rootfs` env path doesn't exist on a Mac host — using only
/// `env.base_rootfs.exists()` makes `cold_path_ready` permanently false even
/// after `init_macos_guest` finishes, which blocks every Linux claw create.
fn macos_linux_base_disk_exists() -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    let assets = std::env::var("THEYOS_VM_ASSETS_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/Library/Application Support/theyos/vms")
    });
    std::path::Path::new(&assets)
        .join("linux-base")
        .join("disk.img")
        .exists()
}

/// On macOS, native macOS claw creation uses the initialized
/// `macos-base/base.vzsnapshot` instead of a Linux rootfs. Availability is
/// currently claw-scoped rather than guest-OS-scoped, so the Mac base snapshot
/// must also satisfy the cold-path probe on Mac hosts.
fn macos_base_snapshot_exists() -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    let assets = std::env::var("THEYOS_VM_ASSETS_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/Library/Application Support/theyos/vms")
    });
    std::path::Path::new(&assets)
        .join("macos-base")
        .join("base.vzsnapshot")
        .exists()
}

/// Fill in `has_golden` + recompute `cold_path_ready` for a specific claw.
fn with_golden_for_claw(mut host: HostProjection, state: &AppState, claw: &str) -> HostProjection {
    host.has_golden = has_golden_for(state, claw);
    host.cold_path_ready = host.has_golden || host.has_base_rootfs;
    host
}

/// Check if a golden rootfs exists for a specific claw.
///
/// Looks in both the versioned DAG location
/// (`{home}/firecracker/assets/goldens/{claw}/current`) and the legacy flat
/// fallback (`{home}/firecracker/assets/ubuntu-24.04-{claw}.ext4`). Mirrors
/// the resolution order in `vmrunner-rs/src/lib.rs:1207-1229`.
fn has_golden_for(state: &AppState, claw: &str) -> bool {
    let env = &state.vm_runner.env;
    let assets_dir = env.home.join("firecracker/assets");
    if core_rs::artifact_meta::golden_current_rootfs(&assets_dir, claw).is_some() {
        return true;
    }
    // Legacy flat path
    env.home
        .join(format!("firecracker/assets/ubuntu-24.04-{claw}.ext4"))
        .exists()
}

fn compute_degradations(host: &HostProjection) -> Vec<Degradation> {
    let mut degs = vec![];
    if host.has_golden && !host.has_base_rootfs {
        degs.push(Degradation::BaseRootfsMissingButGoldenPresent);
    }
    degs
}
