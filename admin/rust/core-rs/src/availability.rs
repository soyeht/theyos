//! Claw availability projection — single source of truth for "can a user create
//! an instance of this claw right now?".
//!
//! # Architecture
//!
//! The backend has three independent sources of truth about claws:
//!
//! 1. **Manifest** (`core_rs::manifest`) — which claws theyOS *knows about*.
//!    Compiled from `claws/manifest.yml` at build time. Static.
//!
//! 2. **`ClawStore`** (`claw_rs::ClawStore`) — which claws are *installed on
//!    this host*. Dynamic, persisted in `.run/installed_claws.json`. Mutated
//!    by the install worker as install progresses.
//!
//! 3. **Runtime host state** — golden rootfs presence, base rootfs presence,
//!    maintenance mode. Probed on demand from disk + maintenance lockfile.
//!
//! Before this module existed, each of these was consulted independently by
//! different handlers, causing split-brain: `GET /mobile/claws` listed from
//! (2) but `POST /mobile/instances` validated against a 4th source (Registry),
//! so claws could appear "ready" in the listing but be rejected as "unsupported
//! claw type" on create.
//!
//! This module defines a **derived projection** — pure types + `compute_overall`
//! that fuse the three sources into a single verdict the UI and gates can
//! agree on. The projection is never persisted; it's re-derived on every
//! request from the three underlying sources.
//!
//! # Non-goals
//!
//! - Warm pool state. Warm pool is an optimization, not a gate — if empty,
//!   the create path falls through to cold boot (see
//!   `vmrunner-rs/src/lib.rs:1207-1229`). Surfacing it here would require
//!   holding the executor mutex on every request, which we explicitly reject.
//!
//! - Persistence. The projection is ephemeral by design. Persisting would
//!   recreate the original split-brain problem under a new name.
//!
//! # Serialization
//!
//! All types are `Serialize + Deserialize` so the projection can be exposed
//! directly over the HTTP API. `OverallState` and `UnavailReason` are tagged
//! enums (`serde(tag = "...")`) so JSON consumers can match on the tag field.

use serde::{Deserialize, Serialize};

// ─── Top-level projection ────────────────────────────────────────────────────

/// Full availability projection for a single claw.
///
/// Built by `server-rs::availability::project_claw` from
/// manifest + `claw_store` + `vm_runner.env` + maintenance. Consumed by API
/// handlers and serialized to JSON in API responses.
///
/// **Not persisted.** Re-derived on every request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClawAvailability {
    /// Claw name (manifest key or user-supplied string for Unknown).
    pub name: String,

    /// Install state projection — derived from `ClawStore` + `jobs.result`.
    pub install: InstallProjection,

    /// Host capabilities projection — derived from filesystem + maintenance probes.
    pub host: HostProjection,

    /// Fused verdict for consumers that need a single decision.
    pub overall: OverallState,

    /// Structured reasons when `overall` is not `Creatable`. Empty otherwise.
    /// The API emits these in the `reasons` field of error responses.
    pub reasons: Vec<UnavailReason>,

    /// Non-blocking observations about degraded operation (e.g. slower
    /// cold path). Never affects `overall`.
    pub degradations: Vec<Degradation>,
}

// ─── Install projection ──────────────────────────────────────────────────────

/// Projected install state for a claw on this host.
///
/// Mapping from `claw_rs::ClawStatus` happens in `server-rs::availability::project_install`.
/// `ClawStatus::Ready` maps to `InstallStatus::Succeeded` here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallProjection {
    pub status: InstallStatus,
    /// Only present when `status == Installing`. Read from `jobs.result` of
    /// the install job (see `install_worker::run_install_claw_prebuilt`).
    pub progress: Option<InstallProgress>,
    /// ISO 8601 UTC timestamp of successful install (only present when
    /// `status == Succeeded`).
    pub installed_at: Option<String>,
    /// Last install error (only present when `status == Failed`).
    pub error: Option<String>,
    /// Install job ID (for correlation with the jobs-rs store).
    pub job_id: Option<String>,
}

impl InstallProjection {
    /// Construct a projection for a claw with no install history.
    #[must_use]
    pub fn default_not_installed() -> Self {
        Self {
            status: InstallStatus::NotInstalled,
            progress: None,
            installed_at: None,
            error: None,
            job_id: None,
        }
    }
}

/// Install state as seen by API consumers.
///
/// Separate from `claw_rs::ClawStatus` (the persisted event store) so the
/// public API contract can evolve independently of the persisted schema.
/// `#[serde(alias = "ready")]` on `Succeeded` is defensive: if the persisted
/// store ever bleeds `ClawStatus::Ready` into the API directly, deserialization
/// still works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallStatus {
    NotInstalled,
    Installing,
    #[serde(alias = "ready")]
    Succeeded,
    Failed,
    Uninstalling,
}

/// Fine-grained progress information for a claw install in progress.
///
/// Written by `install_worker` into `jobs.result` throttled to 1 Hz, read by
/// `project_install` when the claw's install status is `Installing`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallProgress {
    pub phase: InstallPhase,
    /// 0..=100
    pub percent: u8,
    pub bytes_downloaded: u64,
    pub bytes_total: u64,
    /// Wall-clock Unix epoch in milliseconds. Used for staleness detection
    /// on the client (e.g. "no update for 30s → show 'stalled'"). Wall clock
    /// is acceptable here because install is single-process (`install_worker`
    /// and server-rs run in the same tokio runtime).
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPhase {
    Downloading,
    Verifying,
    Finalizing,
}

// ─── Host projection ─────────────────────────────────────────────────────────

/// Projected host capabilities relevant to claw creation.
///
/// All fields are derived from cheap probes (filesystem stat, `HashSet` lookup,
/// flock read). No caching — re-derived on every request.
///
/// The lint against 4+ bools-in-a-struct is waived here because each bool
/// represents an **independent observation** about the host — they're not a
/// hidden state machine that should become an enum. A user of this type
/// routinely needs to read several of them at once (e.g. "is cold path ready
/// AND is maintenance off?"), which is exactly the case the lint documents
/// as legitimate. See `compute_overall` for how they fuse into a single verdict.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProjection {
    /// True if at least one cold-path source is available:
    /// either a golden rootfs for this claw, or the base rootfs.
    /// This is what `vmrunner` actually falls back to
    /// (see `vmrunner-rs/src/lib.rs:1207-1229`).
    pub cold_path_ready: bool,

    /// True if a golden rootfs exists for this specific claw.
    /// Implies fast cold-path; creates in ~15-20s instead of ~40s.
    pub has_golden: bool,

    /// True if the shared base rootfs (ubuntu-24.04-rootfs-v2.ext4) exists
    /// on the host. Falsy does not imply blocked create as long as
    /// `has_golden` is true.
    pub has_base_rootfs: bool,

    /// True if maintenance mode (artifact sync) is blocking new creates.
    pub maintenance_blocked: bool,

    /// Only present when `maintenance_blocked == true`. Suggested wait time
    /// in seconds; the handler emits this as a `Retry-After` HTTP header.
    pub maintenance_retry_after_secs: Option<u64>,
}

// ─── Overall state ───────────────────────────────────────────────────────────

/// Fused verdict for clients that want a single field to match on.
///
/// Tagged with `state` so JSON consumers can match on `overall.state == "creatable"`.
/// The variant-specific data lives alongside — `installing` has `percent`, `failed`
/// has `error`, and `reasons` on `ClawAvailability` carries the full detail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OverallState {
    /// Claw is installed and the host can create an instance right now.
    Creatable,
    /// Claw install is in progress.
    Installing { percent: u8 },
    /// Claw is known but not installed on this host. User action needed: install.
    NotInstalled,
    /// Last install attempt failed. User action needed: retry.
    Failed { error: String },
    /// Claw is installed but cannot be created right now (maintenance, missing
    /// rootfs, etc). Check `reasons` for specifics.
    Blocked,
    /// Name is not in the manifest. Typo or client bug.
    Unknown,
}

// ─── Unavailability reasons ──────────────────────────────────────────────────

/// Structured reason a claw is not `Creatable`.
///
/// API emits these in the `reasons` field of error responses when a create
/// is rejected. Consumers (iOS, frontend) can render user-facing messages
/// per reason type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UnavailReason {
    /// Name not present in the manifest.
    UnknownType,
    /// Claw is in the manifest but hasn't been installed on this host.
    NotInstalled,
    /// Claw is still downloading / verifying.
    InstallInProgress { percent: u8 },
    /// Claw install failed.
    InstallFailed { error: String },
    /// Neither a golden rootfs for this claw nor the base rootfs is available.
    /// This is the only artifact-related blocker — having either one is enough.
    NoColdPathAvailable,
    /// Maintenance mode is active; new creates are rejected with HTTP 503.
    MaintenanceMode { retry_after_secs: u64 },
}

// ─── Degradations (informational) ────────────────────────────────────────────

/// Non-blocking observations about degraded operation.
///
/// Never affects `overall`. Emitted so the UI can show a "host needs attention"
/// banner without blocking user actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Degradation {
    /// Golden rootfs exists for this claw, but the base rootfs is missing.
    /// Informational only — create continues to work via the golden path
    /// (see vmrunner-rs/src/lib.rs:1207-1229 for the fallback logic).
    BaseRootfsMissingButGoldenPresent,
    // NOTE: Degradation::InstallerPlanStale and Degradation::WarmPoolEmpty
    // are deferred until there's a real producer. Adding states without
    // producers is API noise. Warm pool surfacing is Step 6 (push-based).
}

// ─── Pure computation ────────────────────────────────────────────────────────

/// Derive `(OverallState, reasons)` from install + host projections.
///
/// This is the single decision function that fuses the three sources of
/// truth into a verdict. Pure — no I/O, no state, no clock. Trivially unit-testable.
///
/// # Priority ordering
///
/// Install state takes precedence over host state:
/// - Not installed / Installing / Failed → those are the verdict regardless
///   of whether the host could otherwise create this claw.
/// - Only when install is `Succeeded` do we consult host state.
///
/// Rationale: users need to act on install problems first. Telling someone
/// "maintenance mode is active" when they haven't even installed the claw
/// yet is noise.
#[must_use]
pub fn compute_overall(
    install: &InstallProjection,
    host: &HostProjection,
) -> (OverallState, Vec<UnavailReason>) {
    let mut reasons = Vec::new();
    let overall = match install.status {
        InstallStatus::NotInstalled | InstallStatus::Uninstalling => {
            reasons.push(UnavailReason::NotInstalled);
            OverallState::NotInstalled
        }
        InstallStatus::Installing => {
            let percent = install.progress.as_ref().map_or(0, |p| p.percent);
            reasons.push(UnavailReason::InstallInProgress { percent });
            OverallState::Installing { percent }
        }
        InstallStatus::Failed => {
            let err = install
                .error
                .clone()
                .unwrap_or_else(|| "unknown install failure".to_string());
            reasons.push(UnavailReason::InstallFailed { error: err.clone() });
            OverallState::Failed { error: err }
        }
        InstallStatus::Succeeded => {
            // Maintenance takes priority over cold-path checks — if the host
            // is in maintenance, we're not allocating resources regardless of
            // whether the rootfs is in place.
            if host.maintenance_blocked {
                reasons.push(UnavailReason::MaintenanceMode {
                    retry_after_secs: host.maintenance_retry_after_secs.unwrap_or(30),
                });
                OverallState::Blocked
            } else if !host.cold_path_ready {
                reasons.push(UnavailReason::NoColdPathAvailable);
                OverallState::Blocked
            } else {
                OverallState::Creatable
            }
        }
    };
    (overall, reasons)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
