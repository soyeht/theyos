//! `InitState` and `InitPhase` — resumable macOS guest base image initialization.
//!
//! Decision 8 from research.md: 6-phase init with JSON phase file for resume.
//! Re-running `init-macos-guest` after any failure resumes from the last completed phase.
//!
//! ## State model (v2)
//!
//! - `phase`: last top-level phase completed (or currently executing).
//! - `status`: current status of the init process (`pending`/`in_progress`/`done`/`failed`).
//! - `sub_phase`: checkpoint within `CreateSnapshot` for granular resume.
//! - `phase_history`: per-phase audit trail with timing, attempts, and errors.
//!
//! v1 files (without `version` field) are migrated transparently on read.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use crate::VZError;

/// Current schema version. v1 files have `version: 0` (default).
const INIT_STATE_VERSION: u32 = 2;

/// Phase of the macOS guest base image initialization.
///
/// Phases run in order. Completion of each phase is recorded in
/// `init-state.json` before proceeding to the next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InitPhase {
    /// Phase 1: Download the macOS IPSW from Apple CDN (resumable via HTTP Range).
    DownloadIpsw,
    /// Phase 2: Create the 64 GB raw sparse disk image.
    CreateDisk,
    /// Phase 3: Run `VZMacOSInstaller` to install macOS (~20 min).
    InstallMacOS,
    /// Phase 4: Privileged APFS injection (provision-inject helper with root:wheel ownership).
    Provision,
    /// Phase 5: Single-boot VM, verify SSH, provision software, save VZ snapshot.
    CreateSnapshot,
    /// Phase 6: All phases complete — base image is ready for cloning.
    Complete,
}

/// Status of a phase or the overall init process.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    /// Phase is about to start.
    #[default]
    Pending,
    /// Phase is currently executing.
    InProgress,
    /// Phase completed successfully.
    Done,
    /// Phase failed (error stored in `PhaseRecord`).
    Failed,
}

/// Sub-phases within `CreateSnapshot` for granular resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSubPhase {
    /// Boot macOS VM.
    Boot,
    /// DHCP lease acquired.
    DhcpAcquired,
    /// SSH is reachable.
    SshReady,
    /// Base software provisioned (Homebrew, tools — best-effort).
    BaseSoftware,
    /// VM paused and .vzsnapshot saved.
    SnapshotSaved,
}

/// Per-phase audit record with timing and error tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseRecord {
    pub status: PhaseStatus,
    /// Unix timestamp (seconds) when this phase attempt started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    /// Unix timestamp (seconds) when this phase attempt finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
    /// Number of times this phase has been attempted.
    #[serde(default)]
    pub attempts: u32,
    /// Error message from the last failed attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Sub-phases completed within `CreateSnapshot`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed_sub_phases: Vec<SnapshotSubPhase>,
    /// Whether optional steps (e.g. base software) failed.
    /// `Complete + degraded=true` means core is OK but optional tooling is missing.
    #[serde(default)]
    pub degraded: bool,
}

/// Persistent state for the macOS guest base image init process.
///
/// Serialized as JSON at `$THEYOS_VM_ASSETS_DIR/macos-base/init-state.json`.
/// All fields use `#[serde(default)]` so the file can be read after adding new fields.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InitState {
    /// Schema version (0 = v1 legacy, 2 = current).
    #[serde(default)]
    pub version: u32,

    /// Current or last completed top-level phase.
    pub phase: Option<InitPhase>,

    /// Status of the current phase / overall init.
    #[serde(default)]
    pub status: PhaseStatus,

    /// Current sub-phase checkpoint within `CreateSnapshot`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_phase: Option<SnapshotSubPhase>,

    /// Per-phase audit trail. `BTreeMap` for deterministic JSON key ordering.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub phase_history: BTreeMap<String, PhaseRecord>,

    // ── Existing fields (unchanged from v1) ──────────────────────────────
    /// macOS version string (e.g. "15.3.1") — populated after IPSW URL fetch.
    #[serde(default)]
    pub macos_version: Option<String>,

    /// Host macOS version string (e.g. "26.4") at prepare time.
    #[serde(default)]
    pub host_macos_version: Option<String>,

    /// Host macOS build string (e.g. "25E246") at prepare time.
    #[serde(default)]
    pub host_macos_build: Option<String>,

    /// Build string extracted from the selected restore image, when known.
    #[serde(default)]
    pub ipsw_build: Option<String>,

    /// Human-readable source for the selected restore image.
    #[serde(default)]
    pub ipsw_source: Option<String>,

    /// Expected SHA256 hash of the IPSW file — populated after URL fetch.
    #[serde(default)]
    pub ipsw_sha256: Option<String>,

    /// Expected total IPSW size in bytes — for progress display.
    #[serde(default)]
    pub ipsw_total_bytes: Option<u64>,

    /// Bytes already downloaded — used for HTTP Range-request resume.
    #[serde(default)]
    pub ipsw_bytes_downloaded: u64,

    /// `source_label`s of restore-image candidates that have already been tried
    /// and failed (download/inspect/install). Persisted so a process restart
    /// doesn't keep retrying the same broken candidate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_ipsw_sources: Vec<String>,

    /// Base64-encoded `VZMacHardwareModel` data — populated after macOS install.
    #[serde(default)]
    pub hardware_model_data: Option<String>,

    /// Path to the base snapshot file (relative to the assets base dir).
    #[serde(default)]
    pub snapshot_path: Option<String>,

    /// Base64-encoded `VZMacMachineIdentifier` data (ECID) used when creating the base snapshot.
    ///
    /// All VMs cloned from the base image must use this ECID so that:
    /// 1. Warm pool VMs can restore from `base.vzsnapshot` (VZ 26 requires ECID matching).
    /// 2. Cold boot VMs use the same "machine identity" the disk was provisioned with,
    ///    preventing macOS from triggering Setup Assistant on every boot.
    #[serde(default)]
    pub machine_identifier_data_b64: Option<String>,

    /// CPU count used for the macOS install VM.
    ///
    /// This is the effective value after applying the selected restore image's
    /// `VZMacOSConfigurationRequirements`. Later base boots must not request
    /// fewer resources than the installer-required configuration.
    #[serde(default)]
    pub install_cpu_count: Option<u32>,

    /// Memory (MB) used for the macOS install VM.
    ///
    /// This is the effective value after applying the selected restore image's
    /// `VZMacOSConfigurationRequirements`.
    #[serde(default)]
    pub install_memory_mb: Option<u32>,

    /// CPU count used when the base snapshot was created.
    /// Warm pool and cold boot VMs must use the same value for snapshot restore.
    #[serde(default)]
    pub snapshot_cpus: Option<u32>,

    /// Memory (MB) used when the base snapshot was created.
    /// Warm pool and cold boot VMs must use the same value for snapshot restore.
    #[serde(default)]
    pub snapshot_memory_mb: Option<u32>,
}

// ── Phase transition helpers ─────────────────────────────────────────────────

impl InitState {
    /// Begin a new phase: sets phase, `status = InProgress`, records start time.
    pub fn begin_phase(&mut self, phase: InitPhase) {
        let key = phase_key(&phase);
        let record = self
            .phase_history
            .entry(key)
            .or_insert_with(|| PhaseRecord {
                status: PhaseStatus::Pending,
                started_at: None,
                finished_at: None,
                attempts: 0,
                error: None,
                completed_sub_phases: Vec::new(),
                degraded: false,
            });
        record.status = PhaseStatus::InProgress;
        record.started_at = Some(now_unix());
        record.finished_at = None;
        record.attempts += 1;
        record.error = None;

        self.phase = Some(phase);
        self.status = PhaseStatus::InProgress;
        self.sub_phase = None;
        self.version = INIT_STATE_VERSION;
    }

    /// Mark the current phase as successfully completed.
    pub fn complete_phase(&mut self) {
        self.status = PhaseStatus::Done;
        if let Some(ref phase) = self.phase {
            let key = phase_key(phase);
            if let Some(record) = self.phase_history.get_mut(&key) {
                record.status = PhaseStatus::Done;
                record.finished_at = Some(now_unix());
            }
        }
        self.sub_phase = None;
    }

    /// Mark the current phase as failed with an error message.
    pub fn fail_phase(&mut self, error: &str) {
        self.status = PhaseStatus::Failed;
        if let Some(ref phase) = self.phase {
            let key = phase_key(phase);
            if let Some(record) = self.phase_history.get_mut(&key) {
                record.status = PhaseStatus::Failed;
                record.finished_at = Some(now_unix());
                record.error = Some(error.to_string());
            }
        }
    }

    /// Begin a sub-phase within `CreateSnapshot`.
    pub fn begin_sub_phase(&mut self, sub: SnapshotSubPhase) {
        self.sub_phase = Some(sub);
    }

    /// Mark a sub-phase as completed.
    pub fn complete_sub_phase(&mut self, sub: SnapshotSubPhase) {
        let key = phase_key(&InitPhase::CreateSnapshot);
        if let Some(record) = self.phase_history.get_mut(&key) {
            if !record.completed_sub_phases.contains(&sub) {
                record.completed_sub_phases.push(sub);
            }
        }
        self.sub_phase = None;
    }

    /// Check if a sub-phase was already completed (for resume).
    #[must_use]
    pub fn sub_phase_completed(&self, sub: &SnapshotSubPhase) -> bool {
        let key = phase_key(&InitPhase::CreateSnapshot);
        self.phase_history
            .get(&key)
            .is_some_and(|r| r.completed_sub_phases.contains(sub))
    }

    /// Mark the current phase as degraded (optional steps failed but core is OK).
    pub fn mark_degraded(&mut self) {
        if let Some(ref phase) = self.phase {
            let key = phase_key(phase);
            if let Some(record) = self.phase_history.get_mut(&key) {
                record.degraded = true;
            }
        }
    }
}

/// Serialize a phase enum value to its JSON key string.
fn phase_key(phase: &InitPhase) -> String {
    serde_json::to_value(phase)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// Current Unix timestamp in seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── File I/O ─────────────────────────────────────────────────────────────────

/// File name for the init-state JSON within the base dir.
pub const INIT_STATE_FILE: &str = "init-state.json";

/// Read the current `InitState` from `base_dir/init-state.json`.
///
/// Returns a default (empty) state if the file does not exist yet.
/// Transparently migrates v1 files (no `version` field) to v2 in memory.
///
/// # Errors
///
/// Returns `VZError::Internal` if the file exists but cannot be parsed.
pub fn read_state(base_dir: &Path) -> Result<InitState, VZError> {
    let path = base_dir.join(INIT_STATE_FILE);
    if !path.exists() {
        return Ok(InitState::default());
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| VZError::Internal(format!("read init-state.json: {e}")))?;
    let mut state: InitState = serde_json::from_str(&data)
        .map_err(|e| VZError::Internal(format!("parse init-state.json: {e}")))?;

    // Migrate v1 → v2: old files have version == 0 (default).
    if state.version == 0 && state.phase.is_some() {
        state.version = INIT_STATE_VERSION;
        state.status = if state.phase == Some(InitPhase::Complete) {
            PhaseStatus::Done
        } else {
            PhaseStatus::Pending
        };
        // Don't write back — migration is applied in-memory on read.
        // The file will be updated on the next write_state call.
    }

    Ok(state)
}

/// Write `state` to `base_dir/init-state.json` atomically (write-then-rename).
///
/// # Errors
///
/// Returns `VZError::Internal` if serialization or file I/O fails.
pub fn write_state(base_dir: &Path, state: &InitState) -> Result<(), VZError> {
    let path = base_dir.join(INIT_STATE_FILE);
    let tmp = base_dir.join(".init-state.json.tmp");
    let data = serde_json::to_string_pretty(state)
        .map_err(|e| VZError::Internal(format!("serialize init-state: {e}")))?;
    std::fs::write(&tmp, data)
        .map_err(|e| VZError::Internal(format!("write .init-state.json.tmp: {e}")))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| VZError::Internal(format!("rename init-state.json: {e}")))?;
    Ok(())
}

/// Return `true` if the base image initialization completed successfully.
#[must_use]
pub fn is_complete(base_dir: &Path) -> bool {
    matches!(
        read_state(base_dir),
        Ok(InitState {
            phase: Some(InitPhase::Complete),
            ..
        })
    )
}

/// Return `true` if complete and no phases are degraded.
#[must_use]
pub fn is_complete_and_healthy(base_dir: &Path) -> bool {
    read_state(base_dir).ok().is_some_and(|s| {
        s.phase == Some(InitPhase::Complete) && !s.phase_history.values().any(|r| r.degraded)
    })
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests;
