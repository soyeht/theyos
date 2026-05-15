//! `LinuxInitState` and `LinuxInitPhase` — resumable Linux guest base image initialization.
//!
//! Mirrors the macOS `init_state.rs` pattern but with Linux-specific phases:
//! download Ubuntu cloud image → convert → first boot (populate NVRAM) → validate SSH → save base.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::VZError;

/// Phase of the Linux guest base image initialization.
///
/// Phases run in order. Completion of each phase is recorded in
/// `init-state.json` before proceeding to the next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxInitPhase {
    /// Phase 1: Download the Ubuntu 24.04 ARM64 cloud image (~600 MB qcow2).
    DownloadImage,
    /// Phase 2: Convert qcow2 to raw, resize to 20 GB, fix GPT backup header.
    ConvertImage,
    /// Phase 3: First boot with blank NVRAM + cloud-init (GRUB populates NVRAM).
    FirstBoot,
    /// Phase 4: SSH into the booted VM and verify health.
    ValidateSsh,
    /// Phase 5: Shut down, save disk + NVRAM, create claw symlinks.
    SaveBase,
    /// Phase 6: All phases complete — base image is ready for cloning.
    Complete,
}

/// Persistent state for the Linux guest base image init process.
///
/// Serialized as JSON at `$THEYOS_VM_ASSETS_DIR/linux-base/init-state.json`.
/// All fields use `#[serde(default)]` so the file can be read after adding new fields.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LinuxInitState {
    /// Last completed phase (None = not started).
    pub phase: Option<LinuxInitPhase>,

    /// Ubuntu cloud image download URL.
    #[serde(default)]
    pub image_url: Option<String>,

    /// Expected total image size in bytes — for progress display.
    #[serde(default)]
    pub image_total_bytes: Option<u64>,

    /// Bytes already downloaded — used for HTTP Range-request resume.
    #[serde(default)]
    pub image_bytes_downloaded: u64,

    /// Ubuntu version string (e.g. "24.04") — populated after download.
    #[serde(default)]
    pub ubuntu_version: Option<String>,

    /// Disk size in GB after conversion + resize.
    #[serde(default)]
    pub disk_size_gb: Option<u64>,
}

/// File name for the init-state JSON within the base dir.
pub const LINUX_INIT_STATE_FILE: &str = "init-state.json";

/// Read the current `LinuxInitState` from `base_dir/init-state.json`.
///
/// Returns a default (empty) state if the file does not exist yet.
///
/// # Errors
///
/// Returns `VZError::Internal` if the file exists but cannot be parsed.
pub fn read_state(base_dir: &Path) -> Result<LinuxInitState, VZError> {
    let path = base_dir.join(LINUX_INIT_STATE_FILE);
    if !path.exists() {
        return Ok(LinuxInitState::default());
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| VZError::Internal(format!("read linux init-state.json: {e}")))?;
    serde_json::from_str(&data)
        .map_err(|e| VZError::Internal(format!("parse linux init-state.json: {e}")))
}

/// Write `state` to `base_dir/init-state.json` atomically (write-then-rename).
///
/// # Errors
///
/// Returns `VZError::Internal` if serialization or file I/O fails.
pub fn write_state(base_dir: &Path, state: &LinuxInitState) -> Result<(), VZError> {
    let path = base_dir.join(LINUX_INIT_STATE_FILE);
    let tmp = base_dir.join(".init-state.json.tmp");
    let data = serde_json::to_string_pretty(state)
        .map_err(|e| VZError::Internal(format!("serialize linux init-state: {e}")))?;
    std::fs::write(&tmp, data)
        .map_err(|e| VZError::Internal(format!("write .init-state.json.tmp: {e}")))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| VZError::Internal(format!("rename linux init-state.json: {e}")))?;
    Ok(())
}

/// Return `true` if the Linux base image initialization completed successfully.
#[must_use]
pub fn is_complete(base_dir: &Path) -> bool {
    matches!(
        read_state(base_dir),
        Ok(LinuxInitState {
            phase: Some(LinuxInitPhase::Complete),
            ..
        })
    )
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_state_is_empty() {
        let dir = TempDir::new().unwrap();
        let state = read_state(dir.path()).unwrap();
        assert!(state.phase.is_none());
        assert_eq!(state.image_bytes_downloaded, 0);
        assert!(!is_complete(dir.path()));
    }

    #[test]
    fn test_write_read_roundtrip() {
        let dir = TempDir::new().unwrap();
        let mut state = LinuxInitState::default();
        state.phase = Some(LinuxInitPhase::DownloadImage);
        state.image_bytes_downloaded = 300_000_000;
        state.ubuntu_version = Some("24.04".to_string());
        state.image_url = Some("https://cloud-images.ubuntu.com/test.img".to_string());

        write_state(dir.path(), &state).unwrap();
        let loaded = read_state(dir.path()).unwrap();

        assert_eq!(loaded.phase, Some(LinuxInitPhase::DownloadImage));
        assert_eq!(loaded.image_bytes_downloaded, 300_000_000);
        assert_eq!(loaded.ubuntu_version, Some("24.04".to_string()));
        assert_eq!(
            loaded.image_url,
            Some("https://cloud-images.ubuntu.com/test.img".to_string())
        );
    }

    #[test]
    fn test_complete_phase_detected() {
        let dir = TempDir::new().unwrap();
        let mut state = LinuxInitState::default();
        state.phase = Some(LinuxInitPhase::Complete);
        write_state(dir.path(), &state).unwrap();
        assert!(is_complete(dir.path()));
    }

    #[test]
    fn test_incomplete_phases_not_complete() {
        let dir = TempDir::new().unwrap();
        for phase in [
            LinuxInitPhase::DownloadImage,
            LinuxInitPhase::ConvertImage,
            LinuxInitPhase::FirstBoot,
            LinuxInitPhase::ValidateSsh,
            LinuxInitPhase::SaveBase,
        ] {
            let mut state = LinuxInitState::default();
            state.phase = Some(phase);
            write_state(dir.path(), &state).unwrap();
            assert!(!is_complete(dir.path()));
        }
    }

    #[test]
    fn test_atomic_write_no_tmp_leftover() {
        let dir = TempDir::new().unwrap();
        write_state(dir.path(), &LinuxInitState::default()).unwrap();
        assert!(dir.path().join(LINUX_INIT_STATE_FILE).exists());
        assert!(!dir.path().join(".init-state.json.tmp").exists());
    }

    #[test]
    fn test_overwrite_preserves_latest() {
        let dir = TempDir::new().unwrap();
        let mut state = LinuxInitState::default();
        state.phase = Some(LinuxInitPhase::DownloadImage);
        write_state(dir.path(), &state).unwrap();

        state.phase = Some(LinuxInitPhase::ConvertImage);
        write_state(dir.path(), &state).unwrap();

        assert_eq!(
            read_state(dir.path()).unwrap().phase,
            Some(LinuxInitPhase::ConvertImage)
        );
    }

    #[test]
    fn test_all_six_phases_sequential() {
        let dir = TempDir::new().unwrap();
        let phases = [
            LinuxInitPhase::DownloadImage,
            LinuxInitPhase::ConvertImage,
            LinuxInitPhase::FirstBoot,
            LinuxInitPhase::ValidateSsh,
            LinuxInitPhase::SaveBase,
            LinuxInitPhase::Complete,
        ];
        for (i, phase) in phases.iter().enumerate() {
            let mut state = LinuxInitState::default();
            state.phase = Some(phase.clone());
            write_state(dir.path(), &state).unwrap();
            let loaded = read_state(dir.path()).unwrap();
            assert_eq!(loaded.phase, Some(phase.clone()), "phase {i} mismatch");
        }
        assert!(is_complete(dir.path()));
    }

    #[test]
    fn test_resume_from_each_phase() {
        let dir = TempDir::new().unwrap();
        let resume_phases = [
            (LinuxInitPhase::DownloadImage, false),
            (LinuxInitPhase::ConvertImage, false),
            (LinuxInitPhase::FirstBoot, false),
            (LinuxInitPhase::ValidateSsh, false),
            (LinuxInitPhase::SaveBase, false),
            (LinuxInitPhase::Complete, true),
        ];
        for (phase, expect_complete) in resume_phases {
            let mut state = LinuxInitState::default();
            state.phase = Some(phase.clone());
            write_state(dir.path(), &state).unwrap();
            let loaded = read_state(dir.path()).unwrap();
            assert_eq!(loaded.phase.as_ref(), Some(&phase));
            assert_eq!(is_complete(dir.path()), expect_complete);
        }
    }

    #[test]
    fn test_json_serde_all_phases() {
        let phases = [
            (LinuxInitPhase::DownloadImage, "\"download_image\""),
            (LinuxInitPhase::ConvertImage, "\"convert_image\""),
            (LinuxInitPhase::FirstBoot, "\"first_boot\""),
            (LinuxInitPhase::ValidateSsh, "\"validate_ssh\""),
            (LinuxInitPhase::SaveBase, "\"save_base\""),
            (LinuxInitPhase::Complete, "\"complete\""),
        ];
        for (phase, expected_json) in phases {
            let s = serde_json::to_string(&phase).unwrap();
            assert_eq!(s, expected_json, "unexpected JSON for {phase:?}");
            let rt: LinuxInitPhase = serde_json::from_str(&s).unwrap();
            assert_eq!(rt, phase);
        }
    }

    #[test]
    fn test_backward_compat_missing_fields() {
        let dir = TempDir::new().unwrap();
        // Write a minimal JSON with only the phase field
        let minimal = r#"{"phase":"complete"}"#;
        std::fs::write(dir.path().join(LINUX_INIT_STATE_FILE), minimal).unwrap();
        let loaded = read_state(dir.path()).unwrap();
        assert_eq!(loaded.phase, Some(LinuxInitPhase::Complete));
        assert!(loaded.image_url.is_none());
        assert_eq!(loaded.image_bytes_downloaded, 0);
        assert!(loaded.disk_size_gb.is_none());
    }
}
