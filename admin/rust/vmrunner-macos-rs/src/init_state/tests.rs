#![cfg(test)]

use super::*;
use tempfile::TempDir;

#[test]
fn test_default_state_is_empty() {
    let dir = TempDir::new().unwrap();
    let state = read_state(dir.path()).unwrap();
    assert!(state.phase.is_none());
    assert_eq!(state.ipsw_bytes_downloaded, 0);
    assert!(!is_complete(dir.path()));
}

#[test]
fn test_write_read_roundtrip() {
    let dir = TempDir::new().unwrap();
    let mut state = InitState::default();
    state.phase = Some(InitPhase::DownloadIpsw);
    state.ipsw_bytes_downloaded = 6_655_000_000;
    state.macos_version = Some("15.3.1".to_string());
    state.host_macos_version = Some("26.4".to_string());
    state.host_macos_build = Some("25E246".to_string());
    state.ipsw_build = Some("24D70".to_string());
    state.ipsw_source = Some("local-auto:/tmp/UniversalMac_15.3.1_24D70_Restore.ipsw".to_string());

    write_state(dir.path(), &state).unwrap();
    let loaded = read_state(dir.path()).unwrap();

    assert_eq!(loaded.phase, Some(InitPhase::DownloadIpsw));
    assert_eq!(loaded.ipsw_bytes_downloaded, 6_655_000_000);
    assert_eq!(loaded.macos_version, Some("15.3.1".to_string()));
    assert_eq!(loaded.host_macos_version, Some("26.4".to_string()));
    assert_eq!(loaded.host_macos_build, Some("25E246".to_string()));
    assert_eq!(loaded.ipsw_build, Some("24D70".to_string()));
    assert_eq!(
        loaded.ipsw_source,
        Some("local-auto:/tmp/UniversalMac_15.3.1_24D70_Restore.ipsw".to_string())
    );
}

#[test]
fn test_complete_phase_detected() {
    let dir = TempDir::new().unwrap();
    let mut state = InitState::default();
    state.phase = Some(InitPhase::Complete);
    write_state(dir.path(), &state).unwrap();
    assert!(is_complete(dir.path()));
}

#[test]
fn test_incomplete_phases_not_complete() {
    let dir = TempDir::new().unwrap();
    for phase in [
        InitPhase::DownloadIpsw,
        InitPhase::CreateDisk,
        InitPhase::InstallMacOS,
        InitPhase::Provision,
        InitPhase::CreateSnapshot,
    ] {
        let mut state = InitState::default();
        state.phase = Some(phase);
        write_state(dir.path(), &state).unwrap();
        assert!(!is_complete(dir.path()));
    }
}

#[test]
fn test_atomic_write_no_tmp_leftover() {
    let dir = TempDir::new().unwrap();
    write_state(dir.path(), &InitState::default()).unwrap();
    assert!(dir.path().join(INIT_STATE_FILE).exists());
    assert!(!dir.path().join(".init-state.json.tmp").exists());
}

#[test]
fn test_overwrite_preserves_latest() {
    let dir = TempDir::new().unwrap();
    let mut state = InitState::default();
    state.phase = Some(InitPhase::DownloadIpsw);
    write_state(dir.path(), &state).unwrap();

    state.phase = Some(InitPhase::CreateDisk);
    write_state(dir.path(), &state).unwrap();

    assert_eq!(
        read_state(dir.path()).unwrap().phase,
        Some(InitPhase::CreateDisk)
    );
}

#[test]
fn test_all_six_phases_sequential() {
    let dir = TempDir::new().unwrap();
    let phases = [
        InitPhase::DownloadIpsw,
        InitPhase::CreateDisk,
        InitPhase::InstallMacOS,
        InitPhase::Provision,
        InitPhase::CreateSnapshot,
        InitPhase::Complete,
    ];
    for (i, phase) in phases.iter().enumerate() {
        let mut state = InitState::default();
        state.phase = Some(phase.clone());
        write_state(dir.path(), &state).unwrap();
        let loaded = read_state(dir.path()).unwrap();
        assert_eq!(loaded.phase, Some(phase.clone()), "phase {i} mismatch");
    }
    // After the loop, phase is Complete
    assert!(is_complete(dir.path()));
}

#[test]
fn test_resume_from_each_phase() {
    // Simulate resuming from each phase: write the phase then read it back
    let dir = TempDir::new().unwrap();
    let resume_phases = [
        (InitPhase::DownloadIpsw, false),
        (InitPhase::CreateDisk, false),
        (InitPhase::InstallMacOS, false),
        (InitPhase::Provision, false),
        (InitPhase::CreateSnapshot, false),
        (InitPhase::Complete, true),
    ];
    for (phase, expect_complete) in resume_phases {
        let mut state = InitState::default();
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
        (InitPhase::DownloadIpsw, "\"download_ipsw\""),
        (InitPhase::CreateDisk, "\"create_disk\""),
        (InitPhase::InstallMacOS, "\"install_mac_o_s\""),
        (InitPhase::Provision, "\"provision\""),
        (InitPhase::CreateSnapshot, "\"create_snapshot\""),
        (InitPhase::Complete, "\"complete\""),
    ];
    for (phase, expected_json) in phases {
        let s = serde_json::to_string(&phase).unwrap();
        assert_eq!(s, expected_json, "unexpected JSON for {phase:?}");
        let rt: InitPhase = serde_json::from_str(&s).unwrap();
        assert_eq!(rt, phase);
    }
}

// ── v2 tests ─────────────────────────────────────────────────────────────

#[test]
fn test_v1_migration_complete() {
    let dir = TempDir::new().unwrap();
    // Write v1-style JSON (no version, no status)
    let v1_json = r#"{"phase": "complete", "macos_version": "15.3.1"}"#;
    std::fs::write(dir.path().join(INIT_STATE_FILE), v1_json).unwrap();

    let state = read_state(dir.path()).unwrap();
    assert_eq!(state.version, INIT_STATE_VERSION);
    assert_eq!(state.status, PhaseStatus::Done);
    assert_eq!(state.phase, Some(InitPhase::Complete));
}

#[test]
fn test_v1_migration_in_progress() {
    let dir = TempDir::new().unwrap();
    let v1_json = r#"{"phase": "provision"}"#;
    std::fs::write(dir.path().join(INIT_STATE_FILE), v1_json).unwrap();

    let state = read_state(dir.path()).unwrap();
    assert_eq!(state.version, INIT_STATE_VERSION);
    assert_eq!(state.status, PhaseStatus::Pending);
    assert_eq!(state.phase, Some(InitPhase::Provision));
}

#[test]
fn test_begin_complete_phase() {
    let mut state = InitState::default();
    state.begin_phase(InitPhase::DownloadIpsw);
    assert_eq!(state.phase, Some(InitPhase::DownloadIpsw));
    assert_eq!(state.status, PhaseStatus::InProgress);
    assert!(state.phase_history.contains_key("download_ipsw"));
    assert_eq!(state.phase_history["download_ipsw"].attempts, 1);

    state.complete_phase();
    assert_eq!(state.status, PhaseStatus::Done);
    assert_eq!(
        state.phase_history["download_ipsw"].status,
        PhaseStatus::Done
    );
    assert!(state.phase_history["download_ipsw"].finished_at.is_some());
}

#[test]
fn test_fail_phase_records_error() {
    let mut state = InitState::default();
    state.begin_phase(InitPhase::InstallMacOS);
    state.fail_phase("disk full");

    assert_eq!(state.status, PhaseStatus::Failed);
    let record = &state.phase_history["install_mac_o_s"];
    assert_eq!(record.status, PhaseStatus::Failed);
    assert_eq!(record.error.as_deref(), Some("disk full"));
}

#[test]
fn test_sub_phase_tracking() {
    let mut state = InitState::default();
    state.begin_phase(InitPhase::CreateSnapshot);

    assert!(!state.sub_phase_completed(&SnapshotSubPhase::Boot));

    state.begin_sub_phase(SnapshotSubPhase::Boot);
    assert_eq!(state.sub_phase, Some(SnapshotSubPhase::Boot));

    state.complete_sub_phase(SnapshotSubPhase::Boot);
    assert!(state.sub_phase_completed(&SnapshotSubPhase::Boot));
    assert!(state.sub_phase.is_none());
}

#[test]
fn test_degraded_state() {
    let mut state = InitState::default();
    state.begin_phase(InitPhase::CreateSnapshot);
    state.mark_degraded();

    let record = &state.phase_history["create_snapshot"];
    assert!(record.degraded);
}

#[test]
fn test_is_complete_and_healthy() {
    let dir = TempDir::new().unwrap();

    // Healthy complete
    let mut state = InitState::default();
    state.begin_phase(InitPhase::Complete);
    state.complete_phase();
    write_state(dir.path(), &state).unwrap();
    assert!(is_complete_and_healthy(dir.path()));

    // Degraded complete
    state.begin_phase(InitPhase::CreateSnapshot);
    state.mark_degraded();
    state.complete_phase();
    state.begin_phase(InitPhase::Complete);
    state.complete_phase();
    write_state(dir.path(), &state).unwrap();
    assert!(is_complete(dir.path()));
    assert!(!is_complete_and_healthy(dir.path()));
}

#[test]
fn test_phase_history_btreemap_deterministic() {
    let mut state = InitState::default();
    state.begin_phase(InitPhase::CreateSnapshot);
    state.complete_phase();
    state.begin_phase(InitPhase::DownloadIpsw);
    state.complete_phase();
    state.begin_phase(InitPhase::Provision);
    state.complete_phase();

    // BTreeMap keys are sorted alphabetically
    let keys: Vec<&String> = state.phase_history.keys().collect();
    assert_eq!(keys, &["create_snapshot", "download_ipsw", "provision"]);
}

#[test]
fn test_retry_increments_attempts() {
    let mut state = InitState::default();
    state.begin_phase(InitPhase::DownloadIpsw);
    assert_eq!(state.phase_history["download_ipsw"].attempts, 1);

    state.fail_phase("network error");
    state.begin_phase(InitPhase::DownloadIpsw);
    assert_eq!(state.phase_history["download_ipsw"].attempts, 2);
}

#[test]
fn test_v2_roundtrip_with_history() {
    let dir = TempDir::new().unwrap();
    let mut state = InitState::default();
    state.begin_phase(InitPhase::DownloadIpsw);
    state.complete_phase();
    state.begin_phase(InitPhase::CreateDisk);
    state.complete_phase();

    write_state(dir.path(), &state).unwrap();
    let loaded = read_state(dir.path()).unwrap();

    assert_eq!(loaded.version, INIT_STATE_VERSION);
    assert_eq!(loaded.phase_history.len(), 2);
    assert!(loaded.phase_history.contains_key("download_ipsw"));
    assert!(loaded.phase_history.contains_key("create_disk"));
}
