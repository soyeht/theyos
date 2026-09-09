#![cfg(test)]

use super::*;

fn install_not_installed() -> InstallProjection {
    InstallProjection::default_not_installed()
}

fn install_succeeded() -> InstallProjection {
    InstallProjection {
        status: InstallStatus::Succeeded,
        progress: None,
        installed_at: Some("2026-04-11T00:00:00Z".to_string()),
        error: None,
        job_id: None,
    }
}

fn install_installing(percent: u8) -> InstallProjection {
    InstallProjection {
        status: InstallStatus::Installing,
        progress: Some(InstallProgress {
            phase: InstallPhase::Downloading,
            percent,
            bytes_downloaded: 0,
            bytes_total: 100,
            updated_at_ms: 0,
        }),
        installed_at: None,
        error: None,
        job_id: Some("job-1".to_string()),
    }
}

fn install_failed(msg: &str) -> InstallProjection {
    InstallProjection {
        status: InstallStatus::Failed,
        progress: None,
        installed_at: None,
        error: Some(msg.to_string()),
        job_id: None,
    }
}

fn host_ready() -> HostProjection {
    HostProjection {
        cold_path_ready: true,
        has_golden: true,
        has_base_rootfs: true,
        maintenance_blocked: false,
        maintenance_retry_after_secs: None,
    }
}

fn host_golden_only() -> HostProjection {
    HostProjection {
        cold_path_ready: true,
        has_golden: true,
        has_base_rootfs: false,
        maintenance_blocked: false,
        maintenance_retry_after_secs: None,
    }
}

fn host_base_only() -> HostProjection {
    HostProjection {
        cold_path_ready: true,
        has_golden: false,
        has_base_rootfs: true,
        maintenance_blocked: false,
        maintenance_retry_after_secs: None,
    }
}

fn host_no_rootfs() -> HostProjection {
    HostProjection {
        cold_path_ready: false,
        has_golden: false,
        has_base_rootfs: false,
        maintenance_blocked: false,
        maintenance_retry_after_secs: None,
    }
}

fn host_maintenance(retry: u64) -> HostProjection {
    HostProjection {
        cold_path_ready: true,
        has_golden: true,
        has_base_rootfs: true,
        maintenance_blocked: true,
        maintenance_retry_after_secs: Some(retry),
    }
}

// ─── Happy path ──────────────────────────────────────────────────────

#[test]
fn creatable_when_succeeded_and_host_ready() {
    let (overall, reasons) = compute_overall(&install_succeeded(), &host_ready());
    assert_eq!(overall, OverallState::Creatable);
    assert!(reasons.is_empty());
}

#[test]
fn creatable_with_golden_only() {
    let (overall, reasons) = compute_overall(&install_succeeded(), &host_golden_only());
    assert_eq!(overall, OverallState::Creatable);
    assert!(reasons.is_empty());
}

#[test]
fn creatable_with_base_rootfs_only() {
    // Cold path from base rootfs — slower but works.
    let (overall, reasons) = compute_overall(&install_succeeded(), &host_base_only());
    assert_eq!(overall, OverallState::Creatable);
    assert!(reasons.is_empty());
}

// ─── Install state has priority ──────────────────────────────────────

#[test]
fn not_installed_when_store_empty() {
    let (overall, reasons) = compute_overall(&install_not_installed(), &host_ready());
    assert_eq!(overall, OverallState::NotInstalled);
    assert_eq!(reasons.len(), 1);
    assert!(matches!(reasons[0], UnavailReason::NotInstalled));
}

#[test]
fn installing_carries_percent() {
    let (overall, reasons) = compute_overall(&install_installing(42), &host_ready());
    assert_eq!(overall, OverallState::Installing { percent: 42 });
    assert_eq!(reasons.len(), 1);
    assert!(matches!(
        reasons[0],
        UnavailReason::InstallInProgress { percent: 42 }
    ));
}

#[test]
fn installing_with_no_progress_reports_zero_percent() {
    let install = InstallProjection {
        status: InstallStatus::Installing,
        progress: None,
        installed_at: None,
        error: None,
        job_id: Some("job-1".to_string()),
    };
    let (overall, _) = compute_overall(&install, &host_ready());
    assert_eq!(overall, OverallState::Installing { percent: 0 });
}

#[test]
fn failed_carries_error_message() {
    let (overall, reasons) = compute_overall(&install_failed("artifact 404"), &host_ready());
    match overall {
        OverallState::Failed { ref error } => assert_eq!(error, "artifact 404"),
        _ => panic!("expected Failed"),
    }
    assert_eq!(reasons.len(), 1);
    match &reasons[0] {
        UnavailReason::InstallFailed { error } => assert_eq!(error, "artifact 404"),
        _ => panic!("expected InstallFailed"),
    }
}

#[test]
fn failed_without_error_uses_placeholder() {
    let install = InstallProjection {
        status: InstallStatus::Failed,
        progress: None,
        installed_at: None,
        error: None,
        job_id: None,
    };
    let (overall, _) = compute_overall(&install, &host_ready());
    match overall {
        OverallState::Failed { ref error } => assert_eq!(error, "unknown install failure"),
        _ => panic!("expected Failed with placeholder"),
    }
}

#[test]
fn uninstalling_behaves_as_not_installed() {
    let install = InstallProjection {
        status: InstallStatus::Uninstalling,
        progress: None,
        installed_at: None,
        error: None,
        job_id: None,
    };
    let (overall, reasons) = compute_overall(&install, &host_ready());
    assert_eq!(overall, OverallState::NotInstalled);
    assert!(matches!(reasons[0], UnavailReason::NotInstalled));
}

// ─── Blocked by host state ───────────────────────────────────────────

#[test]
fn blocked_when_no_cold_path_available() {
    let (overall, reasons) = compute_overall(&install_succeeded(), &host_no_rootfs());
    assert_eq!(overall, OverallState::Blocked);
    assert_eq!(reasons.len(), 1);
    assert!(matches!(reasons[0], UnavailReason::NoColdPathAvailable));
}

#[test]
fn blocked_under_maintenance() {
    let (overall, reasons) = compute_overall(&install_succeeded(), &host_maintenance(45));
    assert_eq!(overall, OverallState::Blocked);
    assert_eq!(reasons.len(), 1);
    assert!(matches!(
        reasons[0],
        UnavailReason::MaintenanceMode {
            retry_after_secs: 45
        }
    ));
}

#[test]
fn maintenance_has_priority_over_no_cold_path() {
    // If host is in maintenance AND has no rootfs, surface maintenance
    // (user can't do anything about rootfs during a sync).
    let mut host = host_no_rootfs();
    host.maintenance_blocked = true;
    host.maintenance_retry_after_secs = Some(30);
    let (overall, reasons) = compute_overall(&install_succeeded(), &host);
    assert_eq!(overall, OverallState::Blocked);
    assert!(matches!(
        reasons[0],
        UnavailReason::MaintenanceMode {
            retry_after_secs: 30
        }
    ));
}

#[test]
fn install_state_wins_over_maintenance() {
    // Telling the user "maintenance" when they haven't even installed
    // the claw is noise. NotInstalled must take precedence.
    let (overall, reasons) = compute_overall(&install_not_installed(), &host_maintenance(30));
    assert_eq!(overall, OverallState::NotInstalled);
    assert!(matches!(reasons[0], UnavailReason::NotInstalled));
}

#[test]
fn install_state_wins_over_no_cold_path() {
    let (overall, reasons) = compute_overall(&install_not_installed(), &host_no_rootfs());
    assert_eq!(overall, OverallState::NotInstalled);
    assert!(matches!(reasons[0], UnavailReason::NotInstalled));
}

// ─── Default / helper sanity checks ──────────────────────────────────

#[test]
fn default_not_installed_helper() {
    let p = InstallProjection::default_not_installed();
    assert_eq!(p.status, InstallStatus::NotInstalled);
    assert!(p.progress.is_none());
    assert!(p.installed_at.is_none());
    assert!(p.error.is_none());
    assert!(p.job_id.is_none());
}

// ─── Serde shape assertions (the public API contract) ───────────────

#[test]
fn install_status_serializes_as_snake_case() {
    let json = serde_json::to_string(&InstallStatus::Succeeded).unwrap();
    assert_eq!(json, "\"succeeded\"");
}

#[test]
fn install_status_accepts_ready_alias_on_deserialize() {
    // Defensive: if anyone ever serializes ClawStatus::Ready into the
    // wire format, we still accept it.
    let s: InstallStatus = serde_json::from_str("\"ready\"").unwrap();
    assert_eq!(s, InstallStatus::Succeeded);
}

#[test]
fn overall_state_is_tagged() {
    let state = OverallState::Installing { percent: 25 };
    let v = serde_json::to_value(&state).unwrap();
    assert_eq!(v["state"], "installing");
    assert_eq!(v["percent"], 25);
}

#[test]
fn unavail_reason_is_tagged() {
    let r = UnavailReason::MaintenanceMode {
        retry_after_secs: 60,
    };
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["type"], "maintenance_mode");
    assert_eq!(v["retry_after_secs"], 60);
}

#[test]
fn unknown_type_reason_serializes() {
    let v = serde_json::to_value(UnavailReason::UnknownType).unwrap();
    assert_eq!(v["type"], "unknown_type");
}

#[test]
fn no_cold_path_reason_serializes() {
    let v = serde_json::to_value(UnavailReason::NoColdPathAvailable).unwrap();
    assert_eq!(v["type"], "no_cold_path_available");
}
