#![cfg(test)]

use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

struct FakeTransport;
struct FakeTickleTransport;

impl HouseCreatedTransport for FakeTransport {
    fn topic(&self) -> &'static str {
        "com.soyeht.app"
    }

    fn send_push<'a>(
        &'a self,
        _token_hex: &'a str,
        _json_body: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), push::DispatchAttemptError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

impl ApnsTransport for FakeTickleTransport {
    fn topic(&self) -> &'static str {
        "com.soyeht.app"
    }

    fn send<'a>(
        &'a self,
        _push_token: &'a [u8],
        _body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), dispatcher::ApnsError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn push_transport_wiring_installs_when_loader_returns_transport() {
    let installed = Mutex::new(false);
    let status = install_house_created_push_transport_with(
        || Some(Arc::new(FakeTransport) as Arc<dyn HouseCreatedTransport>),
        |transport| {
            assert_eq!(transport.topic(), "com.soyeht.app");
            *installed.lock().unwrap() = true;
            Ok(())
        },
    );

    assert_eq!(status, PushTransportStartupStatus::Installed);
    assert!(*installed.lock().unwrap());
}

#[test]
fn push_transport_wiring_gracefully_skips_without_env_transport() {
    let status = install_house_created_push_transport_with(
        || None,
        |_| panic!("installer must not be called when loader returns None"),
    );

    assert_eq!(status, PushTransportStartupStatus::Skipped);
}

#[test]
fn push_transport_wiring_reports_already_installed() {
    let status = install_house_created_push_transport_with(
        || Some(Arc::new(FakeTransport) as Arc<dyn HouseCreatedTransport>),
        Err,
    );

    assert_eq!(status, PushTransportStartupStatus::AlreadyInstalled);
}

#[test]
fn tickle_transport_wiring_installs_when_loader_returns_transport() {
    let installed = Mutex::new(false);
    let status = install_owner_event_tickle_transport_with(
        || Some(Arc::new(FakeTickleTransport) as Arc<dyn ApnsTransport>),
        |transport| {
            assert_eq!(transport.topic(), "com.soyeht.app");
            *installed.lock().unwrap() = true;
            Ok(())
        },
    );

    assert_eq!(status, PushTransportStartupStatus::Installed);
    assert!(*installed.lock().unwrap());
}

#[test]
fn tickle_transport_wiring_gracefully_skips_without_env_transport() {
    let status = install_owner_event_tickle_transport_with(
        || None,
        |_| panic!("installer must not be called when loader returns None"),
    );

    assert_eq!(status, PushTransportStartupStatus::Skipped);
}

#[test]
fn tickle_transport_wiring_reports_already_installed() {
    let status = install_owner_event_tickle_transport_with(
        || Some(Arc::new(FakeTickleTransport) as Arc<dyn ApnsTransport>),
        Err,
    );

    assert_eq!(status, PushTransportStartupStatus::AlreadyInstalled);
}

#[test]
fn per_claw_vpn_startup_gate_is_default_off() {
    let status = per_claw_vpn_startup_gate_with(|| Ok(None));

    assert_eq!(status, PerClawVpnStartupStatus::Disabled);
}

#[test]
fn per_claw_vpn_startup_gate_does_not_load_preflight_when_default_off() {
    let status = per_claw_vpn_startup_gate_with_preflight(
        || Ok(None),
        || panic!("preflight evidence must not load when config is absent"),
    );

    assert_eq!(status, PerClawVpnStartupStatus::Disabled);
}

#[test]
fn per_claw_vpn_startup_gate_requires_owner_auth_when_configured() {
    let config = ClawVpnDevConfig::from_values(
        Some("1"),
        None,
        Some("relay-stream://127.0.0.1:49152"),
        Some("198.18.0.0/24"),
        None,
        None,
    )
    .unwrap()
    .unwrap();
    let status = per_claw_vpn_startup_gate_with(|| Ok(Some(config)));

    assert_eq!(
        status,
        PerClawVpnStartupStatus::OwnerAuthorizationRequired {
            mode: ClawVpnDevMode::Live
        }
    );
}

#[test]
fn per_claw_vpn_startup_gate_reports_preflight_blockers_in_order() {
    let config = || {
        ClawVpnDevConfig::from_values(
            Some("1"),
            None,
            Some("relay-stream://127.0.0.1:49152"),
            Some("198.18.0.0/24"),
            None,
            None,
        )
        .unwrap()
        .unwrap()
    };

    let status = per_claw_vpn_startup_gate_with_preflight(
        || Ok(Some(config())),
        || PerClawVpnT1PreflightEvidence::new(true, false, false),
    );
    assert_eq!(
        status,
        PerClawVpnStartupStatus::RollbackRequired {
            mode: ClawVpnDevMode::Live
        }
    );

    let status = per_claw_vpn_startup_gate_with_preflight(
        || Ok(Some(config())),
        || PerClawVpnT1PreflightEvidence::new(true, true, false),
    );
    assert_eq!(
        status,
        PerClawVpnStartupStatus::HardwareEvidenceRequired {
            mode: ClawVpnDevMode::Live
        }
    );

    let status = per_claw_vpn_startup_gate_with_preflight(
        || Ok(Some(config())),
        || PerClawVpnT1PreflightEvidence::new(true, true, true),
    );
    assert_eq!(
        status,
        PerClawVpnStartupStatus::PreflightEvidencePresent {
            mode: ClawVpnDevMode::Live
        }
    );
}

#[test]
fn per_claw_vpn_startup_gate_rejects_dial_mode_after_preflight() {
    let config = ClawVpnDevConfig::from_values(
        None,
        Some("1"),
        Some("relay-stream://127.0.0.1:49152"),
        Some("198.18.0.0/24"),
        None,
        None,
    )
    .unwrap()
    .unwrap();

    let status = per_claw_vpn_startup_gate_with_preflight(
        || Ok(Some(config)),
        || PerClawVpnT1PreflightEvidence::new(true, true, true),
    );

    assert_eq!(
        status,
        PerClawVpnStartupStatus::UnsupportedMode {
            mode: ClawVpnDevMode::Dial
        }
    );
}

fn t1_preflight_evidence_json(
    artifact_sha: &str,
    production_activation: bool,
    rollback_ref: &str,
    audit_root: &str,
) -> String {
    serde_json::json!({
        "schema": PER_CLAW_VPN_T1_PREFLIGHT_EVIDENCE_SCHEMA,
        "artifact_sha": artifact_sha,
        "scope": "dev-host T1-T4 only",
        "production_activation": production_activation,
        "owner_authorization": true,
        "owner_authorization_ref": "owner-authorization-alpha",
        "rollback": true,
        "rollback_ref": rollback_ref,
        "hardware_t1_t4": true,
        "hardware_evidence_ref": "evidence-pack-t1-t4-alpha",
        "audit_root": audit_root,
    })
    .to_string()
}

#[test]
fn server_build_git_sha_is_full_sha_when_available() {
    assert!(
        THEYOS_SERVER_BUILD_GIT_SHA == "unknown" || is_full_git_sha(THEYOS_SERVER_BUILD_GIT_SHA),
        "compiled server build git SHA must be unknown or a full 40-hex SHA"
    );
    assert_eq!(
        theyos_server_build_git_sha().is_some(),
        is_full_git_sha(THEYOS_SERVER_BUILD_GIT_SHA)
    );
}

#[test]
fn t1_preflight_evidence_record_accepts_compiled_artifact_sha_when_available() {
    let Some(artifact_sha) = theyos_server_build_git_sha() else {
        return;
    };
    let json = t1_preflight_evidence_json(
        artifact_sha,
        false,
        "rollback-artifact-alpha",
        "/tmp/t1-evidence-root",
    );

    let bundle = parse_per_claw_vpn_t1_preflight_evidence_record(&json, artifact_sha).unwrap();

    assert!(bundle.evidence().has_owner_authorization());
    assert!(bundle.evidence().has_rollback());
    assert!(bundle.evidence().has_hardware_t1_t4());
}

#[test]
fn t1_preflight_evidence_record_loads_sha_bound_dev_evidence() {
    let artifact_sha = "0123456789abcdef0123456789abcdef01234567";
    let audit_root = "/tmp/t1-evidence-root";
    let json =
        t1_preflight_evidence_json(artifact_sha, false, "rollback-artifact-alpha", audit_root);

    let tempdir = tempfile::tempdir().unwrap();
    let evidence_path = tempdir.path().join("evidence.json");
    std::fs::write(&evidence_path, json).unwrap();

    let bundle =
        load_per_claw_vpn_t1_preflight_evidence_record(&evidence_path, artifact_sha).unwrap();

    assert!(bundle.evidence().has_owner_authorization());
    assert!(bundle.evidence().has_rollback());
    assert!(bundle.evidence().has_hardware_t1_t4());
    assert_eq!(bundle.audit_root(), Path::new(audit_root));

    let config = ClawVpnDevConfig::from_values(
        Some("1"),
        None,
        Some("relay-stream://127.0.0.1:49152"),
        Some("198.18.0.0/24"),
        None,
        None,
    )
    .unwrap()
    .unwrap();
    let status =
        per_claw_vpn_startup_gate_with_preflight(|| Ok(Some(config)), || bundle.evidence());

    assert_eq!(
        status,
        PerClawVpnStartupStatus::PreflightEvidencePresent {
            mode: ClawVpnDevMode::Live
        }
    );
}

#[test]
fn t1_preflight_evidence_record_loads_for_current_build_when_sha_available() {
    let Some(artifact_sha) = theyos_server_build_git_sha() else {
        return;
    };
    let audit_root = "/tmp/t1-evidence-root";
    let json =
        t1_preflight_evidence_json(artifact_sha, false, "rollback-artifact-alpha", audit_root);

    let tempdir = tempfile::tempdir().unwrap();
    let evidence_path = tempdir.path().join("evidence.json");
    std::fs::write(&evidence_path, json).unwrap();

    let bundle =
        load_per_claw_vpn_t1_preflight_evidence_record_for_current_build(&evidence_path).unwrap();

    assert!(bundle.evidence().has_owner_authorization());
    assert!(bundle.evidence().has_rollback());
    assert!(bundle.evidence().has_hardware_t1_t4());
    assert_eq!(bundle.audit_root(), Path::new(audit_root));
}

#[test]
fn t1_preflight_evidence_record_rejects_unknown_current_build_sha() {
    let artifact_sha = "0123456789abcdef0123456789abcdef01234567";
    let json = t1_preflight_evidence_json(
        artifact_sha,
        false,
        "rollback-artifact-alpha",
        "/tmp/t1-evidence-root",
    );

    let tempdir = tempfile::tempdir().unwrap();
    let evidence_path = tempdir.path().join("evidence.json");
    std::fs::write(&evidence_path, json).unwrap();

    let error = load_per_claw_vpn_t1_preflight_evidence_record_for_build_sha(&evidence_path, None)
        .expect_err("unknown build SHA must not load evidence");

    assert!(matches!(
        error,
        PerClawVpnT1PreflightEvidenceLoadError::InvalidArtifactSha
    ));
}

#[test]
fn t1_preflight_evidence_record_rejects_wrong_artifact_sha() {
    let expected_sha = "0123456789abcdef0123456789abcdef01234567";
    let record_sha = "abcdef0123456789abcdef0123456789abcdef01";
    let json = t1_preflight_evidence_json(
        record_sha,
        false,
        "rollback-artifact-alpha",
        "/tmp/t1-evidence-root",
    );

    let error = parse_per_claw_vpn_t1_preflight_evidence_record(&json, expected_sha)
        .expect_err("stale evidence must not load");

    assert!(matches!(
        error,
        PerClawVpnT1PreflightEvidenceLoadError::ArtifactShaMismatch
    ));
}

#[test]
fn t1_preflight_evidence_record_rejects_schema_and_scope_drift() {
    let artifact_sha = "0123456789abcdef0123456789abcdef01234567";
    let base_json = t1_preflight_evidence_json(
        artifact_sha,
        false,
        "rollback-artifact-alpha",
        "/tmp/t1-evidence-root",
    );

    let mut record: serde_json::Value = serde_json::from_str(&base_json).unwrap();
    record["schema"] = serde_json::json!("per_claw_vpn_t1_preflight_evidence_v2");
    let error = parse_per_claw_vpn_t1_preflight_evidence_record(&record.to_string(), artifact_sha)
        .expect_err("schema drift must not load");
    assert!(matches!(
        error,
        PerClawVpnT1PreflightEvidenceLoadError::InvalidSchema
    ));

    let mut record: serde_json::Value = serde_json::from_str(&base_json).unwrap();
    record["scope"] = serde_json::json!("production");
    let error = parse_per_claw_vpn_t1_preflight_evidence_record(&record.to_string(), artifact_sha)
        .expect_err("scope drift must not load");
    assert!(matches!(
        error,
        PerClawVpnT1PreflightEvidenceLoadError::InvalidScope
    ));
}

#[test]
fn t1_preflight_evidence_record_rejects_production_scope() {
    let artifact_sha = "0123456789abcdef0123456789abcdef01234567";
    let json = t1_preflight_evidence_json(
        artifact_sha,
        true,
        "rollback-artifact-alpha",
        "/tmp/t1-evidence-root",
    );

    let error = parse_per_claw_vpn_t1_preflight_evidence_record(&json, artifact_sha)
        .expect_err("production activation must not load as T1 evidence");

    assert!(matches!(
        error,
        PerClawVpnT1PreflightEvidenceLoadError::ProductionActivationRequested
    ));
}

#[test]
fn t1_preflight_evidence_record_rejects_missing_evidence_reference() {
    let artifact_sha = "0123456789abcdef0123456789abcdef01234567";
    let json = t1_preflight_evidence_json(artifact_sha, false, "", "/tmp/t1-evidence-root");

    let error = parse_per_claw_vpn_t1_preflight_evidence_record(&json, artifact_sha)
        .expect_err("evidence references must be present");

    assert!(matches!(
        error,
        PerClawVpnT1PreflightEvidenceLoadError::MissingEvidenceReference
    ));
}

#[test]
fn t1_preflight_evidence_record_rejects_unsafe_audit_root() {
    let artifact_sha = "0123456789abcdef0123456789abcdef01234567";
    for audit_root in ["relative/root", "/tmp/../tmp/t1-evidence-root"] {
        let json =
            t1_preflight_evidence_json(artifact_sha, false, "rollback-artifact-alpha", audit_root);

        let error = parse_per_claw_vpn_t1_preflight_evidence_record(&json, artifact_sha)
            .expect_err("unsafe audit root must not load");

        assert!(matches!(
            error,
            PerClawVpnT1PreflightEvidenceLoadError::InvalidAuditRoot
        ));
    }
}

#[test]
fn per_claw_vpn_startup_gate_fails_closed_on_invalid_config() {
    let status = per_claw_vpn_startup_gate_with(|| Err(ClawVpnDevConfigError::ConflictingModes));

    assert_eq!(status, PerClawVpnStartupStatus::InvalidConfig);
}

#[test]
fn per_claw_vpn_startup_gate_does_not_load_preflight_for_invalid_config() {
    let status = per_claw_vpn_startup_gate_with_preflight(
        || Err(ClawVpnDevConfigError::ConflictingModes),
        || panic!("preflight evidence must not load when config is invalid"),
    );

    assert_eq!(status, PerClawVpnStartupStatus::InvalidConfig);
}

#[test]
fn setup_beacon_params_preserve_label_and_sanitize_dns_host() {
    let params =
        setup_beacon_params_for_host("Developer Mac".to_string(), "Developer Mac.local.", 8091);

    assert_eq!(params.host_label, "Developer Mac");
    assert_eq!(params.host_dns, "developer-mac.local");
    assert_eq!(params.port, 8091);
    assert!(params.pair_machine_window.is_none());
}
