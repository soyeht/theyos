//! Small startup wiring helpers kept in the library so the binary's boot
//! path can be tested without launching the full server.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::apns_push::{self, HouseCreatedTransport};
use crate::claw_vpn_dev_config::{ClawVpnDevConfig, ClawVpnDevConfigError, ClawVpnDevMode};
use crate::setup_beacon::SetupBeaconParams;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushTransportStartupStatus {
    Installed,
    Skipped,
    AlreadyInstalled,
}

#[must_use = "inspect the per-Claw VPN startup gate status before continuing"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerClawVpnStartupStatus {
    Disabled,
    OwnerAuthorizationRequired { mode: ClawVpnDevMode },
    RollbackRequired { mode: ClawVpnDevMode },
    HardwareEvidenceRequired { mode: ClawVpnDevMode },
    UnsupportedMode { mode: ClawVpnDevMode },
    PreflightEvidencePresent { mode: ClawVpnDevMode },
    InvalidConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerClawVpnT1PreflightEvidence {
    owner_authorization: bool,
    rollback: bool,
    hardware_t1_t4: bool,
}

impl PerClawVpnT1PreflightEvidence {
    #[must_use]
    pub const fn missing() -> Self {
        Self {
            owner_authorization: false,
            rollback: false,
            hardware_t1_t4: false,
        }
    }

    #[must_use]
    pub const fn new(owner_authorization: bool, rollback: bool, hardware_t1_t4: bool) -> Self {
        Self {
            owner_authorization,
            rollback,
            hardware_t1_t4,
        }
    }

    #[must_use]
    pub const fn has_owner_authorization(self) -> bool {
        self.owner_authorization
    }

    #[must_use]
    pub const fn has_rollback(self) -> bool {
        self.rollback
    }

    #[must_use]
    pub const fn has_hardware_t1_t4(self) -> bool {
        self.hardware_t1_t4
    }
}

pub const PER_CLAW_VPN_T1_PREFLIGHT_EVIDENCE_SCHEMA: &str = "per_claw_vpn_t1_preflight_evidence_v1";
pub const THEYOS_SERVER_BUILD_GIT_SHA: &str = env!("THEYOS_SERVER_BUILD_GIT_SHA");
const PER_CLAW_VPN_T1_PREFLIGHT_SCOPE_DEV_T1_T4: &str = "dev-host T1-T4 only";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerClawVpnT1PreflightEvidenceBundle {
    evidence: PerClawVpnT1PreflightEvidence,
    audit_root: PathBuf,
}

impl PerClawVpnT1PreflightEvidenceBundle {
    #[must_use]
    pub fn evidence(&self) -> PerClawVpnT1PreflightEvidence {
        self.evidence
    }

    #[must_use]
    pub fn audit_root(&self) -> &Path {
        &self.audit_root
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PerClawVpnT1PreflightEvidenceLoadError {
    #[error("per-Claw VPN T1 preflight evidence read failed")]
    Read(#[source] io::Error),

    #[error("per-Claw VPN T1 preflight evidence parse failed")]
    Parse(#[source] serde_json::Error),

    #[error("per-Claw VPN T1 preflight evidence schema is invalid")]
    InvalidSchema,

    #[error("per-Claw VPN T1 preflight evidence scope is invalid")]
    InvalidScope,

    #[error("per-Claw VPN T1 preflight evidence artifact SHA is invalid")]
    InvalidArtifactSha,

    #[error("per-Claw VPN T1 preflight evidence artifact SHA mismatch")]
    ArtifactShaMismatch,

    #[error("per-Claw VPN T1 preflight evidence cannot authorize production")]
    ProductionActivationRequested,

    #[error("per-Claw VPN T1 preflight evidence reference is missing")]
    MissingEvidenceReference,

    #[error("per-Claw VPN T1 preflight evidence audit root is invalid")]
    InvalidAuditRoot,
}

#[derive(serde::Deserialize)]
struct PerClawVpnT1PreflightEvidenceRecord {
    schema: String,
    artifact_sha: String,
    scope: String,
    production_activation: bool,
    #[serde(flatten)]
    gates: PerClawVpnT1PreflightEvidenceRecordGates,
    owner_authorization_ref: String,
    rollback_ref: String,
    hardware_evidence_ref: String,
    audit_root: PathBuf,
}

#[derive(serde::Deserialize)]
struct PerClawVpnT1PreflightEvidenceRecordGates {
    owner_authorization: bool,
    rollback: bool,
    hardware_t1_t4: bool,
}

pub fn load_per_claw_vpn_t1_preflight_evidence_record(
    path: impl AsRef<Path>,
    expected_artifact_sha: &str,
) -> Result<PerClawVpnT1PreflightEvidenceBundle, PerClawVpnT1PreflightEvidenceLoadError> {
    let json =
        std::fs::read_to_string(path).map_err(PerClawVpnT1PreflightEvidenceLoadError::Read)?;
    parse_per_claw_vpn_t1_preflight_evidence_record(&json, expected_artifact_sha)
}

pub fn parse_per_claw_vpn_t1_preflight_evidence_record(
    json: &str,
    expected_artifact_sha: &str,
) -> Result<PerClawVpnT1PreflightEvidenceBundle, PerClawVpnT1PreflightEvidenceLoadError> {
    if !is_full_git_sha(expected_artifact_sha) {
        return Err(PerClawVpnT1PreflightEvidenceLoadError::InvalidArtifactSha);
    }
    let record: PerClawVpnT1PreflightEvidenceRecord =
        serde_json::from_str(json).map_err(PerClawVpnT1PreflightEvidenceLoadError::Parse)?;
    if record.schema != PER_CLAW_VPN_T1_PREFLIGHT_EVIDENCE_SCHEMA {
        return Err(PerClawVpnT1PreflightEvidenceLoadError::InvalidSchema);
    }
    if record.scope != PER_CLAW_VPN_T1_PREFLIGHT_SCOPE_DEV_T1_T4 {
        return Err(PerClawVpnT1PreflightEvidenceLoadError::InvalidScope);
    }
    if record.production_activation {
        return Err(PerClawVpnT1PreflightEvidenceLoadError::ProductionActivationRequested);
    }
    if record.owner_authorization_ref.trim().is_empty()
        || record.rollback_ref.trim().is_empty()
        || record.hardware_evidence_ref.trim().is_empty()
    {
        return Err(PerClawVpnT1PreflightEvidenceLoadError::MissingEvidenceReference);
    }
    if !is_full_git_sha(&record.artifact_sha) {
        return Err(PerClawVpnT1PreflightEvidenceLoadError::InvalidArtifactSha);
    }
    if record.artifact_sha != expected_artifact_sha {
        return Err(PerClawVpnT1PreflightEvidenceLoadError::ArtifactShaMismatch);
    }
    if !record.audit_root.is_absolute() || has_non_normal_path_component(&record.audit_root) {
        return Err(PerClawVpnT1PreflightEvidenceLoadError::InvalidAuditRoot);
    }
    Ok(PerClawVpnT1PreflightEvidenceBundle {
        evidence: PerClawVpnT1PreflightEvidence {
            owner_authorization: record.gates.owner_authorization,
            rollback: record.gates.rollback,
            hardware_t1_t4: record.gates.hardware_t1_t4,
        },
        audit_root: record.audit_root,
    })
}

fn is_full_git_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[must_use]
pub fn theyos_server_build_git_sha() -> Option<&'static str> {
    if is_full_git_sha(THEYOS_SERVER_BUILD_GIT_SHA) {
        Some(THEYOS_SERVER_BUILD_GIT_SHA)
    } else {
        None
    }
}

fn has_non_normal_path_component(path: &Path) -> bool {
    path.components().any(|component| {
        !matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )
    })
}

/// Install the production `house_created` APNs transport from environment.
///
/// Missing or invalid APNs environment returns `Skipped`; startup must remain
/// graceful so scenario A and Bonjour-only scenario B keep working.
pub fn install_house_created_push_transport_from_env() -> PushTransportStartupStatus {
    install_house_created_push_transport_with(
        || {
            apns_push::A2Transport::from_env()
                .map(|transport| Arc::new(transport) as Arc<dyn HouseCreatedTransport>)
        },
        apns_push::install_transport,
    )
}

pub fn install_house_created_push_transport_with<Load, Install>(
    load: Load,
    install: Install,
) -> PushTransportStartupStatus
where
    Load: FnOnce() -> Option<Arc<dyn HouseCreatedTransport>>,
    Install: FnOnce(Arc<dyn HouseCreatedTransport>) -> Result<(), Arc<dyn HouseCreatedTransport>>,
{
    let Some(transport) = load() else {
        tracing::info!(
            stage = "apns.push.transport_skipped",
            "THEYOS_APNS_KEY_PATH/_KEY_ID/_TEAM_ID/_TOPIC not all set or invalid - house_created push will no-op"
        );
        return PushTransportStartupStatus::Skipped;
    };

    if let Ok(()) = install(transport) {
        tracing::info!(stage = "apns.push.transport_installed");
        PushTransportStartupStatus::Installed
    } else {
        tracing::info!(stage = "apns.push.transport_already_installed");
        PushTransportStartupStatus::AlreadyInstalled
    }
}

/// Inspect the per-Claw VPN dev flags during startup without activating the
/// datapath.
///
/// This is intentionally a stop gate, not runtime wiring: when the dev config is
/// absent it returns `Disabled`; when it is present it stops at owner
/// authorization and hardware evidence requirements from the T1 readiness
/// runbook. It does not call the runtime assembly, open TUN/utun, dial a relay,
/// install routes, spawn work, or build caller-supplied handles.
#[must_use = "inspect the per-Claw VPN startup gate status before continuing"]
pub fn per_claw_vpn_startup_gate_from_env() -> PerClawVpnStartupStatus {
    per_claw_vpn_startup_gate_with(ClawVpnDevConfig::from_env)
}

#[must_use = "inspect the per-Claw VPN startup gate status before continuing"]
pub fn per_claw_vpn_startup_gate_with<Load>(load: Load) -> PerClawVpnStartupStatus
where
    Load: FnOnce() -> Result<Option<ClawVpnDevConfig>, ClawVpnDevConfigError>,
{
    per_claw_vpn_startup_gate_with_preflight(load, PerClawVpnT1PreflightEvidence::missing)
}

#[must_use = "inspect the per-Claw VPN startup gate status before continuing"]
pub fn per_claw_vpn_startup_gate_with_preflight<Load, LoadPreflight>(
    load: Load,
    load_preflight: LoadPreflight,
) -> PerClawVpnStartupStatus
where
    Load: FnOnce() -> Result<Option<ClawVpnDevConfig>, ClawVpnDevConfigError>,
    LoadPreflight: FnOnce() -> PerClawVpnT1PreflightEvidence,
{
    match load() {
        Ok(None) => PerClawVpnStartupStatus::Disabled,
        Ok(Some(config)) => {
            let mode = config.mode();
            let preflight = load_preflight();
            if !preflight.has_owner_authorization() {
                tracing::warn!(
                    stage = "claw_vpn.startup.owner_authorization_required",
                    mode = ?mode,
                    "per-Claw VPN dev config is present; live wiring remains blocked pending owner authorization, rollback, and T1-T4 hardware evidence"
                );
                return PerClawVpnStartupStatus::OwnerAuthorizationRequired { mode };
            }
            if !preflight.has_rollback() {
                tracing::warn!(
                    stage = "claw_vpn.startup.rollback_required",
                    mode = ?mode,
                    "per-Claw VPN owner authorization is present; live wiring remains blocked pending prebuilt rollback and T1-T4 hardware evidence"
                );
                return PerClawVpnStartupStatus::RollbackRequired { mode };
            }
            if !preflight.has_hardware_t1_t4() {
                tracing::warn!(
                    stage = "claw_vpn.startup.hardware_evidence_required",
                    mode = ?mode,
                    "per-Claw VPN owner authorization and rollback are present; live wiring remains blocked pending T1-T4 hardware evidence"
                );
                return PerClawVpnStartupStatus::HardwareEvidenceRequired { mode };
            }
            match mode {
                ClawVpnDevMode::Live => {}
                ClawVpnDevMode::Dial => {
                    tracing::warn!(
                        stage = "claw_vpn.startup.unsupported_mode",
                        mode = ?mode,
                        "per-Claw VPN T1 preflight evidence is present for a non-live mode; startup gate does not activate live wiring"
                    );
                    return PerClawVpnStartupStatus::UnsupportedMode { mode };
                }
            }
            tracing::warn!(
                stage = "claw_vpn.startup.preflight_evidence_present",
                mode = ?mode,
                "per-Claw VPN T1 preflight evidence is present; startup gate does not activate live wiring"
            );
            PerClawVpnStartupStatus::PreflightEvidencePresent { mode }
        }
        Err(error) => {
            tracing::warn!(
                stage = "claw_vpn.startup.invalid_config",
                error = %error,
                "per-Claw VPN dev config is invalid; live wiring remains disabled"
            );
            PerClawVpnStartupStatus::InvalidConfig
        }
    }
}

#[must_use]
pub fn setup_beacon_params_for_host(
    host_label: String,
    raw_hostname: &str,
    port: u16,
) -> SetupBeaconParams {
    SetupBeaconParams {
        host_label,
        host_dns: host_dns_from_hostname(raw_hostname),
        port,
        pair_machine_window: None,
    }
}

#[must_use]
pub fn host_dns_from_hostname(raw_hostname: &str) -> String {
    let label = sanitize_dns_label(raw_hostname);
    format!("{label}.local")
}

fn sanitize_dns_label(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('.');
    let without_local = trimmed
        .strip_suffix(".local")
        .or_else(|| trimmed.strip_suffix(".LOCAL"))
        .unwrap_or(trimmed);
    let mut out: String = without_local
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while out.starts_with('-') {
        out.remove(0);
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.len() > 63 {
        out.truncate(63);
        while out.ends_with('-') {
            out.pop();
        }
    }
    if out.is_empty() {
        "soyeht-engine".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    struct FakeTransport;

    impl HouseCreatedTransport for FakeTransport {
        fn topic(&self) -> &'static str {
            "com.soyeht.app"
        }

        fn send_push<'a>(
            &'a self,
            _token_hex: &'a str,
            _json_body: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), apns_push::DispatchAttemptError>> + Send + 'a>>
        {
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
            THEYOS_SERVER_BUILD_GIT_SHA == "unknown"
                || is_full_git_sha(THEYOS_SERVER_BUILD_GIT_SHA),
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
        let error =
            parse_per_claw_vpn_t1_preflight_evidence_record(&record.to_string(), artifact_sha)
                .expect_err("schema drift must not load");
        assert!(matches!(
            error,
            PerClawVpnT1PreflightEvidenceLoadError::InvalidSchema
        ));

        let mut record: serde_json::Value = serde_json::from_str(&base_json).unwrap();
        record["scope"] = serde_json::json!("production");
        let error =
            parse_per_claw_vpn_t1_preflight_evidence_record(&record.to_string(), artifact_sha)
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
            let json = t1_preflight_evidence_json(
                artifact_sha,
                false,
                "rollback-artifact-alpha",
                audit_root,
            );

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
        let status =
            per_claw_vpn_startup_gate_with(|| Err(ClawVpnDevConfigError::ConflictingModes));

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
}
