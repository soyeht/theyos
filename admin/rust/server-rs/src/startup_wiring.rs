//! Small startup wiring helpers kept in the library so the binary's boot
//! path can be tested without launching the full server.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerClawVpnStartupStatus {
    Disabled,
    OwnerAuthorizationRequired { mode: ClawVpnDevMode },
    InvalidConfig,
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
pub fn per_claw_vpn_startup_gate_from_env() -> PerClawVpnStartupStatus {
    per_claw_vpn_startup_gate_with(ClawVpnDevConfig::from_env)
}

pub fn per_claw_vpn_startup_gate_with<Load>(load: Load) -> PerClawVpnStartupStatus
where
    Load: FnOnce() -> Result<Option<ClawVpnDevConfig>, ClawVpnDevConfigError>,
{
    match load() {
        Ok(None) => PerClawVpnStartupStatus::Disabled,
        Ok(Some(config)) => {
            let mode = config.mode();
            tracing::warn!(
                stage = "claw_vpn.startup.owner_authorization_required",
                mode = ?mode,
                "per-Claw VPN dev config is present; live wiring remains blocked pending owner authorization, rollback, and T1-T4 hardware evidence"
            );
            PerClawVpnStartupStatus::OwnerAuthorizationRequired { mode }
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
    fn per_claw_vpn_startup_gate_fails_closed_on_invalid_config() {
        let status =
            per_claw_vpn_startup_gate_with(|| Err(ClawVpnDevConfigError::ConflictingModes));

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
