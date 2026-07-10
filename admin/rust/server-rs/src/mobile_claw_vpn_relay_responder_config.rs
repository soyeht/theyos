//! Default-off local identity config for the mobile Claw VPN Relay-R responder.
//!
//! This module only parses and validates the local Claw responder identity. It
//! does not authorize Mesh-C state, open sockets, read relay endpoints, write
//! relay hellos, start Relay-R, install routes, or mutate host networking.

use std::fmt;

use household_rs::claw_vpn_mobile_state::ClawVpnMobileClawId;

pub const MOBILE_CLAW_VPN_RELAY_RESPONDER_ENABLE_ENV: &str =
    "THEYOS_MOBILE_CLAW_VPN_RELAY_RESPONDER_ENABLE";
pub const MOBILE_CLAW_VPN_RELAY_RESPONDER_CLAW_ID_ENV: &str =
    "THEYOS_MOBILE_CLAW_VPN_RELAY_RESPONDER_CLAW_ID";

#[derive(Clone, Default, PartialEq, Eq)]
pub struct MobileClawVpnRelayResponderConfig {
    claw: Option<ClawVpnMobileClawId>,
}

impl fmt::Debug for MobileClawVpnRelayResponderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let claw = if self.claw.is_some() {
            "Some(<redacted>)"
        } else {
            "None"
        };
        f.debug_struct("MobileClawVpnRelayResponderConfig")
            .field("claw", &claw)
            .finish()
    }
}

impl MobileClawVpnRelayResponderConfig {
    pub fn from_env() -> Result<Self, MobileClawVpnRelayResponderConfigError> {
        Self::from_getter(read_env)
    }

    pub fn from_getter(
        get: impl Fn(&'static str) -> Option<Result<String, MobileClawVpnRelayResponderConfigError>>,
    ) -> Result<Self, MobileClawVpnRelayResponderConfigError> {
        let enabled = transpose_env(get(MOBILE_CLAW_VPN_RELAY_RESPONDER_ENABLE_ENV))?;
        let claw = transpose_env(get(MOBILE_CLAW_VPN_RELAY_RESPONDER_CLAW_ID_ENV))?;

        Self::from_values(enabled.as_deref(), claw.as_deref())
    }

    pub fn from_values(
        enabled: Option<&str>,
        claw: Option<&str>,
    ) -> Result<Self, MobileClawVpnRelayResponderConfigError> {
        let enabled = parse_enabled_flag(enabled)?;
        let claw = claw.filter(|value| !value.trim().is_empty());

        if !enabled {
            if claw.is_some() {
                return Err(MobileClawVpnRelayResponderConfigError::ClawIdConfiguredWhileDisabled);
            }
            return Ok(Self::default());
        }

        let claw = claw.ok_or(MobileClawVpnRelayResponderConfigError::ClawIdRequired)?;
        let claw = ClawVpnMobileClawId::try_new(claw)
            .map_err(|_error| MobileClawVpnRelayResponderConfigError::InvalidClawId)?;
        Ok(Self { claw: Some(claw) })
    }

    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.claw.is_some()
    }

    #[must_use]
    pub fn claw(&self) -> Option<&ClawVpnMobileClawId> {
        self.claw.as_ref()
    }
}

fn read_env(name: &'static str) -> Option<Result<String, MobileClawVpnRelayResponderConfigError>> {
    match std::env::var(name) {
        Ok(value) => Some(Ok(value)),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => Some(Err(
            MobileClawVpnRelayResponderConfigError::EnvVarNotUnicode,
        )),
    }
}

fn transpose_env(
    value: Option<Result<String, MobileClawVpnRelayResponderConfigError>>,
) -> Result<Option<String>, MobileClawVpnRelayResponderConfigError> {
    value.transpose()
}

fn parse_enabled_flag(value: Option<&str>) -> Result<bool, MobileClawVpnRelayResponderConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(false);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(MobileClawVpnRelayResponderConfigError::InvalidEnabledFlag),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MobileClawVpnRelayResponderConfigError {
    EnvVarNotUnicode,
    InvalidEnabledFlag,
    ClawIdConfiguredWhileDisabled,
    ClawIdRequired,
    InvalidClawId,
}

impl MobileClawVpnRelayResponderConfigError {
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            Self::EnvVarNotUnicode => "env_var_not_unicode",
            Self::InvalidEnabledFlag => "invalid_enabled_flag",
            Self::ClawIdConfiguredWhileDisabled => "claw_id_configured_while_disabled",
            Self::ClawIdRequired => "claw_id_required",
            Self::InvalidClawId => "invalid_claw_id",
        }
    }
}

impl fmt::Debug for MobileClawVpnRelayResponderConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileClawVpnRelayResponderConfigError")
            .field("kind", &self.kind())
            .finish()
    }
}

impl fmt::Display for MobileClawVpnRelayResponderConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mobile Claw VPN relay responder config is invalid")
    }
}

impl std::error::Error for MobileClawVpnRelayResponderConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_claw_vpn_relay_responder_config_is_default_off() {
        let config = MobileClawVpnRelayResponderConfig::from_values(None, None).unwrap();

        assert_eq!(config, MobileClawVpnRelayResponderConfig::default());
        assert!(!config.is_configured());
        assert!(config.claw().is_none());
        assert!(format!("{config:?}").contains("claw: \"None\""));
    }

    #[test]
    fn mobile_claw_vpn_relay_responder_config_requires_explicit_enable() {
        let error =
            MobileClawVpnRelayResponderConfig::from_values(None, Some("claw-alpha")).unwrap_err();

        assert_eq!(error.kind(), "claw_id_configured_while_disabled");
        assert!(!format!("{error:?}").contains("claw-alpha"));
        assert!(!error.to_string().contains("claw-alpha"));
    }

    #[test]
    fn mobile_claw_vpn_relay_responder_config_accepts_local_claw_identity() {
        let config =
            MobileClawVpnRelayResponderConfig::from_values(Some("true"), Some("claw-alpha"))
                .unwrap();

        assert!(config.is_configured());
        assert_eq!(
            config.claw().unwrap(),
            &ClawVpnMobileClawId::try_new("claw-alpha").unwrap()
        );
        assert!(!format!("{config:?}").contains("claw-alpha"));
        assert!(format!("{config:?}").contains("Some(<redacted>)"));
    }

    #[test]
    fn mobile_claw_vpn_relay_responder_config_rejects_invalid_values_without_echo() {
        let error =
            MobileClawVpnRelayResponderConfig::from_values(Some("maybe"), Some("claw-alpha"))
                .unwrap_err();
        assert_eq!(error.kind(), "invalid_enabled_flag");
        assert!(!format!("{error:?}").contains("claw-alpha"));
        assert!(!error.to_string().contains("claw-alpha"));

        let error = MobileClawVpnRelayResponderConfig::from_values(Some("true"), None).unwrap_err();
        assert_eq!(error.kind(), "claw_id_required");

        let error =
            MobileClawVpnRelayResponderConfig::from_values(Some("true"), Some(" claw-alpha"))
                .unwrap_err();
        assert_eq!(error.kind(), "invalid_claw_id");
        assert!(!format!("{error:?}").contains("claw-alpha"));
        assert!(!error.to_string().contains("claw-alpha"));
    }

    #[test]
    fn mobile_claw_vpn_relay_responder_config_from_getter_is_fail_closed() {
        let error = MobileClawVpnRelayResponderConfig::from_getter(|name| match name {
            MOBILE_CLAW_VPN_RELAY_RESPONDER_ENABLE_ENV => Some(Ok("true".to_string())),
            MOBILE_CLAW_VPN_RELAY_RESPONDER_CLAW_ID_ENV => Some(Err(
                MobileClawVpnRelayResponderConfigError::EnvVarNotUnicode,
            )),
            _ => None,
        })
        .unwrap_err();

        assert_eq!(error.kind(), "env_var_not_unicode");
    }
}
