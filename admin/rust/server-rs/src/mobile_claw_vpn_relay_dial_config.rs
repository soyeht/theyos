//! Default-off relay dial config for mobile Claw VPN rendezvous preflight.
//!
//! This module only parses and validates configuration. It does not authorize
//! Mesh-C state, open sockets, write relay hellos, start Relay-R, install
//! routes, or mutate host networking.

use std::{fmt, net::SocketAddr, time::Duration};

pub const MOBILE_CLAW_VPN_RELAY_DIAL_ADDR_ENV: &str = "THEYOS_MOBILE_CLAW_VPN_RELAY_DIAL_ADDR";
pub const MOBILE_CLAW_VPN_RELAY_DIAL_ALLOW_NON_LOOPBACK_ENV: &str =
    "THEYOS_MOBILE_CLAW_VPN_RELAY_DIAL_ALLOW_NON_LOOPBACK";
pub const MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT_SECS_ENV: &str =
    "THEYOS_MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT_SECS";
pub const MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT_SECS_ENV: &str =
    "THEYOS_MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT_SECS";

pub const DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_MOBILE_CLAW_VPN_RELAY_DIAL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MobileClawVpnRendezvousRelayDialConfig {
    pub(crate) relay_addr: Option<SocketAddr>,
    pub(crate) connect_timeout: Duration,
    pub(crate) hello_timeout: Duration,
    pub(crate) allow_non_loopback_relay_addr: bool,
}

impl Default for MobileClawVpnRendezvousRelayDialConfig {
    fn default() -> Self {
        Self {
            relay_addr: None,
            connect_timeout: DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT,
            hello_timeout: DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT,
            allow_non_loopback_relay_addr: false,
        }
    }
}

impl fmt::Debug for MobileClawVpnRendezvousRelayDialConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let relay_addr = if self.relay_addr.is_some() {
            "Some(<redacted>)"
        } else {
            "None"
        };
        f.debug_struct("MobileClawVpnRendezvousRelayDialConfig")
            .field("relay_addr", &relay_addr)
            .field("connect_timeout", &self.connect_timeout)
            .field("hello_timeout", &self.hello_timeout)
            .field(
                "allow_non_loopback_relay_addr",
                &self.allow_non_loopback_relay_addr,
            )
            .finish()
    }
}

impl MobileClawVpnRendezvousRelayDialConfig {
    pub fn from_env() -> Result<Self, MobileClawVpnRendezvousRelayDialConfigError> {
        Self::from_getter(read_env)
    }

    pub fn from_getter(
        get: impl Fn(
            &'static str,
        ) -> Option<Result<String, MobileClawVpnRendezvousRelayDialConfigError>>,
    ) -> Result<Self, MobileClawVpnRendezvousRelayDialConfigError> {
        let relay_addr = transpose_env(get(MOBILE_CLAW_VPN_RELAY_DIAL_ADDR_ENV))?;
        let allow_non_loopback =
            transpose_env(get(MOBILE_CLAW_VPN_RELAY_DIAL_ALLOW_NON_LOOPBACK_ENV))?;
        let connect_timeout =
            transpose_env(get(MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT_SECS_ENV))?;
        let hello_timeout = transpose_env(get(MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT_SECS_ENV))?;

        Self::from_values(
            relay_addr.as_deref(),
            allow_non_loopback.as_deref(),
            connect_timeout.as_deref(),
            hello_timeout.as_deref(),
        )
    }

    pub fn from_values(
        relay_addr: Option<&str>,
        allow_non_loopback: Option<&str>,
        connect_timeout_secs: Option<&str>,
        hello_timeout_secs: Option<&str>,
    ) -> Result<Self, MobileClawVpnRendezvousRelayDialConfigError> {
        let relay_addr = parse_optional_relay_addr(relay_addr)?;
        let allow_non_loopback_relay_addr = parse_bool(allow_non_loopback)?;
        let connect_timeout = parse_duration_secs(
            connect_timeout_secs,
            DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT,
        )?;
        let hello_timeout = parse_duration_secs(
            hello_timeout_secs,
            DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT,
        )?;

        let config = Self {
            relay_addr,
            connect_timeout,
            hello_timeout,
            allow_non_loopback_relay_addr,
        };
        config.validate_config()?;
        Ok(config)
    }

    #[must_use]
    pub fn is_configured(self) -> bool {
        self.relay_addr.is_some()
    }

    pub(crate) fn validate_for_dial(self) -> Result<Self, MobileClawVpnRendezvousRelayDialError> {
        self.validate_config()
            .map_err(MobileClawVpnRendezvousRelayDialError::from)?;
        Ok(self)
    }

    pub(crate) fn validate_for_token_bearing_dial(
        self,
    ) -> Result<Self, MobileClawVpnRendezvousRelayDialError> {
        let config = self.validate_for_dial()?;
        if let Some(relay_addr) = config.relay_addr {
            if !relay_addr.ip().is_loopback() {
                return Err(MobileClawVpnRendezvousRelayDialError::RelayAuthRequired);
            }
        }
        Ok(config)
    }

    fn validate_config(self) -> Result<Self, MobileClawVpnRendezvousRelayDialConfigError> {
        if let Some(relay_addr) = self.relay_addr {
            if !self.allow_non_loopback_relay_addr && !relay_addr.ip().is_loopback() {
                return Err(MobileClawVpnRendezvousRelayDialConfigError::NonLoopbackRelayAddr);
            }
            if relay_addr.port() == 0 {
                return Err(MobileClawVpnRendezvousRelayDialConfigError::InvalidRelayAddrPort);
            }
        }
        validate_deadline(self.connect_timeout)?;
        validate_deadline(self.hello_timeout)?;
        Ok(self)
    }
}

fn read_env(
    name: &'static str,
) -> Option<Result<String, MobileClawVpnRendezvousRelayDialConfigError>> {
    match std::env::var(name) {
        Ok(value) => Some(Ok(value)),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => Some(Err(
            MobileClawVpnRendezvousRelayDialConfigError::EnvVarNotUnicode,
        )),
    }
}

fn transpose_env(
    value: Option<Result<String, MobileClawVpnRendezvousRelayDialConfigError>>,
) -> Result<Option<String>, MobileClawVpnRendezvousRelayDialConfigError> {
    value.transpose()
}

fn parse_optional_relay_addr(
    raw: Option<&str>,
) -> Result<Option<SocketAddr>, MobileClawVpnRendezvousRelayDialConfigError> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    raw.parse::<SocketAddr>()
        .map(Some)
        .map_err(|_| MobileClawVpnRendezvousRelayDialConfigError::InvalidRelayAddr)
}

fn parse_bool(raw: Option<&str>) -> Result<bool, MobileClawVpnRendezvousRelayDialConfigError> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(false);
    };
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(MobileClawVpnRendezvousRelayDialConfigError::InvalidAllowNonLoopbackFlag),
    }
}

fn parse_duration_secs(
    raw: Option<&str>,
    default: Duration,
) -> Result<Duration, MobileClawVpnRendezvousRelayDialConfigError> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };
    let seconds = raw
        .parse::<u64>()
        .map_err(|_| MobileClawVpnRendezvousRelayDialConfigError::InvalidDeadline)?;
    Ok(Duration::from_secs(seconds))
}

fn validate_deadline(
    duration: Duration,
) -> Result<(), MobileClawVpnRendezvousRelayDialConfigError> {
    if duration.is_zero() || duration > MAX_MOBILE_CLAW_VPN_RELAY_DIAL_TIMEOUT {
        return Err(MobileClawVpnRendezvousRelayDialConfigError::InvalidDeadline);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MobileClawVpnRendezvousRelayDialConfigError {
    EnvVarNotUnicode,
    InvalidRelayAddr,
    NonLoopbackRelayAddr,
    InvalidRelayAddrPort,
    InvalidDeadline,
    InvalidAllowNonLoopbackFlag,
}

impl MobileClawVpnRendezvousRelayDialConfigError {
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            Self::EnvVarNotUnicode => "env_var_not_unicode",
            Self::InvalidRelayAddr => "invalid_relay_addr",
            Self::NonLoopbackRelayAddr => "non_loopback_relay_addr",
            Self::InvalidRelayAddrPort => "invalid_relay_addr_port",
            Self::InvalidDeadline => "invalid_deadline",
            Self::InvalidAllowNonLoopbackFlag => "invalid_allow_non_loopback_flag",
        }
    }
}

impl fmt::Debug for MobileClawVpnRendezvousRelayDialConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileClawVpnRendezvousRelayDialConfigError")
            .field("kind", &self.kind())
            .finish()
    }
}

impl fmt::Display for MobileClawVpnRendezvousRelayDialConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mobile Claw VPN rendezvous relay dial config is invalid")
    }
}

impl std::error::Error for MobileClawVpnRendezvousRelayDialConfigError {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MobileClawVpnRendezvousRelayDialError {
    InvalidConfig,
    NonLoopbackRelayAddr,
    InvalidRelayAddrPort,
    InvalidDeadline,
    ConnectTimeout,
    DialFailed,
    HelloTimeout,
    HelloWriteFailed,
    RelayAuthRequired,
}

impl MobileClawVpnRendezvousRelayDialError {
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::NonLoopbackRelayAddr => "non_loopback_relay_addr",
            Self::InvalidRelayAddrPort => "invalid_relay_addr_port",
            Self::InvalidDeadline => "invalid_deadline",
            Self::ConnectTimeout => "connect_timeout",
            Self::DialFailed => "dial_failed",
            Self::HelloTimeout => "hello_timeout",
            Self::HelloWriteFailed => "hello_write_failed",
            Self::RelayAuthRequired => "relay_auth_required",
        }
    }
}

impl From<MobileClawVpnRendezvousRelayDialConfigError> for MobileClawVpnRendezvousRelayDialError {
    fn from(error: MobileClawVpnRendezvousRelayDialConfigError) -> Self {
        match error {
            MobileClawVpnRendezvousRelayDialConfigError::NonLoopbackRelayAddr => {
                Self::NonLoopbackRelayAddr
            }
            MobileClawVpnRendezvousRelayDialConfigError::InvalidRelayAddrPort => {
                Self::InvalidRelayAddrPort
            }
            MobileClawVpnRendezvousRelayDialConfigError::InvalidDeadline => Self::InvalidDeadline,
            MobileClawVpnRendezvousRelayDialConfigError::EnvVarNotUnicode
            | MobileClawVpnRendezvousRelayDialConfigError::InvalidRelayAddr
            | MobileClawVpnRendezvousRelayDialConfigError::InvalidAllowNonLoopbackFlag => {
                Self::InvalidConfig
            }
        }
    }
}

impl fmt::Debug for MobileClawVpnRendezvousRelayDialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileClawVpnRendezvousRelayDialError")
            .field("kind", &self.kind())
            .finish()
    }
}

impl fmt::Display for MobileClawVpnRendezvousRelayDialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mobile Claw VPN rendezvous relay dial failed")
    }
}

impl std::error::Error for MobileClawVpnRendezvousRelayDialError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_claw_vpn_relay_dial_config_is_default_off() {
        let config =
            MobileClawVpnRendezvousRelayDialConfig::from_values(None, None, None, None).unwrap();

        assert_eq!(config, MobileClawVpnRendezvousRelayDialConfig::default());
        assert!(!config.is_configured());
        assert!(format!("{config:?}").contains("relay_addr: \"None\""));
    }

    #[test]
    fn mobile_claw_vpn_relay_dial_config_accepts_loopback_endpoint() {
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("127.0.0.1:49152"),
            None,
            Some("3"),
            Some("4"),
        )
        .unwrap();

        assert!(config.is_configured());
        assert_eq!(config.relay_addr, Some("127.0.0.1:49152".parse().unwrap()));
        assert_eq!(config.connect_timeout, Duration::from_secs(3));
        assert_eq!(config.hello_timeout, Duration::from_secs(4));
        assert!(!config.allow_non_loopback_relay_addr);
        assert!(!format!("{config:?}").contains("127.0.0.1"));
    }

    #[test]
    fn mobile_claw_vpn_relay_dial_config_requires_explicit_non_loopback_opt_in() {
        assert_eq!(
            MobileClawVpnRendezvousRelayDialConfig::from_values(
                Some("198.51.100.10:49152"),
                None,
                None,
                None,
            )
            .unwrap_err()
            .kind(),
            "non_loopback_relay_addr"
        );

        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("198.51.100.10:49152"),
            Some("true"),
            None,
            None,
        )
        .unwrap();
        assert!(config.allow_non_loopback_relay_addr);
        assert!(!format!("{config:?}").contains("198.51.100.10"));
    }

    #[test]
    fn mobile_claw_vpn_relay_dial_token_bearing_non_loopback_requires_relay_auth() {
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("198.51.100.10:49152"),
            Some("true"),
            None,
            None,
        )
        .unwrap();

        let error = config.validate_for_token_bearing_dial().unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{config:?}").contains("198.51.100.10"));
        assert!(!format!("{error:?}").contains("198.51.100.10"));
        assert!(!error.to_string().contains("198.51.100.10"));
    }

    #[test]
    fn mobile_claw_vpn_relay_dial_config_rejects_invalid_values_without_echo() {
        let error = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("relay.example.invalid:49152"),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(error.kind(), "invalid_relay_addr");
        assert!(!format!("{error:?}").contains("relay.example.invalid"));
        assert!(!error.to_string().contains("relay.example.invalid"));

        assert_eq!(
            MobileClawVpnRendezvousRelayDialConfig::from_values(
                Some("127.0.0.1:49152"),
                Some("maybe"),
                None,
                None,
            )
            .unwrap_err()
            .kind(),
            "invalid_allow_non_loopback_flag"
        );
        assert_eq!(
            MobileClawVpnRendezvousRelayDialConfig::from_values(
                Some("127.0.0.1:49152"),
                None,
                Some("0"),
                None,
            )
            .unwrap_err()
            .kind(),
            "invalid_deadline"
        );
    }
}
