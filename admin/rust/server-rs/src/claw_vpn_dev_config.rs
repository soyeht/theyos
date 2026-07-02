//! Default-off configuration parser for the Product A per-Claw VPN dev proof.
//!
//! This module is intentionally pure: it does not create TUN/utun interfaces,
//! install routes, dial relays, spawn tasks, or wire itself into bootstrap.

use std::fmt;
use std::net::Ipv4Addr;

use household_rs::claw_share_relay_stream_endpoint::{
    RelayStreamEndpointParseError, parse_relay_endpoint,
};
use household_rs::claw_vpn::{
    CLAW_VPN_DEFAULT_MAX_SESSIONS_PER_MEMBER_CLAW, ClawVpnIpv4Pool, ClawVpnPoolError,
};

pub const CLAW_VPN_LIVE_ENV: &str = "THEYOS_CLAW_VPN_LIVE";
pub const CLAW_VPN_DIAL_ENV: &str = "THEYOS_CLAW_VPN_DIAL";
pub const CLAW_VPN_RELAY_ENDPOINT_ENV: &str = "THEYOS_CLAW_VPN_RELAY_ENDPOINT";
pub const CLAW_VPN_IPV4_POOL_ENV: &str = "THEYOS_CLAW_VPN_IPV4_POOL";
pub const CLAW_VPN_MAX_SESSIONS_PER_MEMBER_CLAW_ENV: &str =
    "THEYOS_CLAW_VPN_MAX_SESSIONS_PER_MEMBER_CLAW";
pub const CLAW_VPN_MAX_SESSIONS_PER_CLAW_ENV: &str = "THEYOS_CLAW_VPN_MAX_SESSIONS_PER_CLAW";

pub const CLAW_VPN_DEFAULT_MAX_SESSIONS_PER_CLAW: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnDevMode {
    /// Claw-side dev agent mode.
    Live,
    /// Device/client-side dev dialer mode.
    Dial,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ClawVpnDevConfig {
    mode: ClawVpnDevMode,
    relay_endpoint: String,
    relay_host: String,
    relay_port: u16,
    ipv4_pool: ClawVpnIpv4Pool,
    max_sessions_per_member_claw: usize,
    max_sessions_per_claw: usize,
}

impl fmt::Debug for ClawVpnDevConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnDevConfig")
            .field("mode", &self.mode)
            .field("relay_endpoint", &"<redacted>")
            .field("relay_host", &"<redacted>")
            .field("relay_port", &"<redacted>")
            .field("ipv4_pool", &"<redacted>")
            .field(
                "max_sessions_per_member_claw",
                &self.max_sessions_per_member_claw,
            )
            .field("max_sessions_per_claw", &self.max_sessions_per_claw)
            .finish()
    }
}

impl ClawVpnDevConfig {
    pub fn from_env() -> Result<Option<Self>, ClawVpnDevConfigError> {
        Self::from_getter(read_env)
    }

    pub fn from_getter(
        get: impl Fn(&'static str) -> Option<Result<String, ClawVpnDevConfigError>>,
    ) -> Result<Option<Self>, ClawVpnDevConfigError> {
        let live = transpose_env(get(CLAW_VPN_LIVE_ENV))?;
        let dial = transpose_env(get(CLAW_VPN_DIAL_ENV))?;
        let relay_endpoint = transpose_env(get(CLAW_VPN_RELAY_ENDPOINT_ENV))?;
        let ipv4_pool = transpose_env(get(CLAW_VPN_IPV4_POOL_ENV))?;
        let max_sessions_per_member_claw =
            transpose_env(get(CLAW_VPN_MAX_SESSIONS_PER_MEMBER_CLAW_ENV))?;
        let max_sessions_per_claw = transpose_env(get(CLAW_VPN_MAX_SESSIONS_PER_CLAW_ENV))?;

        Self::from_values(
            live.as_deref(),
            dial.as_deref(),
            relay_endpoint.as_deref(),
            ipv4_pool.as_deref(),
            max_sessions_per_member_claw.as_deref(),
            max_sessions_per_claw.as_deref(),
        )
    }

    pub fn from_values(
        live: Option<&str>,
        dial: Option<&str>,
        relay_endpoint: Option<&str>,
        ipv4_pool: Option<&str>,
        max_sessions_per_member_claw: Option<&str>,
        max_sessions_per_claw: Option<&str>,
    ) -> Result<Option<Self>, ClawVpnDevConfigError> {
        let live_enabled = parse_enabled_flag(CLAW_VPN_LIVE_ENV, live)?;
        let dial_enabled = parse_enabled_flag(CLAW_VPN_DIAL_ENV, dial)?;
        let mode = match (live_enabled, dial_enabled) {
            (false, false) => return Ok(None),
            (true, false) => ClawVpnDevMode::Live,
            (false, true) => ClawVpnDevMode::Dial,
            (true, true) => return Err(ClawVpnDevConfigError::ConflictingModes),
        };
        let relay_endpoint = required_value(CLAW_VPN_RELAY_ENDPOINT_ENV, relay_endpoint)?;
        let (relay_host, relay_port) = parse_relay_endpoint(relay_endpoint)?;
        let ipv4_pool = parse_ipv4_pool(required_value(CLAW_VPN_IPV4_POOL_ENV, ipv4_pool)?)?;
        let max_sessions_per_member_claw = parse_session_limit(
            CLAW_VPN_MAX_SESSIONS_PER_MEMBER_CLAW_ENV,
            max_sessions_per_member_claw,
            CLAW_VPN_DEFAULT_MAX_SESSIONS_PER_MEMBER_CLAW,
        )?;
        let max_sessions_per_claw = parse_session_limit(
            CLAW_VPN_MAX_SESSIONS_PER_CLAW_ENV,
            max_sessions_per_claw,
            CLAW_VPN_DEFAULT_MAX_SESSIONS_PER_CLAW,
        )?;

        Ok(Some(Self {
            mode,
            relay_endpoint: relay_endpoint.to_string(),
            relay_host,
            relay_port,
            ipv4_pool,
            max_sessions_per_member_claw,
            max_sessions_per_claw,
        }))
    }

    #[must_use]
    pub fn mode(&self) -> ClawVpnDevMode {
        self.mode
    }

    #[must_use]
    pub fn relay_endpoint(&self) -> &str {
        &self.relay_endpoint
    }

    #[must_use]
    pub fn relay_host(&self) -> &str {
        &self.relay_host
    }

    #[must_use]
    pub fn relay_port(&self) -> u16 {
        self.relay_port
    }

    #[must_use]
    pub fn ipv4_pool(&self) -> ClawVpnIpv4Pool {
        self.ipv4_pool
    }

    #[must_use]
    pub fn max_sessions_per_member_claw(&self) -> usize {
        self.max_sessions_per_member_claw
    }

    #[must_use]
    pub fn max_sessions_per_claw(&self) -> usize {
        self.max_sessions_per_claw
    }
}

fn read_env(name: &'static str) -> Option<Result<String, ClawVpnDevConfigError>> {
    match std::env::var(name) {
        Ok(value) => Some(Ok(value)),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            Some(Err(ClawVpnDevConfigError::EnvVarNotUnicode(name)))
        }
    }
}

fn transpose_env(
    value: Option<Result<String, ClawVpnDevConfigError>>,
) -> Result<Option<String>, ClawVpnDevConfigError> {
    value.transpose()
}

fn parse_enabled_flag(
    field: &'static str,
    value: Option<&str>,
) -> Result<bool, ClawVpnDevConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(false);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ClawVpnDevConfigError::InvalidEnabledFlag { field }),
    }
}

fn required_value<'a>(
    field: &'static str,
    value: Option<&'a str>,
) -> Result<&'a str, ClawVpnDevConfigError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ClawVpnDevConfigError::Required { field })
}

fn parse_session_limit(
    field: &'static str,
    value: Option<&str>,
    default: usize,
) -> Result<usize, ClawVpnDevConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };
    let parsed = value
        .parse::<usize>()
        .map_err(|_| ClawVpnDevConfigError::InvalidSessionLimit { field })?;
    if parsed == 0 {
        return Err(ClawVpnDevConfigError::InvalidSessionLimit { field });
    }
    Ok(parsed)
}

fn parse_ipv4_pool(value: &str) -> Result<ClawVpnIpv4Pool, ClawVpnDevConfigError> {
    let (network, prefix_len) = value
        .split_once('/')
        .ok_or(ClawVpnDevConfigError::InvalidIpv4Pool)?;
    let network = network
        .parse::<Ipv4Addr>()
        .map_err(|_| ClawVpnDevConfigError::InvalidIpv4Pool)?;
    let prefix_len = prefix_len
        .parse::<u8>()
        .map_err(|_| ClawVpnDevConfigError::InvalidIpv4Pool)?;
    ClawVpnIpv4Pool::try_new(network, prefix_len).map_err(Into::into)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClawVpnDevConfigError {
    #[error("claw vpn dev config env var is not unicode: {0}")]
    EnvVarNotUnicode(&'static str),

    #[error("claw vpn dev config enabled flag is invalid: {field}")]
    InvalidEnabledFlag { field: &'static str },

    #[error("claw vpn live and dial modes cannot both be enabled")]
    ConflictingModes,

    #[error("claw vpn dev config value is required: {field}")]
    Required { field: &'static str },

    #[error("claw vpn dev config relay endpoint is invalid")]
    RelayEndpoint(#[from] RelayStreamEndpointParseError),

    #[error("claw vpn dev config IPv4 pool must be formatted as network/prefix")]
    InvalidIpv4Pool,

    #[error("claw vpn dev config IPv4 pool is rejected")]
    Pool(#[from] ClawVpnPoolError),

    #[error("claw vpn dev config session limit is invalid: {field}")]
    InvalidSessionLimit { field: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT: &str = "relay-stream://127.0.0.1:49152";
    const POOL: &str = "198.18.0.0/24";

    #[test]
    fn claw_vpn_dev_config_is_default_off() {
        assert_eq!(
            ClawVpnDevConfig::from_values(None, None, None, None, None, None),
            Ok(None)
        );
        assert_eq!(
            ClawVpnDevConfig::from_values(
                Some("off"),
                Some("0"),
                Some(ENDPOINT),
                Some(POOL),
                None,
                None,
            ),
            Ok(None)
        );
    }

    #[test]
    fn claw_vpn_dev_config_parses_live_mode() {
        let config = ClawVpnDevConfig::from_values(
            Some("1"),
            None,
            Some(ENDPOINT),
            Some(POOL),
            Some("2"),
            Some("8"),
        )
        .unwrap()
        .unwrap();

        assert_eq!(config.mode(), ClawVpnDevMode::Live);
        assert_eq!(config.relay_endpoint(), ENDPOINT);
        assert_eq!(config.relay_host(), "127.0.0.1");
        assert_eq!(config.relay_port(), 49152);
        assert_eq!(config.ipv4_pool().network(), Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(config.ipv4_pool().prefix_len(), 24);
        assert_eq!(config.max_sessions_per_member_claw(), 2);
        assert_eq!(config.max_sessions_per_claw(), 8);
    }

    #[test]
    fn claw_vpn_dev_config_parses_dial_mode_with_safe_defaults() {
        let config = ClawVpnDevConfig::from_values(
            None,
            Some("true"),
            Some(ENDPOINT),
            Some(POOL),
            None,
            None,
        )
        .unwrap()
        .unwrap();

        assert_eq!(config.mode(), ClawVpnDevMode::Dial);
        assert_eq!(
            config.max_sessions_per_member_claw(),
            CLAW_VPN_DEFAULT_MAX_SESSIONS_PER_MEMBER_CLAW
        );
        assert_eq!(
            config.max_sessions_per_claw(),
            CLAW_VPN_DEFAULT_MAX_SESSIONS_PER_CLAW
        );
    }

    #[test]
    fn claw_vpn_dev_config_rejects_ambiguous_or_invalid_enablement() {
        assert_eq!(
            ClawVpnDevConfig::from_values(
                Some("1"),
                Some("1"),
                Some(ENDPOINT),
                Some(POOL),
                None,
                None,
            ),
            Err(ClawVpnDevConfigError::ConflictingModes)
        );
        assert_eq!(
            ClawVpnDevConfig::from_values(Some("maybe"), None, None, None, None, None),
            Err(ClawVpnDevConfigError::InvalidEnabledFlag {
                field: CLAW_VPN_LIVE_ENV
            })
        );
    }

    #[test]
    fn claw_vpn_dev_config_fails_closed_when_enabled_values_are_missing() {
        assert_eq!(
            ClawVpnDevConfig::from_values(Some("1"), None, None, Some(POOL), None, None),
            Err(ClawVpnDevConfigError::Required {
                field: CLAW_VPN_RELAY_ENDPOINT_ENV
            })
        );
        assert_eq!(
            ClawVpnDevConfig::from_values(Some("1"), None, Some(ENDPOINT), None, None, None),
            Err(ClawVpnDevConfigError::Required {
                field: CLAW_VPN_IPV4_POOL_ENV
            })
        );
    }

    #[test]
    fn claw_vpn_dev_config_rejects_bad_endpoint_pool_and_limits() {
        assert_eq!(
            ClawVpnDevConfig::from_values(
                Some("1"),
                None,
                Some("http://127.0.0.1:49152"),
                Some(POOL),
                None,
                None,
            ),
            Err(ClawVpnDevConfigError::RelayEndpoint(
                RelayStreamEndpointParseError::WrongScheme
            ))
        );
        assert_eq!(
            ClawVpnDevConfig::from_values(
                Some("1"),
                None,
                Some(ENDPOINT),
                Some("198.18.0.0"),
                None,
                None,
            ),
            Err(ClawVpnDevConfigError::InvalidIpv4Pool)
        );
        assert_eq!(
            ClawVpnDevConfig::from_values(
                Some("1"),
                None,
                Some(ENDPOINT),
                Some("100.64.0.0/24"),
                None,
                None,
            ),
            Err(ClawVpnDevConfigError::Pool(
                ClawVpnPoolError::OverlapsReservedRange
            ))
        );
        assert_eq!(
            ClawVpnDevConfig::from_values(
                Some("1"),
                None,
                Some(ENDPOINT),
                Some(POOL),
                Some("0"),
                None,
            ),
            Err(ClawVpnDevConfigError::InvalidSessionLimit {
                field: CLAW_VPN_MAX_SESSIONS_PER_MEMBER_CLAW_ENV
            })
        );
    }

    #[test]
    fn claw_vpn_dev_config_debug_redacts_endpoint_and_pool() {
        let config =
            ClawVpnDevConfig::from_values(Some("1"), None, Some(ENDPOINT), Some(POOL), None, None)
                .unwrap()
                .unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("127.0.0.1"));
        assert!(!debug.contains("198.18.0.0"));
        assert!(debug.contains("Live"));
    }
}
