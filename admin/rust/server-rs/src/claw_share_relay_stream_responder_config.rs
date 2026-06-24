//! Default-off configuration guard for the future Product A `relay_stream` responder.
//!
//! This module is intentionally pure parsing/validation. It does not spawn a
//! responder, open sockets, load household state, mint offers, advertise
//! `relay_stream`, or touch the Noise keystore.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::claw_share_relay_stream_noise_keystore::{
    DEFAULT_RELAY_STREAM_NOISE_KEY_ID, relay_stream_noise_static_key_account,
};

pub const RELAY_STREAM_RESPONDER_ENABLE_ENV: &str = "THEYOS_CLAW_RELAY_STREAM_ENABLE";
pub const RELAY_STREAM_RESPONDER_BIND_ADDR_ENV: &str = "THEYOS_CLAW_RELAY_STREAM_BIND_ADDR";
pub const RELAY_STREAM_RESPONDER_KEY_ID_ENV: &str = "THEYOS_CLAW_RELAY_STREAM_KEY_ID";
pub const RELAY_STREAM_RESPONDER_AUTH_DEADLINE_SECS_ENV: &str =
    "THEYOS_CLAW_RELAY_STREAM_AUTH_DEADLINE_SECS";
pub const RELAY_STREAM_RESPONDER_IDLE_TIMEOUT_SECS_ENV: &str =
    "THEYOS_CLAW_RELAY_STREAM_IDLE_TIMEOUT_SECS";

pub const DEFAULT_RELAY_STREAM_RESPONDER_AUTH_DEADLINE: Duration = Duration::from_secs(15);
pub const DEFAULT_RELAY_STREAM_RESPONDER_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_RELAY_STREAM_RESPONDER_AUTH_DEADLINE: Duration = Duration::from_secs(300);
pub const MAX_RELAY_STREAM_RESPONDER_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStreamResponderConfig {
    pub enabled: bool,
    pub bind_addr: SocketAddr,
    pub key_id: String,
    pub auth_deadline: Duration,
    pub idle_timeout: Duration,
}

impl RelayStreamResponderConfig {
    pub fn new(
        bind_addr: &str,
        key_id: Option<&str>,
        auth_deadline: Duration,
        idle_timeout: Duration,
    ) -> Result<Self, RelayStreamResponderConfigError> {
        let key_id = key_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
            .to_string();
        validate_key_id(&key_id)?;

        Ok(Self {
            enabled: true,
            bind_addr: parse_loopback_bind_addr(bind_addr)?,
            key_id,
            auth_deadline: validate_deadline(
                "auth_deadline",
                auth_deadline,
                MAX_RELAY_STREAM_RESPONDER_AUTH_DEADLINE,
            )?,
            idle_timeout: validate_deadline(
                "idle_timeout",
                idle_timeout,
                MAX_RELAY_STREAM_RESPONDER_IDLE_TIMEOUT,
            )?,
        })
    }

    pub fn from_env() -> Result<Option<Self>, RelayStreamResponderConfigError> {
        Self::from_getter(read_env)
    }

    pub fn from_getter(
        get: impl Fn(&'static str) -> Option<Result<String, RelayStreamResponderConfigError>>,
    ) -> Result<Option<Self>, RelayStreamResponderConfigError> {
        let enabled = transpose_env(get(RELAY_STREAM_RESPONDER_ENABLE_ENV))?;
        let bind_addr = transpose_env(get(RELAY_STREAM_RESPONDER_BIND_ADDR_ENV))?;
        let key_id = transpose_env(get(RELAY_STREAM_RESPONDER_KEY_ID_ENV))?;
        let auth_deadline_secs = transpose_env(get(RELAY_STREAM_RESPONDER_AUTH_DEADLINE_SECS_ENV))?;
        let idle_timeout_secs = transpose_env(get(RELAY_STREAM_RESPONDER_IDLE_TIMEOUT_SECS_ENV))?;

        Self::from_values(
            enabled.as_deref(),
            bind_addr.as_deref(),
            key_id.as_deref(),
            auth_deadline_secs.as_deref(),
            idle_timeout_secs.as_deref(),
        )
    }

    pub fn from_values(
        enabled: Option<&str>,
        bind_addr: Option<&str>,
        key_id: Option<&str>,
        auth_deadline_secs: Option<&str>,
        idle_timeout_secs: Option<&str>,
    ) -> Result<Option<Self>, RelayStreamResponderConfigError> {
        if !is_truthy_enabled(enabled)? {
            return Ok(None);
        }

        let bind_addr = bind_addr
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(RelayStreamResponderConfigError::BindAddrRequired)?;
        let auth_deadline = parse_duration_secs(
            "auth_deadline",
            auth_deadline_secs,
            DEFAULT_RELAY_STREAM_RESPONDER_AUTH_DEADLINE,
            MAX_RELAY_STREAM_RESPONDER_AUTH_DEADLINE,
        )?;
        let idle_timeout = parse_duration_secs(
            "idle_timeout",
            idle_timeout_secs,
            DEFAULT_RELAY_STREAM_RESPONDER_IDLE_TIMEOUT,
            MAX_RELAY_STREAM_RESPONDER_IDLE_TIMEOUT,
        )?;

        Self::new(bind_addr, key_id, auth_deadline, idle_timeout).map(Some)
    }
}

fn read_env(name: &'static str) -> Option<Result<String, RelayStreamResponderConfigError>> {
    match std::env::var(name) {
        Ok(value) => Some(Ok(value)),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            Some(Err(RelayStreamResponderConfigError::EnvVarNotUnicode(name)))
        }
    }
}

fn transpose_env(
    value: Option<Result<String, RelayStreamResponderConfigError>>,
) -> Result<Option<String>, RelayStreamResponderConfigError> {
    value.transpose()
}

fn is_truthy_enabled(value: Option<&str>) -> Result<bool, RelayStreamResponderConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(false);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(RelayStreamResponderConfigError::InvalidEnabledFlag),
    }
}

// TODO(relay-stream): factor this with the rendezvous listener loopback guard
// when the responder lifecycle is introduced.
fn parse_loopback_bind_addr(raw: &str) -> Result<SocketAddr, RelayStreamResponderConfigError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(RelayStreamResponderConfigError::BindAddrRequired);
    }

    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return validate_loopback_bind_addr(addr);
    }

    let Some(port) = raw.strip_prefix("localhost:") else {
        return Err(RelayStreamResponderConfigError::InvalidBindAddr);
    };
    validate_loopback_bind_addr(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        parse_port(port)?,
    ))
}

fn validate_loopback_bind_addr(
    addr: SocketAddr,
) -> Result<SocketAddr, RelayStreamResponderConfigError> {
    if !addr.ip().is_loopback() {
        return Err(RelayStreamResponderConfigError::NonLoopbackBindAddr);
    }
    if addr.port() == 0 {
        return Err(RelayStreamResponderConfigError::InvalidBindAddrPort);
    }
    Ok(addr)
}

fn parse_port(raw: &str) -> Result<u16, RelayStreamResponderConfigError> {
    let port = raw
        .parse::<u16>()
        .map_err(|_| RelayStreamResponderConfigError::InvalidBindAddrPort)?;
    if port == 0 {
        return Err(RelayStreamResponderConfigError::InvalidBindAddrPort);
    }
    Ok(port)
}

fn validate_key_id(key_id: &str) -> Result<(), RelayStreamResponderConfigError> {
    relay_stream_noise_static_key_account(key_id)
        .map(|_| ())
        .map_err(|_| RelayStreamResponderConfigError::InvalidKeyId)
}

fn parse_duration_secs(
    field: &'static str,
    value: Option<&str>,
    default: Duration,
    max: Duration,
) -> Result<Duration, RelayStreamResponderConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };
    let seconds = value
        .parse::<u64>()
        .map_err(|_| RelayStreamResponderConfigError::InvalidDeadline { field })?;
    validate_deadline(field, Duration::from_secs(seconds), max)
}

fn validate_deadline(
    field: &'static str,
    duration: Duration,
    max: Duration,
) -> Result<Duration, RelayStreamResponderConfigError> {
    if duration.is_zero() || duration > max {
        return Err(RelayStreamResponderConfigError::InvalidDeadline { field });
    }
    Ok(duration)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayStreamResponderConfigError {
    #[error("relay stream responder env var is not unicode: {0}")]
    EnvVarNotUnicode(&'static str),

    #[error("relay stream responder enabled flag is invalid")]
    InvalidEnabledFlag,

    #[error("relay stream responder bind address is required")]
    BindAddrRequired,

    #[error("relay stream responder bind address is invalid")]
    InvalidBindAddr,

    #[error("relay stream responder bind address must be loopback")]
    NonLoopbackBindAddr,

    #[error("relay stream responder bind address port is invalid")]
    InvalidBindAddrPort,

    #[error("relay stream responder key id is invalid")]
    InvalidKeyId,

    #[error("relay stream responder deadline is invalid: {field}")]
    InvalidDeadline { field: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config_from_getter(
        vars: &[(&'static str, &'static str)],
    ) -> Result<Option<RelayStreamResponderConfig>, RelayStreamResponderConfigError> {
        let vars: HashMap<&'static str, &'static str> = vars.iter().copied().collect();
        RelayStreamResponderConfig::from_getter(|name| {
            vars.get(name).map(|value| Ok((*value).to_string()))
        })
    }

    #[test]
    fn relay_stream_responder_config_is_default_off() {
        assert_eq!(
            RelayStreamResponderConfig::from_values(None, None, None, None, None).unwrap(),
            None
        );
        assert_eq!(
            RelayStreamResponderConfig::from_values(Some("false"), None, None, None, None).unwrap(),
            None
        );
        assert_eq!(
            RelayStreamResponderConfig::from_values(Some("0"), None, None, None, None).unwrap(),
            None
        );
    }

    #[test]
    fn relay_stream_responder_config_requires_bind_addr_when_enabled() {
        assert_eq!(
            RelayStreamResponderConfig::from_values(Some("true"), None, None, None, None),
            Err(RelayStreamResponderConfigError::BindAddrRequired)
        );
    }

    #[test]
    fn relay_stream_responder_config_accepts_loopback_literals() {
        let ipv4 = RelayStreamResponderConfig::from_values(
            Some("true"),
            Some("127.0.0.1:49152"),
            None,
            None,
            None,
        )
        .unwrap()
        .unwrap();
        assert!(ipv4.enabled);
        assert_eq!(ipv4.bind_addr, "127.0.0.1:49152".parse().unwrap());
        assert_eq!(ipv4.key_id, DEFAULT_RELAY_STREAM_NOISE_KEY_ID);
        assert_eq!(
            ipv4.auth_deadline,
            DEFAULT_RELAY_STREAM_RESPONDER_AUTH_DEADLINE
        );
        assert_eq!(
            ipv4.idle_timeout,
            DEFAULT_RELAY_STREAM_RESPONDER_IDLE_TIMEOUT
        );

        let ipv6 = RelayStreamResponderConfig::from_values(
            Some("on"),
            Some("[::1]:49153"),
            Some("engine.v1"),
            Some("20"),
            Some("600"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(ipv6.bind_addr, "[::1]:49153".parse().unwrap());
        assert_eq!(ipv6.key_id, "engine.v1");
        assert_eq!(ipv6.auth_deadline, Duration::from_secs(20));
        assert_eq!(ipv6.idle_timeout, Duration::from_secs(600));

        let localhost = RelayStreamResponderConfig::from_values(
            Some("yes"),
            Some("localhost:49154"),
            None,
            None,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(localhost.bind_addr, "127.0.0.1:49154".parse().unwrap());
    }

    #[test]
    fn relay_stream_responder_config_parses_env_round_trip() {
        let cfg = config_from_getter(&[
            (RELAY_STREAM_RESPONDER_ENABLE_ENV, "true"),
            (RELAY_STREAM_RESPONDER_BIND_ADDR_ENV, "127.0.0.1:49152"),
            (RELAY_STREAM_RESPONDER_KEY_ID_ENV, "engine:test"),
            (RELAY_STREAM_RESPONDER_AUTH_DEADLINE_SECS_ENV, "30"),
            (RELAY_STREAM_RESPONDER_IDLE_TIMEOUT_SECS_ENV, "900"),
        ])
        .unwrap()
        .unwrap();

        assert!(cfg.enabled);
        assert_eq!(cfg.bind_addr, "127.0.0.1:49152".parse().unwrap());
        assert_eq!(cfg.key_id, "engine:test");
        assert_eq!(cfg.auth_deadline, Duration::from_secs(30));
        assert_eq!(cfg.idle_timeout, Duration::from_secs(900));
    }

    #[test]
    fn relay_stream_responder_config_rejects_non_loopback_or_ambiguous_bind_addr() {
        for bind_addr in ["0.0.0.0:49152", "[::]:49152", "192.168.15.10:49152"] {
            assert_eq!(
                RelayStreamResponderConfig::from_values(
                    Some("true"),
                    Some(bind_addr),
                    None,
                    None,
                    None,
                ),
                Err(RelayStreamResponderConfigError::NonLoopbackBindAddr)
            );
        }

        assert_eq!(
            RelayStreamResponderConfig::from_values(
                Some("true"),
                Some("relay.example.test:49152"),
                None,
                None,
                None,
            ),
            Err(RelayStreamResponderConfigError::InvalidBindAddr)
        );
    }

    #[test]
    fn relay_stream_responder_config_rejects_invalid_port_key_id_and_enabled_flag() {
        assert_eq!(
            RelayStreamResponderConfig::from_values(
                Some("true"),
                Some("127.0.0.1:0"),
                None,
                None,
                None,
            ),
            Err(RelayStreamResponderConfigError::InvalidBindAddrPort)
        );
        assert_eq!(
            RelayStreamResponderConfig::from_values(
                Some("true"),
                Some("localhost:not-a-port"),
                None,
                None,
                None,
            ),
            Err(RelayStreamResponderConfigError::InvalidBindAddrPort)
        );
        assert_eq!(
            RelayStreamResponderConfig::from_values(
                Some("true"),
                Some("127.0.0.1:49152"),
                Some("../engine"),
                None,
                None,
            ),
            Err(RelayStreamResponderConfigError::InvalidKeyId)
        );
        assert_eq!(
            RelayStreamResponderConfig::from_values(
                Some("maybe"),
                Some("127.0.0.1:49152"),
                None,
                None,
                None,
            ),
            Err(RelayStreamResponderConfigError::InvalidEnabledFlag)
        );
    }

    #[test]
    fn relay_stream_responder_config_validates_deadline_bounds() {
        let too_long_auth = (MAX_RELAY_STREAM_RESPONDER_AUTH_DEADLINE.as_secs() + 1).to_string();
        let too_long_idle = (MAX_RELAY_STREAM_RESPONDER_IDLE_TIMEOUT.as_secs() + 1).to_string();

        assert_eq!(
            RelayStreamResponderConfig::from_values(
                Some("true"),
                Some("127.0.0.1:49152"),
                None,
                Some("0"),
                None,
            ),
            Err(RelayStreamResponderConfigError::InvalidDeadline {
                field: "auth_deadline"
            })
        );
        assert_eq!(
            RelayStreamResponderConfig::from_values(
                Some("true"),
                Some("127.0.0.1:49152"),
                None,
                Some(&too_long_auth),
                None,
            ),
            Err(RelayStreamResponderConfigError::InvalidDeadline {
                field: "auth_deadline"
            })
        );
        assert_eq!(
            RelayStreamResponderConfig::from_values(
                Some("true"),
                Some("127.0.0.1:49152"),
                None,
                None,
                Some("0"),
            ),
            Err(RelayStreamResponderConfigError::InvalidDeadline {
                field: "idle_timeout"
            })
        );
        assert_eq!(
            RelayStreamResponderConfig::from_values(
                Some("true"),
                Some("127.0.0.1:49152"),
                None,
                None,
                Some(&too_long_idle),
            ),
            Err(RelayStreamResponderConfigError::InvalidDeadline {
                field: "idle_timeout"
            })
        );
    }

    #[test]
    fn relay_stream_responder_config_debug_has_no_secret_material() {
        let cfg = RelayStreamResponderConfig::from_values(
            Some("true"),
            Some("127.0.0.1:49152"),
            Some("engine"),
            None,
            None,
        )
        .unwrap()
        .unwrap();
        let debug = format!("{cfg:?}");
        assert!(debug.contains("RelayStreamResponderConfig"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("token"));
        assert!(!debug.contains("secret"));
    }
}
