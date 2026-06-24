//! Default-off configuration surface for the standalone public `relay_stream`
//! rendezvous helper.
//!
//! This module is pure env parsing and validation. It does not bind sockets,
//! spawn the helper, read household state, publish catalog entries, or touch
//! router/firewall configuration.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::claw_share_relay_stream_abuse::RelayAbuseConfig;
use crate::claw_share_rendezvous_stream_relay_listener::RendezvousStreamRelayListenerConfig;

pub const RELAY_STREAM_PUBLIC_RELAY_ENV: &str = "THEYOS_RELAY_STREAM_PUBLIC_RELAY";
pub const RELAY_STREAM_PUBLIC_BIND_ADDR_ENV: &str = "THEYOS_RELAY_STREAM_PUBLIC_BIND_ADDR";
pub const RELAY_STREAM_PUBLIC_HELLO_TIMEOUT_SECS_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_HELLO_TIMEOUT_SECS";
pub const RELAY_STREAM_PUBLIC_TOKEN_TTL_SECS_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_TOKEN_TTL_SECS";
pub const RELAY_STREAM_PUBLIC_MAX_PENDING_ENV: &str = "THEYOS_RELAY_STREAM_PUBLIC_MAX_PENDING";
pub const RELAY_STREAM_PUBLIC_MAX_ACTIVE_CONNECTIONS_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_MAX_ACTIVE_CONNECTIONS";
pub const RELAY_STREAM_PUBLIC_REAPER_INTERVAL_SECS_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_REAPER_INTERVAL_SECS";
pub const RELAY_STREAM_PUBLIC_SPLICE_IDLE_TIMEOUT_SECS_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_SPLICE_IDLE_TIMEOUT_SECS";
pub const RELAY_STREAM_PUBLIC_SPLICE_MAX_LIFETIME_SECS_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_SPLICE_MAX_LIFETIME_SECS";

pub const RELAY_STREAM_PUBLIC_MAX_UNPAIRED_ACTIVE_PER_SOURCE_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_MAX_UNPAIRED_ACTIVE_PER_SOURCE";
pub const RELAY_STREAM_PUBLIC_MAX_PENDING_PER_SOURCE_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_MAX_PENDING_PER_SOURCE";
pub const RELAY_STREAM_PUBLIC_MAX_HELLO_ATTEMPTS_PER_SOURCE_PER_WINDOW_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_MAX_HELLO_ATTEMPTS_PER_SOURCE_PER_WINDOW";
pub const RELAY_STREAM_PUBLIC_MAX_FAILED_HELLOS_PER_SOURCE_PER_WINDOW_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_MAX_FAILED_HELLOS_PER_SOURCE_PER_WINDOW";
pub const RELAY_STREAM_PUBLIC_MAX_PAIRED_SPLICES_PER_SOURCE_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_MAX_PAIRED_SPLICES_PER_SOURCE";
pub const RELAY_STREAM_PUBLIC_HELLO_ATTEMPT_WINDOW_SECS_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_HELLO_ATTEMPT_WINDOW_SECS";
pub const RELAY_STREAM_PUBLIC_SOURCE_STATE_TTL_SECS_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_SOURCE_STATE_TTL_SECS";
pub const RELAY_STREAM_PUBLIC_MAX_SOURCE_BUCKETS_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_MAX_SOURCE_BUCKETS";
pub const RELAY_STREAM_PUBLIC_IPV6_SOURCE_PREFIX_LEN_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_IPV6_SOURCE_PREFIX_LEN";
pub const RELAY_STREAM_PUBLIC_STATUS_BIND_ADDR_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_STATUS_BIND_ADDR";
pub const RELAY_STREAM_PUBLIC_STATUS_TOKEN_FILE_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_STATUS_TOKEN_FILE";

const MAX_COUNT: usize = 1_000_000;
const MAX_RATE: u32 = 1_000_000;
const MAX_HELLO_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_TOKEN_TTL: Duration = Duration::from_secs(3600);
const MAX_REAPER_INTERVAL: Duration = Duration::from_secs(3600);
const MAX_SPLICE_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_SPLICE_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_SOURCE_STATE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_HELLO_ATTEMPT_WINDOW: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStreamPublicRelayConfig {
    pub bind_addr: SocketAddr,
    pub listener: RendezvousStreamRelayListenerConfig,
    pub status: Option<RelayStreamPublicRelayStatusConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStreamPublicRelayStatusConfig {
    pub bind_addr: SocketAddr,
    pub token_file: PathBuf,
}

impl RelayStreamPublicRelayConfig {
    pub fn from_env() -> Result<Option<Self>, RelayStreamPublicRelayConfigError> {
        Self::from_getter(read_env)
    }

    pub fn from_getter(
        get: impl Fn(&'static str) -> Option<Result<String, RelayStreamPublicRelayConfigError>>,
    ) -> Result<Option<Self>, RelayStreamPublicRelayConfigError> {
        let enabled = transpose_env(get(RELAY_STREAM_PUBLIC_RELAY_ENV))?;
        if !parse_enabled(enabled.as_deref())? {
            return Ok(None);
        }

        let bind_addr = env_string(&get, RELAY_STREAM_PUBLIC_BIND_ADDR_ENV)?;
        let listener_defaults = RendezvousStreamRelayListenerConfig::default();
        let abuse_defaults = RelayAbuseConfig::default();

        let splice_max_lifetime = parse_duration_secs(
            &get,
            RELAY_STREAM_PUBLIC_SPLICE_MAX_LIFETIME_SECS_ENV,
            listener_defaults.splice_max_lifetime,
            MAX_SPLICE_LIFETIME,
        )?;

        let abuse = RelayAbuseConfig {
            max_unpaired_active_per_source: parse_usize(
                &get,
                RELAY_STREAM_PUBLIC_MAX_UNPAIRED_ACTIVE_PER_SOURCE_ENV,
                abuse_defaults.max_unpaired_active_per_source,
                MAX_COUNT,
            )?,
            max_pending_per_source: parse_usize(
                &get,
                RELAY_STREAM_PUBLIC_MAX_PENDING_PER_SOURCE_ENV,
                abuse_defaults.max_pending_per_source,
                MAX_COUNT,
            )?,
            max_hello_attempts_per_source_per_window: parse_u32(
                &get,
                RELAY_STREAM_PUBLIC_MAX_HELLO_ATTEMPTS_PER_SOURCE_PER_WINDOW_ENV,
                abuse_defaults.max_hello_attempts_per_source_per_window,
                MAX_RATE,
            )?,
            max_failed_hellos_per_source_per_window: parse_u32(
                &get,
                RELAY_STREAM_PUBLIC_MAX_FAILED_HELLOS_PER_SOURCE_PER_WINDOW_ENV,
                abuse_defaults.max_failed_hellos_per_source_per_window,
                MAX_RATE,
            )?,
            max_paired_splices_per_source: parse_optional_usize(
                &get,
                RELAY_STREAM_PUBLIC_MAX_PAIRED_SPLICES_PER_SOURCE_ENV,
                abuse_defaults.max_paired_splices_per_source,
                MAX_COUNT,
            )?,
            hello_attempt_window: parse_duration_secs(
                &get,
                RELAY_STREAM_PUBLIC_HELLO_ATTEMPT_WINDOW_SECS_ENV,
                abuse_defaults.hello_attempt_window,
                MAX_HELLO_ATTEMPT_WINDOW,
            )?,
            source_state_ttl: parse_duration_secs(
                &get,
                RELAY_STREAM_PUBLIC_SOURCE_STATE_TTL_SECS_ENV,
                abuse_defaults.source_state_ttl,
                MAX_SOURCE_STATE_TTL,
            )?,
            max_source_buckets: parse_usize(
                &get,
                RELAY_STREAM_PUBLIC_MAX_SOURCE_BUCKETS_ENV,
                abuse_defaults.max_source_buckets,
                MAX_COUNT,
            )?,
            max_splice_lifetime: splice_max_lifetime,
            ipv6_source_prefix_len: parse_ipv6_prefix_len(
                &get,
                RELAY_STREAM_PUBLIC_IPV6_SOURCE_PREFIX_LEN_ENV,
                abuse_defaults.ipv6_source_prefix_len,
            )?,
        };

        Ok(Some(Self {
            bind_addr: parse_public_bind_addr(&bind_addr)?,
            status: parse_status_config(&get)?,
            listener: RendezvousStreamRelayListenerConfig {
                hello_timeout: parse_duration_secs(
                    &get,
                    RELAY_STREAM_PUBLIC_HELLO_TIMEOUT_SECS_ENV,
                    listener_defaults.hello_timeout,
                    MAX_HELLO_TIMEOUT,
                )?,
                token_ttl: parse_duration_secs(
                    &get,
                    RELAY_STREAM_PUBLIC_TOKEN_TTL_SECS_ENV,
                    listener_defaults.token_ttl,
                    MAX_TOKEN_TTL,
                )?,
                max_pending: parse_usize(
                    &get,
                    RELAY_STREAM_PUBLIC_MAX_PENDING_ENV,
                    listener_defaults.max_pending,
                    MAX_COUNT,
                )?,
                max_active_connections: parse_usize(
                    &get,
                    RELAY_STREAM_PUBLIC_MAX_ACTIVE_CONNECTIONS_ENV,
                    listener_defaults.max_active_connections,
                    MAX_COUNT,
                )?,
                reaper_interval: parse_duration_secs(
                    &get,
                    RELAY_STREAM_PUBLIC_REAPER_INTERVAL_SECS_ENV,
                    listener_defaults.reaper_interval,
                    MAX_REAPER_INTERVAL,
                )?,
                splice_idle_timeout: parse_duration_secs(
                    &get,
                    RELAY_STREAM_PUBLIC_SPLICE_IDLE_TIMEOUT_SECS_ENV,
                    listener_defaults.splice_idle_timeout,
                    MAX_SPLICE_IDLE_TIMEOUT,
                )?,
                splice_max_lifetime,
                abuse,
            },
        }))
    }
}

fn parse_status_config(
    get: &impl Fn(&'static str) -> Option<Result<String, RelayStreamPublicRelayConfigError>>,
) -> Result<Option<RelayStreamPublicRelayStatusConfig>, RelayStreamPublicRelayConfigError> {
    let bind_addr = optional_env_string(get, RELAY_STREAM_PUBLIC_STATUS_BIND_ADDR_ENV)?;
    let token_file = optional_env_string(get, RELAY_STREAM_PUBLIC_STATUS_TOKEN_FILE_ENV)?;

    match (bind_addr, token_file) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(RelayStreamPublicRelayConfigError::StatusBindAddrRequired),
        (Some(_), None) => Err(RelayStreamPublicRelayConfigError::StatusTokenFileRequired),
        (Some(bind_addr), Some(token_file)) => Ok(Some(RelayStreamPublicRelayStatusConfig {
            bind_addr: parse_status_bind_addr(&bind_addr)?,
            token_file: PathBuf::from(token_file),
        })),
    }
}

fn read_env(name: &'static str) -> Option<Result<String, RelayStreamPublicRelayConfigError>> {
    match std::env::var(name) {
        Ok(value) => Some(Ok(value)),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => Some(Err(
            RelayStreamPublicRelayConfigError::EnvVarNotUnicode(name),
        )),
    }
}

fn env_string(
    get: &impl Fn(&'static str) -> Option<Result<String, RelayStreamPublicRelayConfigError>>,
    name: &'static str,
) -> Result<String, RelayStreamPublicRelayConfigError> {
    let value = transpose_env(get(name))?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(RelayStreamPublicRelayConfigError::BindAddrRequired)?;
    Ok(value)
}

fn optional_env_string(
    get: &impl Fn(&'static str) -> Option<Result<String, RelayStreamPublicRelayConfigError>>,
    name: &'static str,
) -> Result<Option<String>, RelayStreamPublicRelayConfigError> {
    Ok(transpose_env(get(name))?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn transpose_env(
    value: Option<Result<String, RelayStreamPublicRelayConfigError>>,
) -> Result<Option<String>, RelayStreamPublicRelayConfigError> {
    value.transpose()
}

fn parse_enabled(value: Option<&str>) -> Result<bool, RelayStreamPublicRelayConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(false);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(RelayStreamPublicRelayConfigError::InvalidEnabledFlag),
    }
}

fn parse_public_bind_addr(raw: &str) -> Result<SocketAddr, RelayStreamPublicRelayConfigError> {
    let addr = raw
        .parse::<SocketAddr>()
        .map_err(|_| RelayStreamPublicRelayConfigError::InvalidBindAddr)?;
    if addr.port() == 0 {
        return Err(RelayStreamPublicRelayConfigError::InvalidBindAddrPort);
    }
    if addr.ip().is_loopback() {
        return Err(RelayStreamPublicRelayConfigError::LoopbackBindAddr);
    }
    if addr.ip().is_unspecified() {
        return Err(RelayStreamPublicRelayConfigError::WildcardBindAddr);
    }
    Ok(addr)
}

fn parse_status_bind_addr(raw: &str) -> Result<SocketAddr, RelayStreamPublicRelayConfigError> {
    let addr = raw
        .parse::<SocketAddr>()
        .map_err(|_| RelayStreamPublicRelayConfigError::InvalidStatusBindAddr)?;
    if addr.port() == 0 {
        return Err(RelayStreamPublicRelayConfigError::InvalidStatusBindAddrPort);
    }
    if !addr.ip().is_loopback() {
        return Err(RelayStreamPublicRelayConfigError::NonLoopbackStatusBindAddr);
    }
    Ok(addr)
}

fn parse_duration_secs(
    get: &impl Fn(&'static str) -> Option<Result<String, RelayStreamPublicRelayConfigError>>,
    name: &'static str,
    default: Duration,
    max: Duration,
) -> Result<Duration, RelayStreamPublicRelayConfigError> {
    let Some(value) = transpose_env(get(name))?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(default);
    };
    let seconds = value
        .parse::<u64>()
        .map_err(|_| RelayStreamPublicRelayConfigError::InvalidNumber { field: name })?;
    let duration = Duration::from_secs(seconds);
    if duration.is_zero() || duration > max {
        return Err(RelayStreamPublicRelayConfigError::OutOfRange { field: name });
    }
    Ok(duration)
}

fn parse_usize(
    get: &impl Fn(&'static str) -> Option<Result<String, RelayStreamPublicRelayConfigError>>,
    name: &'static str,
    default: usize,
    max: usize,
) -> Result<usize, RelayStreamPublicRelayConfigError> {
    let Some(value) = transpose_env(get(name))?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(default);
    };
    let value = value
        .parse::<usize>()
        .map_err(|_| RelayStreamPublicRelayConfigError::InvalidNumber { field: name })?;
    if value == 0 || value > max {
        return Err(RelayStreamPublicRelayConfigError::OutOfRange { field: name });
    }
    Ok(value)
}

fn parse_u32(
    get: &impl Fn(&'static str) -> Option<Result<String, RelayStreamPublicRelayConfigError>>,
    name: &'static str,
    default: u32,
    max: u32,
) -> Result<u32, RelayStreamPublicRelayConfigError> {
    let Some(value) = transpose_env(get(name))?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(default);
    };
    let value = value
        .parse::<u32>()
        .map_err(|_| RelayStreamPublicRelayConfigError::InvalidNumber { field: name })?;
    if value == 0 || value > max {
        return Err(RelayStreamPublicRelayConfigError::OutOfRange { field: name });
    }
    Ok(value)
}

fn parse_optional_usize(
    get: &impl Fn(&'static str) -> Option<Result<String, RelayStreamPublicRelayConfigError>>,
    name: &'static str,
    default: Option<usize>,
    max: usize,
) -> Result<Option<usize>, RelayStreamPublicRelayConfigError> {
    let Some(value) = transpose_env(get(name))?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(default);
    };
    if matches!(value.to_ascii_lowercase().as_str(), "disabled" | "none") {
        return Ok(None);
    }
    let value = value
        .parse::<usize>()
        .map_err(|_| RelayStreamPublicRelayConfigError::InvalidNumber { field: name })?;
    if value == 0 || value > max {
        return Err(RelayStreamPublicRelayConfigError::OutOfRange { field: name });
    }
    Ok(Some(value))
}

fn parse_ipv6_prefix_len(
    get: &impl Fn(&'static str) -> Option<Result<String, RelayStreamPublicRelayConfigError>>,
    name: &'static str,
    default: u8,
) -> Result<u8, RelayStreamPublicRelayConfigError> {
    let Some(value) = transpose_env(get(name))?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(default);
    };
    let value = value
        .parse::<u8>()
        .map_err(|_| RelayStreamPublicRelayConfigError::InvalidNumber { field: name })?;
    if value > 128 {
        return Err(RelayStreamPublicRelayConfigError::OutOfRange { field: name });
    }
    Ok(value)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayStreamPublicRelayConfigError {
    #[error("relay_stream public relay env var is not unicode: {0}")]
    EnvVarNotUnicode(&'static str),

    #[error("relay_stream public relay enabled flag is invalid")]
    InvalidEnabledFlag,

    #[error("relay_stream public relay bind address is required")]
    BindAddrRequired,

    #[error("relay_stream public relay bind address is invalid")]
    InvalidBindAddr,

    #[error("relay_stream public relay bind address must not be loopback")]
    LoopbackBindAddr,

    #[error("relay_stream public relay bind address must not be wildcard")]
    WildcardBindAddr,

    #[error("relay_stream public relay bind address port is invalid")]
    InvalidBindAddrPort,

    #[error("relay_stream public relay status bind address is required")]
    StatusBindAddrRequired,

    #[error("relay_stream public relay status token file is required")]
    StatusTokenFileRequired,

    #[error("relay_stream public relay status bind address is invalid")]
    InvalidStatusBindAddr,

    #[error("relay_stream public relay status bind address must be loopback")]
    NonLoopbackStatusBindAddr,

    #[error("relay_stream public relay status bind address port is invalid")]
    InvalidStatusBindAddrPort,

    #[error("relay_stream public relay numeric field is invalid: {field}")]
    InvalidNumber { field: &'static str },

    #[error("relay_stream public relay numeric field is out of range: {field}")]
    OutOfRange { field: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config_from_getter(
        vars: &[(&'static str, &'static str)],
    ) -> Result<Option<RelayStreamPublicRelayConfig>, RelayStreamPublicRelayConfigError> {
        let vars: HashMap<&'static str, &'static str> = vars.iter().copied().collect();
        RelayStreamPublicRelayConfig::from_getter(|name| {
            vars.get(name).map(|value| Ok((*value).to_string()))
        })
    }

    #[test]
    fn public_relay_config_is_default_off() {
        assert_eq!(config_from_getter(&[]).unwrap(), None);
        assert_eq!(
            config_from_getter(&[(RELAY_STREAM_PUBLIC_RELAY_ENV, "false")]).unwrap(),
            None
        );
    }

    #[test]
    fn public_relay_config_requires_explicit_valid_enable_flag() {
        for value in ["maybe", "on", "yes"] {
            assert_eq!(
                config_from_getter(&[(RELAY_STREAM_PUBLIC_RELAY_ENV, value)]).unwrap_err(),
                RelayStreamPublicRelayConfigError::InvalidEnabledFlag
            );
        }
    }

    #[test]
    fn public_relay_config_requires_bind_addr_when_enabled() {
        assert_eq!(
            config_from_getter(&[(RELAY_STREAM_PUBLIC_RELAY_ENV, "1")]).unwrap_err(),
            RelayStreamPublicRelayConfigError::BindAddrRequired
        );
    }

    #[test]
    fn public_relay_config_rejects_loopback_wildcard_hostname_and_zero_port() {
        for (addr, err) in [
            (
                "127.0.0.1:49152",
                RelayStreamPublicRelayConfigError::LoopbackBindAddr,
            ),
            (
                "0.0.0.0:49152",
                RelayStreamPublicRelayConfigError::WildcardBindAddr,
            ),
            (
                "relay.example.test:49152",
                RelayStreamPublicRelayConfigError::InvalidBindAddr,
            ),
            (
                "192.168.15.10:0",
                RelayStreamPublicRelayConfigError::InvalidBindAddrPort,
            ),
        ] {
            assert_eq!(
                config_from_getter(&[
                    (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
                    (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, addr),
                ])
                .unwrap_err(),
                err
            );
        }
    }

    #[test]
    fn public_relay_config_accepts_explicit_non_loopback_literal() {
        let config = config_from_getter(&[
            (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
            (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(config.bind_addr, "192.168.15.10:49152".parse().unwrap());
        assert_eq!(
            config.listener.abuse.max_unpaired_active_per_source,
            RelayAbuseConfig::default().max_unpaired_active_per_source
        );
        assert_eq!(
            config.listener.splice_max_lifetime,
            config.listener.abuse.max_splice_lifetime
        );
        assert_eq!(config.status, None);
    }

    #[test]
    fn public_relay_config_overrides_abuse_and_listener_bounds() {
        let config = config_from_getter(&[
            (RELAY_STREAM_PUBLIC_RELAY_ENV, "true"),
            (
                RELAY_STREAM_PUBLIC_BIND_ADDR_ENV,
                "[2001:4860:4860::8888]:49152",
            ),
            (RELAY_STREAM_PUBLIC_HELLO_TIMEOUT_SECS_ENV, "7"),
            (RELAY_STREAM_PUBLIC_TOKEN_TTL_SECS_ENV, "90"),
            (RELAY_STREAM_PUBLIC_MAX_PENDING_ENV, "33"),
            (RELAY_STREAM_PUBLIC_MAX_ACTIVE_CONNECTIONS_ENV, "44"),
            (RELAY_STREAM_PUBLIC_REAPER_INTERVAL_SECS_ENV, "5"),
            (RELAY_STREAM_PUBLIC_SPLICE_IDLE_TIMEOUT_SECS_ENV, "120"),
            (RELAY_STREAM_PUBLIC_SPLICE_MAX_LIFETIME_SECS_ENV, "1800"),
            (RELAY_STREAM_PUBLIC_MAX_UNPAIRED_ACTIVE_PER_SOURCE_ENV, "9"),
            (RELAY_STREAM_PUBLIC_MAX_PENDING_PER_SOURCE_ENV, "10"),
            (
                RELAY_STREAM_PUBLIC_MAX_HELLO_ATTEMPTS_PER_SOURCE_PER_WINDOW_ENV,
                "11",
            ),
            (
                RELAY_STREAM_PUBLIC_MAX_FAILED_HELLOS_PER_SOURCE_PER_WINDOW_ENV,
                "12",
            ),
            (RELAY_STREAM_PUBLIC_MAX_PAIRED_SPLICES_PER_SOURCE_ENV, "13"),
            (RELAY_STREAM_PUBLIC_HELLO_ATTEMPT_WINDOW_SECS_ENV, "14"),
            (RELAY_STREAM_PUBLIC_SOURCE_STATE_TTL_SECS_ENV, "15"),
            (RELAY_STREAM_PUBLIC_MAX_SOURCE_BUCKETS_ENV, "16"),
            (RELAY_STREAM_PUBLIC_IPV6_SOURCE_PREFIX_LEN_ENV, "56"),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(config.listener.hello_timeout, Duration::from_secs(7));
        assert_eq!(config.listener.token_ttl, Duration::from_secs(90));
        assert_eq!(config.listener.max_pending, 33);
        assert_eq!(config.listener.max_active_connections, 44);
        assert_eq!(config.listener.reaper_interval, Duration::from_secs(5));
        assert_eq!(
            config.listener.splice_idle_timeout,
            Duration::from_secs(120)
        );
        assert_eq!(
            config.listener.splice_max_lifetime,
            Duration::from_secs(1800)
        );
        assert_eq!(config.listener.abuse.max_unpaired_active_per_source, 9);
        assert_eq!(config.listener.abuse.max_pending_per_source, 10);
        assert_eq!(
            config
                .listener
                .abuse
                .max_hello_attempts_per_source_per_window,
            11
        );
        assert_eq!(
            config
                .listener
                .abuse
                .max_failed_hellos_per_source_per_window,
            12
        );
        assert_eq!(
            config.listener.abuse.max_paired_splices_per_source,
            Some(13)
        );
        assert_eq!(
            config.listener.abuse.hello_attempt_window,
            Duration::from_secs(14)
        );
        assert_eq!(
            config.listener.abuse.source_state_ttl,
            Duration::from_secs(15)
        );
        assert_eq!(config.listener.abuse.max_source_buckets, 16);
        assert_eq!(config.listener.abuse.ipv6_source_prefix_len, 56);
    }

    #[test]
    fn public_relay_config_paired_cap_disable_requires_explicit_word() {
        let disabled = config_from_getter(&[
            (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
            (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
            (
                RELAY_STREAM_PUBLIC_MAX_PAIRED_SPLICES_PER_SOURCE_ENV,
                "disabled",
            ),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(disabled.listener.abuse.max_paired_splices_per_source, None);

        assert_eq!(
            config_from_getter(&[
                (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
                (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
                (RELAY_STREAM_PUBLIC_MAX_PAIRED_SPLICES_PER_SOURCE_ENV, "0"),
            ])
            .unwrap_err(),
            RelayStreamPublicRelayConfigError::OutOfRange {
                field: RELAY_STREAM_PUBLIC_MAX_PAIRED_SPLICES_PER_SOURCE_ENV
            }
        );
    }

    #[test]
    fn public_relay_config_rejects_zero_or_out_of_range_overrides() {
        assert_eq!(
            config_from_getter(&[
                (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
                (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
                (RELAY_STREAM_PUBLIC_MAX_UNPAIRED_ACTIVE_PER_SOURCE_ENV, "0"),
            ])
            .unwrap_err(),
            RelayStreamPublicRelayConfigError::OutOfRange {
                field: RELAY_STREAM_PUBLIC_MAX_UNPAIRED_ACTIVE_PER_SOURCE_ENV
            }
        );
        assert_eq!(
            config_from_getter(&[
                (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
                (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
                (RELAY_STREAM_PUBLIC_IPV6_SOURCE_PREFIX_LEN_ENV, "129"),
            ])
            .unwrap_err(),
            RelayStreamPublicRelayConfigError::OutOfRange {
                field: RELAY_STREAM_PUBLIC_IPV6_SOURCE_PREFIX_LEN_ENV
            }
        );
    }

    #[test]
    fn public_relay_config_status_endpoint_is_optional_loopback_and_authenticated() {
        let config = config_from_getter(&[
            (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
            (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
            (RELAY_STREAM_PUBLIC_STATUS_BIND_ADDR_ENV, "127.0.0.1:49153"),
            (
                RELAY_STREAM_PUBLIC_STATUS_TOKEN_FILE_ENV,
                "/tmp/relay-status-token",
            ),
        ])
        .unwrap()
        .unwrap();

        let status = config.status.unwrap();
        assert_eq!(status.bind_addr, "127.0.0.1:49153".parse().unwrap());
        assert_eq!(status.token_file, PathBuf::from("/tmp/relay-status-token"));
    }

    #[test]
    fn public_relay_config_status_endpoint_fails_closed() {
        assert_eq!(
            config_from_getter(&[
                (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
                (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
                (
                    RELAY_STREAM_PUBLIC_STATUS_TOKEN_FILE_ENV,
                    "/tmp/relay-status-token",
                ),
            ])
            .unwrap_err(),
            RelayStreamPublicRelayConfigError::StatusBindAddrRequired
        );
        assert_eq!(
            config_from_getter(&[
                (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
                (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
                (RELAY_STREAM_PUBLIC_STATUS_BIND_ADDR_ENV, "127.0.0.1:49153"),
            ])
            .unwrap_err(),
            RelayStreamPublicRelayConfigError::StatusTokenFileRequired
        );
        assert_eq!(
            config_from_getter(&[
                (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
                (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
                (
                    RELAY_STREAM_PUBLIC_STATUS_BIND_ADDR_ENV,
                    "192.168.15.10:49153",
                ),
                (
                    RELAY_STREAM_PUBLIC_STATUS_TOKEN_FILE_ENV,
                    "/tmp/relay-status-token",
                ),
            ])
            .unwrap_err(),
            RelayStreamPublicRelayConfigError::NonLoopbackStatusBindAddr
        );
        assert_eq!(
            config_from_getter(&[
                (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
                (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
                (RELAY_STREAM_PUBLIC_STATUS_BIND_ADDR_ENV, "localhost:49153"),
                (
                    RELAY_STREAM_PUBLIC_STATUS_TOKEN_FILE_ENV,
                    "/tmp/relay-status-token",
                ),
            ])
            .unwrap_err(),
            RelayStreamPublicRelayConfigError::InvalidStatusBindAddr
        );
    }
}
