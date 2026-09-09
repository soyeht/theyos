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
use household_rs::claw_share::data_tunnel::PERSISTENT_MAX_BYTES_PER_DIRECTION;

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
pub const RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV: &str =
    "THEYOS_RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION";

/// Per-direction byte budget for the PUBLIC relay splice, and the POLICY
/// FLOOR any explicit override must meet (see `parse_byte_cap`). This is
/// Share public-relay POLICY — the generic listener default stays unlimited
/// (None) so legacy/IpTunnel callers are byte-identical; only this config
/// applies it.
///
/// This is a normal-path backstop against gross misconfiguration, NOT a
/// proof that the endpoint's typed `session-byte-budget-exhausted` always
/// fires before the relay's own cap. The relay is blind: it counts every
/// wire byte of the Noise-encrypted transport (AEAD tag + length framing on
/// EVERY message, plus `Health`/`Resize`/`Open`/`Close`/`Exit` control
/// frames), while the endpoint counts only `TunnelFrame::Data` payload
/// bytes. A peer that spams `Health` keepalives (unbounded — there is no
/// cap on how many round trips a session may do) can make the relay cut
/// first regardless of how large this margin is.
///
/// What actually bounds that WITHIN one session is the relay's own byte
/// cap (a hard close once total wire bytes — including the `Health` spam —
/// reach it) and `splice_max_lifetime` (a hard duration bound regardless of
/// activity pattern). `Health` traffic is activity, so it defers idle
/// timeout rather than being caught by it, and it never touches
/// `PERSISTENT_MAX_TARGET_OPENS` (that budget counts successful target
/// opens, not frames). The reopen limiter and the per-source
/// unpaired/pending/paired caps bound REPETITION and CONCURRENCY — a new
/// dial, or how many sessions run at once — not sustained activity inside
/// an already-authorized connection. This margin exists to catch the case
/// where a relay cap is configured smaller than what ordinary,
/// non-adversarial framing overhead requires for a single legitimate
/// 64 MiB transfer.
pub const DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION: u64 = 72 * 1024 * 1024;

/// Independent of `parse_byte_cap`'s runtime floor check: the default itself
/// must satisfy the invariant it becomes the floor for. Checking `bytes >=
/// DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION` alone would be tautological
/// here — a regression of the default to <= the endpoint budget would still
/// satisfy `bytes >= DEFAULT` for any config using the (now-broken) default,
/// and nothing would catch it. This compile-time assertion is that
/// independent check: it fails the BUILD, not a test, if the default ever
/// regresses.
const _: () = assert!(
    DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION > PERSISTENT_MAX_BYTES_PER_DIRECTION
);

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
                // 0 is explicitly rejected by parse_byte_cap: a public relay
                // may not run with the byte cap disabled.
                splice_max_bytes_per_direction: Some(parse_byte_cap(&get)?),
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

/// Parse the per-direction splice byte cap. Unset/empty means the safe
/// default (72 MiB). An explicit `0` is REJECTED in public mode: it would
/// either disable the cap or block every byte, and a public relay must run
/// with a real, finite budget.
///
/// The default and an explicit override are resolved to the same `bytes`
/// value FIRST, then zero and policy-floor validation apply uniformly to
/// that value — neither check may live only on the explicit-override
/// branch, or a future change to the default itself could silently ship a
/// value that violates its own floor.
///
/// The floor is `DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION`
/// (inclusive), not merely "greater than the endpoint's 64 MiB budget" — a
/// margin of a single byte over the endpoint budget is not enough to
/// absorb even ORDINARY per-message Noise/framing overhead for a
/// legitimate transfer (see the constant's doc comment for why this is a
/// backstop, not a proof of ordering).
fn parse_byte_cap(
    get: &impl Fn(&'static str) -> Option<Result<String, RelayStreamPublicRelayConfigError>>,
) -> Result<u64, RelayStreamPublicRelayConfigError> {
    let override_value = transpose_env(get(RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV))?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let bytes = match override_value {
        Some(value) => value.parse::<u64>().map_err(|_| {
            RelayStreamPublicRelayConfigError::InvalidNumber {
                field: RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV,
            }
        })?,
        None => DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION,
    };
    if bytes == 0 {
        return Err(RelayStreamPublicRelayConfigError::OutOfRange {
            field: RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV,
        });
    }
    if bytes < DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION {
        return Err(RelayStreamPublicRelayConfigError::RelayCapBelowPolicyFloor {
            relay_cap: bytes,
            policy_floor: DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION,
        });
    }
    Ok(bytes)
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

    /// A normal-path policy-floor backstop, not a proof that the endpoint's
    /// typed budget error always fires before the relay's own cap — see
    /// `DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION`'s doc comment.
    #[error(
        "relay_stream public relay splice byte cap ({relay_cap}) is below the policy floor \
         ({policy_floor}) — this is a backstop against gross misconfiguration, not a proof of \
         ordering against adversarial framing"
    )]
    RelayCapBelowPolicyFloor { relay_cap: u64, policy_floor: u64 },
}

#[cfg(test)]
mod tests;
