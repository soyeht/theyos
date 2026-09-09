#![cfg(test)]

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
fn public_relay_config_splice_byte_cap_defaults_and_forbids_zero() {
    // Unset: the safe default (72 MiB) applies.
    let config = config_from_getter(&[
        (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
        (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(
        config.listener.splice_max_bytes_per_direction,
        Some(DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION)
    );

    // Explicit override above the endpoint budget is honored.
    let config = config_from_getter(&[
        (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
        (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
        (
            RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV,
            "83886080",
        ),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(
        config.listener.splice_max_bytes_per_direction,
        Some(83_886_080)
    );

    // 0 is forbidden in public mode: the cap may not be disabled.
    assert_eq!(
        config_from_getter(&[
            (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
            (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
            (RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV, "0"),
        ])
        .unwrap_err(),
        RelayStreamPublicRelayConfigError::OutOfRange {
            field: RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV
        }
    );

    // Non-numeric is a config error, never a silent default.
    assert_eq!(
        config_from_getter(&[
            (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
            (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
            (
                RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV,
                "unlimited",
            ),
        ])
        .unwrap_err(),
        RelayStreamPublicRelayConfigError::InvalidNumber {
            field: RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV
        }
    );
}

#[test]
fn public_relay_config_rejects_relay_cap_below_policy_floor() {
    // A relay cap configured below the policy floor
    // (`DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION`, 72 MiB) must
    // fail configuration startup with a typed error. This is a
    // normal-path backstop against gross misconfiguration — it does
    // NOT prove the endpoint's typed budget error always fires before
    // the relay's own cap under adversarial framing (unbounded
    // `Health` keepalive spam in particular, see the constant's doc
    // comment for what actually bounds that: the relay's own byte cap
    // and `splice_max_lifetime` intra-session; the reopen limiter and
    // per-source caps bound repetition/concurrency, not sustained
    // activity within one already-authorized connection).

    // Exactly equal to the endpoint's own 64 MiB budget: forbidden,
    // same as before this revision — nowhere near the policy floor.
    assert_eq!(
        config_from_getter(&[
            (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
            (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
            (
                RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV,
                "67108864",
            ),
        ])
        .unwrap_err(),
        RelayStreamPublicRelayConfigError::RelayCapBelowPolicyFloor {
            relay_cap: PERSISTENT_MAX_BYTES_PER_DIRECTION,
            policy_floor: DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION,
        }
    );

    // One byte above the endpoint's 64 MiB budget: this used to be the
    // accepted boundary under the old "strictly greater than the
    // endpoint budget" property. It is NOT enough margin to absorb
    // even ordinary per-message Noise/framing overhead for a single
    // legitimate transfer, so it must now be forbidden too.
    assert_eq!(
        config_from_getter(&[
            (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
            (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
            (
                RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV,
                "67108865",
            ),
        ])
        .unwrap_err(),
        RelayStreamPublicRelayConfigError::RelayCapBelowPolicyFloor {
            relay_cap: PERSISTENT_MAX_BYTES_PER_DIRECTION + 1,
            policy_floor: DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION,
        }
    );

    // Well below the endpoint budget (the value this test used to
    // accept, before either invariant existed): also forbidden.
    assert_eq!(
        config_from_getter(&[
            (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
            (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
            (
                RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV,
                "1048576",
            ),
        ])
        .unwrap_err(),
        RelayStreamPublicRelayConfigError::RelayCapBelowPolicyFloor {
            relay_cap: 1_048_576,
            policy_floor: DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION,
        }
    );

    // One byte BELOW the policy floor itself: still forbidden — the
    // floor is inclusive, not "greater than the floor".
    assert_eq!(
        config_from_getter(&[
            (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
            (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
            (
                RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV,
                "75497471",
            ),
        ])
        .unwrap_err(),
        RelayStreamPublicRelayConfigError::RelayCapBelowPolicyFloor {
            relay_cap: DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION - 1,
            policy_floor: DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION,
        }
    );

    // The policy floor exactly: accepted — the floor is inclusive.
    let config = config_from_getter(&[
        (RELAY_STREAM_PUBLIC_RELAY_ENV, "1"),
        (RELAY_STREAM_PUBLIC_BIND_ADDR_ENV, "192.168.15.10:49152"),
        (
            RELAY_STREAM_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION_ENV,
            "75497472",
        ),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(
        config.listener.splice_max_bytes_per_direction,
        Some(DEFAULT_PUBLIC_SPLICE_MAX_BYTES_PER_DIRECTION)
    );

    // The default itself must satisfy its own floor — proven at
    // runtime by `public_relay_config_splice_byte_cap_defaults_and_forbids_zero`'s
    // unset-env case succeeding through this same `bytes >= floor`
    // check. `const _: () = assert!(...)` right after the constant's
    // definition is the INDEPENDENT check for this: it fails the BUILD
    // if the default ever regresses below the endpoint's 64 MiB
    // budget, so a regression cannot hide behind this runtime check
    // becoming tautological (`bytes >= DEFAULT` trivially holds for
    // any config using a broken default, no matter how broken).
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
