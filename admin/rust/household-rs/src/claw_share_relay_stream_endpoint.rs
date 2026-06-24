//! Shared parser for the Product A `relay_stream` endpoint string.
//!
//! The relay stream offer carries its relay address as a `relay-stream://<addr>`
//! string (formatted host-side in `claw_share_relay_stream_mount`). The guest
//! (friend-cli) must turn that back into a dialable `(host, port)` to open a TCP
//! connection to the relay. This parser lives in household-rs so the same logic
//! is shared by the host formatter side and the guest dialer (C7c-2c) without
//! the guest depending on the engine crate.
//!
//! This cut is the PARSER ONLY — no Noise, no dial, no friend-cli wiring.
//!
//! IPv6 handling mirrors the robust bracket-aware endpoint parser: a `[host]:port`
//! literal is split on the closing bracket (so the address may carry colons and
//! an optional `%scope-id`); a bare `host:port` is split on its single colon and
//! an unbracketed IPv6 literal (more than one colon) is rejected. We deliberately
//! do NOT reuse the fragile `host:port` parser that rejects all brackets.

/// Mandatory scheme prefix for a relay stream endpoint string.
pub const RELAY_STREAM_SCHEME: &str = "relay-stream://";

/// Parse a `relay-stream://host:port` endpoint into its `(host, port)` parts.
///
/// The returned host preserves an IPv6 literal exactly as written inside the
/// brackets, including an optional `%scope-id`, but without the brackets
/// themselves. The port is validated to fit `u16`.
pub fn parse_relay_endpoint(s: &str) -> Result<(String, u16), RelayStreamEndpointParseError> {
    let rest = s
        .strip_prefix(RELAY_STREAM_SCHEME)
        .ok_or(RelayStreamEndpointParseError::WrongScheme)?;
    if rest.is_empty() {
        return Err(RelayStreamEndpointParseError::EmptyHost);
    }

    let (host, port_raw) = if let Some(after_open) = rest.strip_prefix('[') {
        // IPv6 literal (optionally with a `%scope-id`): `[host]:port`.
        let close = after_open
            .find(']')
            .ok_or(RelayStreamEndpointParseError::UnclosedBracket)?;
        let host = &after_open[..close];
        let after = &after_open[close + 1..];
        let port_raw = after
            .strip_prefix(':')
            .ok_or(RelayStreamEndpointParseError::MissingPort)?;
        (host, port_raw)
    } else {
        // `host:port` — reject a bare (unbracketed) IPv6 literal, which is
        // ambiguous with the host:port colon. Exactly one colon is required.
        match rest.matches(':').count() {
            1 => rest
                .rsplit_once(':')
                .ok_or(RelayStreamEndpointParseError::MissingPort)?,
            0 => return Err(RelayStreamEndpointParseError::MissingPort),
            _ => return Err(RelayStreamEndpointParseError::UnbracketedIpv6),
        }
    };

    if host.is_empty() {
        return Err(RelayStreamEndpointParseError::EmptyHost);
    }
    // A strict `u16` parse rejects an empty/non-numeric/out-of-range port and any
    // trailing garbage after the digits.
    let port: u16 = port_raw
        .parse()
        .map_err(|_| RelayStreamEndpointParseError::InvalidPort)?;

    Ok((host.to_string(), port))
}

/// Why a `relay-stream://` endpoint string failed to parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayStreamEndpointParseError {
    #[error("relay stream endpoint has the wrong scheme (expected relay-stream://)")]
    WrongScheme,

    #[error("relay stream endpoint host is empty")]
    EmptyHost,

    #[error("relay stream endpoint is missing a port")]
    MissingPort,

    #[error("relay stream endpoint port is invalid or out of range")]
    InvalidPort,

    #[error("relay stream endpoint IPv6 literal must be bracketed as [addr]:port")]
    UnbracketedIpv6,

    #[error("relay stream endpoint has an unclosed IPv6 bracket")]
    UnclosedBracket,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4() {
        assert_eq!(
            parse_relay_endpoint("relay-stream://127.0.0.1:49152").unwrap(),
            ("127.0.0.1".to_string(), 49152)
        );
    }

    #[test]
    fn parses_hostname() {
        assert_eq!(
            parse_relay_endpoint("relay-stream://example.com:49152").unwrap(),
            ("example.com".to_string(), 49152)
        );
    }

    #[test]
    fn parses_bracketed_ipv6() {
        assert_eq!(
            parse_relay_endpoint("relay-stream://[::1]:49152").unwrap(),
            ("::1".to_string(), 49152)
        );
    }

    #[test]
    fn parses_bracketed_ipv6_with_scope_id() {
        // The %scope-id is preserved verbatim in the host string.
        assert_eq!(
            parse_relay_endpoint("relay-stream://[fe80::1%lo0]:49152").unwrap(),
            ("fe80::1%lo0".to_string(), 49152)
        );
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert_eq!(
            parse_relay_endpoint("http://127.0.0.1:49152"),
            Err(RelayStreamEndpointParseError::WrongScheme)
        );
        // A single slash is not the scheme either.
        assert_eq!(
            parse_relay_endpoint("relay-stream:/127.0.0.1:49152"),
            Err(RelayStreamEndpointParseError::WrongScheme)
        );
        // No scheme at all.
        assert_eq!(
            parse_relay_endpoint("127.0.0.1:49152"),
            Err(RelayStreamEndpointParseError::WrongScheme)
        );
    }

    #[test]
    fn rejects_missing_port() {
        assert_eq!(
            parse_relay_endpoint("relay-stream://example.com"),
            Err(RelayStreamEndpointParseError::MissingPort)
        );
        // Bracketed host without a port.
        assert_eq!(
            parse_relay_endpoint("relay-stream://[::1]"),
            Err(RelayStreamEndpointParseError::MissingPort)
        );
    }

    #[test]
    fn rejects_invalid_or_out_of_range_port() {
        // Out of u16 range.
        assert_eq!(
            parse_relay_endpoint("relay-stream://example.com:70000"),
            Err(RelayStreamEndpointParseError::InvalidPort)
        );
        // Non-numeric.
        assert_eq!(
            parse_relay_endpoint("relay-stream://example.com:abc"),
            Err(RelayStreamEndpointParseError::InvalidPort)
        );
        // Empty port after the colon.
        assert_eq!(
            parse_relay_endpoint("relay-stream://example.com:"),
            Err(RelayStreamEndpointParseError::InvalidPort)
        );
        // Trailing garbage after the port digits.
        assert_eq!(
            parse_relay_endpoint("relay-stream://127.0.0.1:49152x"),
            Err(RelayStreamEndpointParseError::InvalidPort)
        );
    }

    #[test]
    fn rejects_unbracketed_ipv6() {
        assert_eq!(
            parse_relay_endpoint("relay-stream://fe80::1:49152"),
            Err(RelayStreamEndpointParseError::UnbracketedIpv6)
        );
        assert_eq!(
            parse_relay_endpoint("relay-stream://::1:49152"),
            Err(RelayStreamEndpointParseError::UnbracketedIpv6)
        );
    }

    #[test]
    fn rejects_empty_or_malformed_host() {
        // Empty authority after the scheme.
        assert_eq!(
            parse_relay_endpoint("relay-stream://"),
            Err(RelayStreamEndpointParseError::EmptyHost)
        );
        // Empty host with a port.
        assert_eq!(
            parse_relay_endpoint("relay-stream://:49152"),
            Err(RelayStreamEndpointParseError::EmptyHost)
        );
        // Empty bracketed host.
        assert_eq!(
            parse_relay_endpoint("relay-stream://[]:49152"),
            Err(RelayStreamEndpointParseError::EmptyHost)
        );
        // Unclosed bracket.
        assert_eq!(
            parse_relay_endpoint("relay-stream://[::1:49152"),
            Err(RelayStreamEndpointParseError::UnclosedBracket)
        );
    }
}
