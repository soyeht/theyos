//! Default-off relay dial config for mobile Claw VPN rendezvous preflight.
//!
//! This module only parses and validates configuration. It does not authorize
//! Mesh-C state, open sockets, write relay hellos, start Relay-R, install
//! routes, or mutate host networking.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use household_rs::keys::{P256PublicKey, P256Signature, verify_signature};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

pub const MOBILE_CLAW_VPN_RELAY_DIAL_ADDR_ENV: &str = "THEYOS_MOBILE_CLAW_VPN_RELAY_DIAL_ADDR";
pub const MOBILE_CLAW_VPN_RELAY_DIAL_ALLOW_NON_LOOPBACK_ENV: &str =
    "THEYOS_MOBILE_CLAW_VPN_RELAY_DIAL_ALLOW_NON_LOOPBACK";
pub const MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT_SECS_ENV: &str =
    "THEYOS_MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT_SECS";
pub const MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT_SECS_ENV: &str =
    "THEYOS_MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT_SECS";
pub const MOBILE_CLAW_VPN_RELAY_DIAL_PEER_IDENTITY_SHA256_ENV: &str =
    "THEYOS_MOBILE_CLAW_VPN_RELAY_DIAL_PEER_IDENTITY_SHA256";

pub const DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_MOBILE_CLAW_VPN_RELAY_DIAL_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_PEER_IDENTITY_SHA256_LEN: usize = 32;
const RELAY_PEER_IDENTITY_SHA256_HEX_LEN: usize = RELAY_PEER_IDENTITY_SHA256_LEN * 2;
pub(crate) const RELAY_AUTH_CHALLENGE_LEN: usize = 32;
const RELAY_AUTH_SIGNING_CONTEXT: &[u8] = b"theyos-mobile-claw-vpn-rendezvous-relay-auth-v1";

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MobileClawVpnRendezvousRelayDialConfig {
    pub(crate) relay_addr: Option<SocketAddr>,
    pub(crate) connect_timeout: Duration,
    pub(crate) hello_timeout: Duration,
    pub(crate) allow_non_loopback_relay_addr: bool,
    pub(crate) relay_peer_identity: Option<MobileClawVpnRendezvousRelayPeerIdentity>,
}

impl Default for MobileClawVpnRendezvousRelayDialConfig {
    fn default() -> Self {
        Self {
            relay_addr: None,
            connect_timeout: DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT,
            hello_timeout: DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT,
            allow_non_loopback_relay_addr: false,
            relay_peer_identity: None,
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
        let relay_peer_identity = if self.relay_peer_identity.is_some() {
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
            .field("relay_peer_identity", &relay_peer_identity)
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
        let relay_peer_identity =
            transpose_env(get(MOBILE_CLAW_VPN_RELAY_DIAL_PEER_IDENTITY_SHA256_ENV))?;

        Self::from_values(
            relay_addr.as_deref(),
            allow_non_loopback.as_deref(),
            connect_timeout.as_deref(),
            hello_timeout.as_deref(),
            relay_peer_identity.as_deref(),
        )
    }

    pub fn from_values(
        relay_addr: Option<&str>,
        allow_non_loopback: Option<&str>,
        connect_timeout_secs: Option<&str>,
        hello_timeout_secs: Option<&str>,
        relay_peer_identity_sha256: Option<&str>,
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
        let relay_peer_identity = parse_optional_relay_peer_identity(relay_peer_identity_sha256)?;

        let config = Self {
            relay_addr,
            connect_timeout,
            hello_timeout,
            allow_non_loopback_relay_addr,
            relay_peer_identity,
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
        relay_auth: Option<&MobileClawVpnRendezvousRelayAuthProof>,
    ) -> Result<Self, MobileClawVpnRendezvousRelayDialError> {
        let config = self.validate_for_dial()?;
        if let Some(relay_addr) = config.relay_addr {
            if !relay_addr.ip().is_loopback() {
                let Some(relay_peer_identity) = config.relay_peer_identity else {
                    return Err(MobileClawVpnRendezvousRelayDialError::RelayAuthRequired);
                };
                if !relay_auth
                    .is_some_and(|proof| proof.authorizes(relay_addr, relay_peer_identity))
                {
                    return Err(MobileClawVpnRendezvousRelayDialError::RelayAuthRequired);
                }
            }
        }
        Ok(config)
    }

    /// Mints a token-bearing dial proof from an already-authenticated
    /// non-loopback relay peer.
    ///
    /// This does not authenticate the peer by itself. It only consumes the
    /// opaque authenticated-peer capability produced only after the relay-auth
    /// handshake cryptographically proves the peer identity.
    pub fn relay_auth_proof_for_authenticated_non_loopback_peer(
        self,
        authenticated_peer: &MobileClawVpnRendezvousAuthenticatedRelayPeer,
    ) -> Result<MobileClawVpnRendezvousRelayAuthProof, MobileClawVpnRendezvousRelayDialError> {
        let config = self.validate_for_dial()?;
        let Some(relay_addr) = config.relay_addr else {
            return Err(MobileClawVpnRendezvousRelayDialError::RelayAuthRequired);
        };
        if relay_addr.ip().is_loopback() {
            return Err(MobileClawVpnRendezvousRelayDialError::RelayAuthRequired);
        }
        let Some(relay_peer_identity) = config.relay_peer_identity else {
            return Err(MobileClawVpnRendezvousRelayDialError::RelayAuthRequired);
        };
        if !authenticated_peer.authorizes(relay_addr, relay_peer_identity) {
            return Err(MobileClawVpnRendezvousRelayDialError::RelayAuthRequired);
        }
        Ok(MobileClawVpnRendezvousRelayAuthProof {
            relay_addr,
            relay_peer_identity,
        })
    }

    fn validate_config(self) -> Result<Self, MobileClawVpnRendezvousRelayDialConfigError> {
        if self.relay_addr.is_none() && self.relay_peer_identity.is_some() {
            return Err(
                MobileClawVpnRendezvousRelayDialConfigError::RelayPeerIdentityWithoutRelayAddr,
            );
        }
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

/// Opaque result of cryptographically authenticating a rendezvous relay peer.
///
/// This type is deliberately separate from configuration. Possessing a relay
/// address or expected identity does not create one; relay-auth code must mint
/// it only after the peer proves possession of the configured relay identity
/// key.
#[derive(PartialEq, Eq)]
pub struct MobileClawVpnRendezvousAuthenticatedRelayPeer {
    relay_addr: SocketAddr,
    relay_peer_identity: MobileClawVpnRendezvousRelayPeerIdentity,
}

impl MobileClawVpnRendezvousAuthenticatedRelayPeer {
    /// Verifies a relay proof-of-possession signature and returns an
    /// authenticated-peer capability bound to the exact socket address and
    /// identity key that produced it.
    ///
    /// This deliberately does not read configuration and does not mint a dial
    /// proof. The caller must still pass the returned capability through
    /// [`MobileClawVpnRendezvousRelayDialConfig::relay_auth_proof_for_authenticated_non_loopback_peer`],
    /// which compares the verified peer identity to the locally configured
    /// expectation before allowing token-bearing non-loopback dials.
    pub fn from_signed_challenge(
        relay_addr: SocketAddr,
        relay_public_key: &P256PublicKey,
        challenge: &MobileClawVpnRendezvousRelayAuthChallenge,
        signature: &P256Signature,
    ) -> Result<Self, MobileClawVpnRendezvousRelayDialError> {
        if relay_addr.ip().is_loopback() {
            return Err(MobileClawVpnRendezvousRelayDialError::RelayAuthRequired);
        }
        let signing_bytes = challenge.signing_bytes(relay_addr, relay_public_key);
        verify_signature(relay_public_key, &signing_bytes, signature)
            .map_err(|_| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;
        Ok(Self {
            relay_addr,
            relay_peer_identity: MobileClawVpnRendezvousRelayPeerIdentity::from_relay_public_key(
                relay_public_key,
            ),
        })
    }

    fn authorizes(
        &self,
        relay_addr: SocketAddr,
        relay_peer_identity: MobileClawVpnRendezvousRelayPeerIdentity,
    ) -> bool {
        self.relay_addr == relay_addr && self.relay_peer_identity == relay_peer_identity
    }

    #[cfg(test)]
    fn new_for_test(
        relay_addr: SocketAddr,
        relay_peer_identity: MobileClawVpnRendezvousRelayPeerIdentity,
    ) -> Self {
        Self {
            relay_addr,
            relay_peer_identity,
        }
    }
}

impl fmt::Debug for MobileClawVpnRendezvousAuthenticatedRelayPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileClawVpnRendezvousAuthenticatedRelayPeer")
            .field("kind", &"relay_peer_authenticated")
            .field("relay_addr", &"<redacted>")
            .field("relay_peer_identity", &"<redacted>")
            .finish()
    }
}

/// Fresh challenge bytes that the relay peer must sign before a token-bearing
/// non-loopback dial can be authorized.
///
/// The challenge is not secret, but its bytes are redacted to avoid accidental
/// copy/paste into logs and tickets. The production relay-auth handshake must
/// generate a fresh challenge for each peer authentication attempt.
pub struct MobileClawVpnRendezvousRelayAuthChallenge {
    nonce: [u8; RELAY_AUTH_CHALLENGE_LEN],
}

impl MobileClawVpnRendezvousRelayAuthChallenge {
    #[must_use]
    pub fn generate() -> Self {
        let mut nonce = [0_u8; RELAY_AUTH_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut nonce);
        Self { nonce }
    }

    /// Returns the exact domain-separated bytes a relay identity key must sign.
    ///
    /// The transcript binds the proof to the target socket address, challenge,
    /// and relay public key. A signature produced for one address cannot be
    /// replayed to authenticate another address.
    #[must_use]
    pub fn signing_bytes(
        &self,
        relay_addr: SocketAddr,
        relay_public_key: &P256PublicKey,
    ) -> Vec<u8> {
        relay_auth_signing_bytes(self, relay_addr, relay_public_key)
    }

    #[must_use]
    pub(crate) fn nonce_bytes(&self) -> &[u8; RELAY_AUTH_CHALLENGE_LEN] {
        &self.nonce
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_nonce_bytes(nonce: [u8; RELAY_AUTH_CHALLENGE_LEN]) -> Self {
        Self { nonce }
    }

    #[cfg(test)]
    fn new_for_test(nonce: [u8; RELAY_AUTH_CHALLENGE_LEN]) -> Self {
        Self { nonce }
    }
}

impl fmt::Debug for MobileClawVpnRendezvousRelayAuthChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileClawVpnRendezvousRelayAuthChallenge")
            .field("kind", &"relay_auth_challenge")
            .field("nonce", &"<redacted>")
            .finish()
    }
}

/// Opaque identity of the authenticated rendezvous relay peer.
///
/// This is a configuration-side expectation, not proof by itself. The future
/// relay-auth code must derive this identity cryptographically from the peer and
/// mint a proof bound to both this identity and the target address.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MobileClawVpnRendezvousRelayPeerIdentity {
    sha256: [u8; RELAY_PEER_IDENTITY_SHA256_LEN],
}

impl MobileClawVpnRendezvousRelayPeerIdentity {
    /// Derives the config-side relay peer identity from the authenticated relay
    /// public key bytes.
    ///
    /// This is not authorization by itself. It is the stable identity value that
    /// configuration stores and that an authenticated-peer capability must match
    /// before a non-loopback token-bearing dial is allowed.
    #[must_use]
    pub fn from_relay_public_key(relay_public_key: &P256PublicKey) -> Self {
        let digest = Sha256::digest(relay_public_key.as_bytes());
        let mut sha256 = [0_u8; RELAY_PEER_IDENTITY_SHA256_LEN];
        sha256.copy_from_slice(&digest);
        Self { sha256 }
    }
}

impl fmt::Debug for MobileClawVpnRendezvousRelayPeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileClawVpnRendezvousRelayPeerIdentity")
            .field("kind", &"relay_peer_identity_sha256")
            .field("sha256", &"<redacted>")
            .finish()
    }
}

/// Proof that a non-loopback rendezvous relay peer was authenticated before a
/// token-bearing hello is written.
///
/// This is intentionally opaque and is minted only from an authenticated relay
/// peer capability. Without that proof, non-loopback token-bearing dials remain
/// fail-closed with `relay_auth_required`. A proof authorizes only the exact
/// relay address and configured peer identity it was minted for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MobileClawVpnRendezvousRelayAuthProof {
    relay_addr: SocketAddr,
    relay_peer_identity: MobileClawVpnRendezvousRelayPeerIdentity,
}

impl MobileClawVpnRendezvousRelayAuthProof {
    fn authorizes(
        self,
        relay_addr: SocketAddr,
        relay_peer_identity: MobileClawVpnRendezvousRelayPeerIdentity,
    ) -> bool {
        self.relay_addr == relay_addr && self.relay_peer_identity == relay_peer_identity
    }

    #[cfg(test)]
    fn new_for_test(
        relay_addr: SocketAddr,
        relay_peer_identity: MobileClawVpnRendezvousRelayPeerIdentity,
    ) -> Self {
        Self {
            relay_addr,
            relay_peer_identity,
        }
    }
}

impl fmt::Debug for MobileClawVpnRendezvousRelayAuthProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileClawVpnRendezvousRelayAuthProof")
            .field("kind", &"relay_peer_authenticated")
            .field("relay_addr", &"<redacted>")
            .field("relay_peer_identity", &"<redacted>")
            .finish()
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

fn relay_auth_signing_bytes(
    challenge: &MobileClawVpnRendezvousRelayAuthChallenge,
    relay_addr: SocketAddr,
    relay_public_key: &P256PublicKey,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        RELAY_AUTH_SIGNING_CONTEXT.len()
            + 1
            + 1
            + 16
            + 2
            + RELAY_AUTH_CHALLENGE_LEN
            + P256PublicKey::LEN,
    );
    bytes.extend_from_slice(RELAY_AUTH_SIGNING_CONTEXT);
    bytes.push(0);
    match relay_addr.ip() {
        IpAddr::V4(ip) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(6);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    bytes.extend_from_slice(&relay_addr.port().to_be_bytes());
    bytes.extend_from_slice(&challenge.nonce);
    bytes.extend_from_slice(relay_public_key.as_bytes());
    bytes
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

fn parse_optional_relay_peer_identity(
    raw: Option<&str>,
) -> Result<
    Option<MobileClawVpnRendezvousRelayPeerIdentity>,
    MobileClawVpnRendezvousRelayDialConfigError,
> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if raw.len() != RELAY_PEER_IDENTITY_SHA256_HEX_LEN {
        return Err(MobileClawVpnRendezvousRelayDialConfigError::InvalidRelayPeerIdentity);
    }
    let mut sha256 = [0_u8; RELAY_PEER_IDENTITY_SHA256_LEN];
    for (byte, chunk) in sha256.iter_mut().zip(raw.as_bytes().chunks_exact(2)) {
        *byte = parse_hex_byte(chunk[0], chunk[1])?;
    }
    Ok(Some(MobileClawVpnRendezvousRelayPeerIdentity { sha256 }))
}

fn parse_hex_byte(high: u8, low: u8) -> Result<u8, MobileClawVpnRendezvousRelayDialConfigError> {
    let high = parse_hex_nibble(high)?;
    let low = parse_hex_nibble(low)?;
    Ok((high << 4) | low)
}

fn parse_hex_nibble(byte: u8) -> Result<u8, MobileClawVpnRendezvousRelayDialConfigError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(MobileClawVpnRendezvousRelayDialConfigError::InvalidRelayPeerIdentity),
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
    InvalidRelayPeerIdentity,
    RelayPeerIdentityWithoutRelayAddr,
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
            Self::InvalidRelayPeerIdentity => "invalid_relay_peer_identity",
            Self::RelayPeerIdentityWithoutRelayAddr => "relay_peer_identity_without_relay_addr",
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
            | MobileClawVpnRendezvousRelayDialConfigError::InvalidAllowNonLoopbackFlag
            | MobileClawVpnRendezvousRelayDialConfigError::InvalidRelayPeerIdentity
            | MobileClawVpnRendezvousRelayDialConfigError::RelayPeerIdentityWithoutRelayAddr => {
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
    use household_rs::keys::{IdentityKey, P256Keypair};

    const PEER_IDENTITY_A: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PEER_IDENTITY_B: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn mobile_claw_vpn_relay_dial_config_is_default_off() {
        let config =
            MobileClawVpnRendezvousRelayDialConfig::from_values(None, None, None, None, None)
                .unwrap();

        assert_eq!(config, MobileClawVpnRendezvousRelayDialConfig::default());
        assert!(!config.is_configured());
        assert!(format!("{config:?}").contains("relay_addr: \"None\""));
        assert!(format!("{config:?}").contains("relay_peer_identity: \"None\""));
    }

    #[test]
    fn mobile_claw_vpn_relay_dial_config_accepts_loopback_endpoint() {
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("127.0.0.1:49152"),
            None,
            Some("3"),
            Some("4"),
            None,
        )
        .unwrap();

        assert!(config.is_configured());
        assert_eq!(config.relay_addr, Some("127.0.0.1:49152".parse().unwrap()));
        assert_eq!(config.connect_timeout, Duration::from_secs(3));
        assert_eq!(config.hello_timeout, Duration::from_secs(4));
        assert!(!config.allow_non_loopback_relay_addr);
        assert_eq!(config.relay_peer_identity, None);
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
            None,
        )
        .unwrap();
        assert!(config.allow_non_loopback_relay_addr);
        assert_eq!(config.relay_peer_identity, None);
        assert!(!format!("{config:?}").contains("198.51.100.10"));
    }

    #[test]
    fn mobile_claw_vpn_relay_dial_token_bearing_non_loopback_requires_relay_auth() {
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("198.51.100.10:49152"),
            Some("true"),
            None,
            None,
            None,
        )
        .unwrap();

        let error = config.validate_for_token_bearing_dial(None).unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{config:?}").contains("198.51.100.10"));
        assert!(!format!("{error:?}").contains("198.51.100.10"));
        assert!(!error.to_string().contains("198.51.100.10"));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_proof_requires_configured_peer_identity() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("198.51.100.10:49152"),
            Some("true"),
            None,
            None,
            None,
        )
        .unwrap();
        let proof_identity = parse_optional_relay_peer_identity(Some(PEER_IDENTITY_A))
            .unwrap()
            .unwrap();
        let proof = MobileClawVpnRendezvousRelayAuthProof::new_for_test(relay_addr, proof_identity);

        let error = config
            .validate_for_token_bearing_dial(Some(&proof))
            .unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{config:?}").contains("198.51.100.10"));
        assert!(!format!("{proof:?}").contains(PEER_IDENTITY_A));
        assert!(!format!("{error:?}").contains("198.51.100.10"));
        assert!(!error.to_string().contains(PEER_IDENTITY_A));
    }

    #[test]
    fn mobile_claw_vpn_relay_dial_config_from_getter_reads_peer_identity() {
        let config = MobileClawVpnRendezvousRelayDialConfig::from_getter(|name| match name {
            MOBILE_CLAW_VPN_RELAY_DIAL_ADDR_ENV => Some(Ok("198.51.100.10:49152".to_owned())),
            MOBILE_CLAW_VPN_RELAY_DIAL_ALLOW_NON_LOOPBACK_ENV => Some(Ok("true".to_owned())),
            MOBILE_CLAW_VPN_RELAY_DIAL_PEER_IDENTITY_SHA256_ENV => {
                Some(Ok(PEER_IDENTITY_A.to_owned()))
            }
            _ => None,
        })
        .unwrap();

        assert_eq!(
            config.relay_addr,
            Some("198.51.100.10:49152".parse().unwrap())
        );
        assert!(config.allow_non_loopback_relay_addr);
        assert!(config.relay_peer_identity.is_some());
        assert!(!format!("{config:?}").contains("198.51.100.10"));
        assert!(!format!("{config:?}").contains(PEER_IDENTITY_A));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_proof_allows_non_loopback_token_bearing_dial() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("198.51.100.10:49152"),
            Some("true"),
            None,
            None,
            Some(PEER_IDENTITY_A),
        )
        .unwrap();
        let proof = MobileClawVpnRendezvousRelayAuthProof::new_for_test(
            relay_addr,
            config.relay_peer_identity.unwrap(),
        );

        let validated = config
            .validate_for_token_bearing_dial(Some(&proof))
            .unwrap();

        assert_eq!(validated.relay_addr, config.relay_addr);
        assert_eq!(validated.relay_peer_identity, config.relay_peer_identity);
        assert!(!format!("{proof:?}").contains("198.51.100.10"));
        assert!(!format!("{proof:?}").contains(PEER_IDENTITY_A));
        assert!(!format!("{config:?}").contains(PEER_IDENTITY_A));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_proof_is_bound_to_relay_addr() {
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("198.51.100.10:49152"),
            Some("true"),
            None,
            None,
            Some(PEER_IDENTITY_A),
        )
        .unwrap();
        let proof = MobileClawVpnRendezvousRelayAuthProof::new_for_test(
            "198.51.100.11:49152".parse().unwrap(),
            config.relay_peer_identity.unwrap(),
        );

        let error = config
            .validate_for_token_bearing_dial(Some(&proof))
            .unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{proof:?}").contains("198.51.100.11"));
        assert!(!format!("{error:?}").contains("198.51.100.10"));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_proof_is_bound_to_peer_identity() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("198.51.100.10:49152"),
            Some("true"),
            None,
            None,
            Some(PEER_IDENTITY_A),
        )
        .unwrap();
        let other_identity = parse_optional_relay_peer_identity(Some(PEER_IDENTITY_B))
            .unwrap()
            .unwrap();
        let proof = MobileClawVpnRendezvousRelayAuthProof::new_for_test(relay_addr, other_identity);

        let error = config
            .validate_for_token_bearing_dial(Some(&proof))
            .unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{proof:?}").contains(PEER_IDENTITY_B));
        assert!(!format!("{error:?}").contains(PEER_IDENTITY_A));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_proof_mints_from_authenticated_peer() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("198.51.100.10:49152"),
            Some("true"),
            None,
            None,
            Some(PEER_IDENTITY_A),
        )
        .unwrap();
        let authenticated_peer = MobileClawVpnRendezvousAuthenticatedRelayPeer::new_for_test(
            relay_addr,
            config.relay_peer_identity.unwrap(),
        );
        let peer_debug = format!("{authenticated_peer:?}");

        let proof = config
            .relay_auth_proof_for_authenticated_non_loopback_peer(&authenticated_peer)
            .unwrap();
        let validated = config
            .validate_for_token_bearing_dial(Some(&proof))
            .unwrap();

        assert_eq!(validated.relay_addr, config.relay_addr);
        assert_eq!(validated.relay_peer_identity, config.relay_peer_identity);
        assert!(!peer_debug.contains("198.51.100.10"));
        assert!(!peer_debug.contains(PEER_IDENTITY_A));
        assert!(!format!("{proof:?}").contains("198.51.100.10"));
        assert!(!format!("{proof:?}").contains(PEER_IDENTITY_A));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_proof_mint_requires_configured_peer_identity() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("198.51.100.10:49152"),
            Some("true"),
            None,
            None,
            None,
        )
        .unwrap();
        let peer_identity = parse_optional_relay_peer_identity(Some(PEER_IDENTITY_A))
            .unwrap()
            .unwrap();
        let authenticated_peer =
            MobileClawVpnRendezvousAuthenticatedRelayPeer::new_for_test(relay_addr, peer_identity);

        let error = config
            .relay_auth_proof_for_authenticated_non_loopback_peer(&authenticated_peer)
            .unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{config:?}").contains("198.51.100.10"));
        assert!(!format!("{error:?}").contains("198.51.100.10"));
        assert!(!error.to_string().contains(PEER_IDENTITY_A));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_proof_mint_is_bound_to_authenticated_addr() {
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("198.51.100.10:49152"),
            Some("true"),
            None,
            None,
            Some(PEER_IDENTITY_A),
        )
        .unwrap();
        let authenticated_peer = MobileClawVpnRendezvousAuthenticatedRelayPeer::new_for_test(
            "198.51.100.11:49152".parse().unwrap(),
            config.relay_peer_identity.unwrap(),
        );
        let peer_debug = format!("{authenticated_peer:?}");

        let error = config
            .relay_auth_proof_for_authenticated_non_loopback_peer(&authenticated_peer)
            .unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!peer_debug.contains("198.51.100.11"));
        assert!(!format!("{error:?}").contains("198.51.100.10"));
        assert!(!error.to_string().contains(PEER_IDENTITY_A));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_proof_mint_is_bound_to_authenticated_identity() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let config = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("198.51.100.10:49152"),
            Some("true"),
            None,
            None,
            Some(PEER_IDENTITY_A),
        )
        .unwrap();
        let other_identity = parse_optional_relay_peer_identity(Some(PEER_IDENTITY_B))
            .unwrap()
            .unwrap();
        let authenticated_peer =
            MobileClawVpnRendezvousAuthenticatedRelayPeer::new_for_test(relay_addr, other_identity);

        let error = config
            .relay_auth_proof_for_authenticated_non_loopback_peer(&authenticated_peer)
            .unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{error:?}").contains(PEER_IDENTITY_A));
        assert!(!error.to_string().contains(PEER_IDENTITY_B));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_peer_verifies_signed_challenge_and_mints_proof() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let relay_key = P256Keypair::generate();
        let relay_public_key = relay_key.public();
        let relay_peer_identity =
            MobileClawVpnRendezvousRelayPeerIdentity::from_relay_public_key(&relay_public_key);
        let config = MobileClawVpnRendezvousRelayDialConfig {
            relay_addr: Some(relay_addr),
            connect_timeout: DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT,
            hello_timeout: DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT,
            allow_non_loopback_relay_addr: true,
            relay_peer_identity: Some(relay_peer_identity),
        };
        let challenge = MobileClawVpnRendezvousRelayAuthChallenge::new_for_test([0xA1; 32]);
        let signature = relay_key
            .sign(&challenge.signing_bytes(relay_addr, &relay_public_key))
            .unwrap();

        let authenticated_peer =
            MobileClawVpnRendezvousAuthenticatedRelayPeer::from_signed_challenge(
                relay_addr,
                &relay_public_key,
                &challenge,
                &signature,
            )
            .unwrap();
        let proof = config
            .relay_auth_proof_for_authenticated_non_loopback_peer(&authenticated_peer)
            .unwrap();
        let validated = config
            .validate_for_token_bearing_dial(Some(&proof))
            .unwrap();

        assert_eq!(validated.relay_addr, Some(relay_addr));
        assert_eq!(validated.relay_peer_identity, Some(relay_peer_identity));
        assert!(!format!("{challenge:?}").contains("a1a1"));
        assert!(!format!("{authenticated_peer:?}").contains("198.51.100.10"));
        assert!(!format!("{proof:?}").contains("198.51.100.10"));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_peer_rejects_signature_from_wrong_key_without_echo() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let relay_key = P256Keypair::generate();
        let relay_public_key = relay_key.public();
        let attacker_key = P256Keypair::generate();
        let challenge = MobileClawVpnRendezvousRelayAuthChallenge::new_for_test([0xB2; 32]);
        let signature = attacker_key
            .sign(&challenge.signing_bytes(relay_addr, &relay_public_key))
            .unwrap();
        let public_key_hex = hex::encode(relay_public_key.as_bytes());

        let error = MobileClawVpnRendezvousAuthenticatedRelayPeer::from_signed_challenge(
            relay_addr,
            &relay_public_key,
            &challenge,
            &signature,
        )
        .unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{error:?}").contains("198.51.100.10"));
        assert!(!format!("{error:?}").contains(&public_key_hex));
        assert!(!error.to_string().contains("198.51.100.10"));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_peer_signature_is_bound_to_relay_addr() {
        let signed_addr = "198.51.100.10:49152".parse().unwrap();
        let attempted_addr = "198.51.100.11:49152".parse().unwrap();
        let relay_key = P256Keypair::generate();
        let relay_public_key = relay_key.public();
        let challenge = MobileClawVpnRendezvousRelayAuthChallenge::new_for_test([0xC3; 32]);
        let signature = relay_key
            .sign(&challenge.signing_bytes(signed_addr, &relay_public_key))
            .unwrap();

        let error = MobileClawVpnRendezvousAuthenticatedRelayPeer::from_signed_challenge(
            attempted_addr,
            &relay_public_key,
            &challenge,
            &signature,
        )
        .unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{error:?}").contains("198.51.100.11"));
        assert!(!error.to_string().contains("198.51.100.10"));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_peer_signature_is_bound_to_challenge_nonce() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let relay_key = P256Keypair::generate();
        let relay_public_key = relay_key.public();
        let signed_challenge = MobileClawVpnRendezvousRelayAuthChallenge::new_for_test([0x11; 32]);
        let attempted_challenge =
            MobileClawVpnRendezvousRelayAuthChallenge::new_for_test([0x22; 32]);
        let signature = relay_key
            .sign(&signed_challenge.signing_bytes(relay_addr, &relay_public_key))
            .unwrap();

        let error = MobileClawVpnRendezvousAuthenticatedRelayPeer::from_signed_challenge(
            relay_addr,
            &relay_public_key,
            &attempted_challenge,
            &signature,
        )
        .unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{signed_challenge:?}").contains("1111"));
        assert!(!format!("{attempted_challenge:?}").contains("2222"));
        assert!(!format!("{error:?}").contains("198.51.100.10"));
        assert!(!error.to_string().contains("198.51.100.10"));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_peer_rejects_loopback_minting() {
        let relay_addr = "127.0.0.1:49152".parse().unwrap();
        let relay_key = P256Keypair::generate();
        let relay_public_key = relay_key.public();
        let challenge = MobileClawVpnRendezvousRelayAuthChallenge::new_for_test([0xD4; 32]);
        let signature = relay_key
            .sign(&challenge.signing_bytes(relay_addr, &relay_public_key))
            .unwrap();

        let error = MobileClawVpnRendezvousAuthenticatedRelayPeer::from_signed_challenge(
            relay_addr,
            &relay_public_key,
            &challenge,
            &signature,
        )
        .unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{error:?}").contains("127.0.0.1"));
    }

    #[test]
    fn mobile_claw_vpn_relay_auth_peer_identity_is_derived_from_signing_key() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let expected_key = P256Keypair::generate();
        let expected_identity =
            MobileClawVpnRendezvousRelayPeerIdentity::from_relay_public_key(&expected_key.public());
        let config = MobileClawVpnRendezvousRelayDialConfig {
            relay_addr: Some(relay_addr),
            connect_timeout: DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT,
            hello_timeout: DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT,
            allow_non_loopback_relay_addr: true,
            relay_peer_identity: Some(expected_identity),
        };
        let attacker_key = P256Keypair::generate();
        let attacker_public_key = attacker_key.public();
        let challenge = MobileClawVpnRendezvousRelayAuthChallenge::new_for_test([0xE5; 32]);
        let signature = attacker_key
            .sign(&challenge.signing_bytes(relay_addr, &attacker_public_key))
            .unwrap();

        let authenticated_peer =
            MobileClawVpnRendezvousAuthenticatedRelayPeer::from_signed_challenge(
                relay_addr,
                &attacker_public_key,
                &challenge,
                &signature,
            )
            .unwrap();
        let error = config
            .relay_auth_proof_for_authenticated_non_loopback_peer(&authenticated_peer)
            .unwrap_err();

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{error:?}").contains("198.51.100.10"));
        assert!(!error.to_string().contains(PEER_IDENTITY_A));
    }

    #[test]
    fn mobile_claw_vpn_relay_dial_config_rejects_invalid_values_without_echo() {
        let error = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("relay.example.invalid:49152"),
            None,
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
                None,
            )
            .unwrap_err()
            .kind(),
            "invalid_deadline"
        );
        let error = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("127.0.0.1:49152"),
            None,
            None,
            None,
            Some("relay.example.invalid"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), "invalid_relay_peer_identity");
        assert!(!format!("{error:?}").contains("relay.example.invalid"));

        let unicode_identity = "\u{00e9}".repeat(32);
        let error = MobileClawVpnRendezvousRelayDialConfig::from_values(
            Some("127.0.0.1:49152"),
            None,
            None,
            None,
            Some(&unicode_identity),
        )
        .unwrap_err();
        assert_eq!(error.kind(), "invalid_relay_peer_identity");
        assert!(!format!("{error:?}").contains(&unicode_identity));

        let error = MobileClawVpnRendezvousRelayDialConfig::from_values(
            None,
            None,
            None,
            None,
            Some(PEER_IDENTITY_A),
        )
        .unwrap_err();
        assert_eq!(error.kind(), "relay_peer_identity_without_relay_addr");
        assert!(!format!("{error:?}").contains(PEER_IDENTITY_A));
    }
}
