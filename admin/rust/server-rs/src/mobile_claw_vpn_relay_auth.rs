//! Stream-local relay-auth handshake for mobile Claw VPN rendezvous dials.
//!
//! This module does not open sockets, choose relay endpoints, authorize Mesh-C
//! state, write token-bearing rendezvous hellos, expose handlers, or mutate host
//! networking. It authenticates a caller-provided stream before the caller may
//! write a token-bearing hello to a non-loopback relay.

use std::net::SocketAddr;

#[cfg(test)]
use crate::mobile_claw_vpn_relay_dial_config::RELAY_AUTH_CHALLENGE_LEN;
use crate::mobile_claw_vpn_relay_dial_config::{
    MobileClawVpnRendezvousAuthenticatedRelayPeer, MobileClawVpnRendezvousRelayAuthChallenge,
    MobileClawVpnRendezvousRelayAuthProof, MobileClawVpnRendezvousRelayDialConfig,
    MobileClawVpnRendezvousRelayDialError,
};
use household_rs::keys::{P256PublicKey, P256Signature};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const RELAY_AUTH_CHALLENGE_PREFIX: &[u8] = b"theyos-mobile-claw-vpn-relay-auth-challenge-v1\0";
const RELAY_AUTH_RESPONSE_PREFIX: &[u8] = b"theyos-mobile-claw-vpn-relay-auth-response-v1\0";
const RELAY_AUTH_RESPONSE_LEN: usize =
    RELAY_AUTH_RESPONSE_PREFIX.len() + P256PublicKey::LEN + P256Signature::LEN;

struct MobileClawVpnRendezvousRelayAuthResponse {
    relay_public_key: P256PublicKey,
    signature: P256Signature,
}

/// Authenticates the relay peer on a caller-provided stream and mints the
/// non-loopback token-bearing dial proof for that exact stream address.
///
/// The challenge is generated inside this function for each attempt. The
/// caller must pass the `SocketAddr` used for the already-connected stream; the
/// signed transcript binds the returned proof to that address and to the
/// configured relay peer identity.
pub(crate) async fn mobile_claw_vpn_authenticate_rendezvous_relay_stream<S>(
    stream: &mut S,
    config: MobileClawVpnRendezvousRelayDialConfig,
    relay_addr: SocketAddr,
) -> Result<MobileClawVpnRendezvousRelayAuthProof, MobileClawVpnRendezvousRelayDialError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = config.validate_for_dial()?;
    if config.relay_addr != Some(relay_addr)
        || relay_addr.ip().is_loopback()
        || config.relay_peer_identity.is_none()
    {
        return Err(MobileClawVpnRendezvousRelayDialError::RelayAuthRequired);
    }

    let challenge = MobileClawVpnRendezvousRelayAuthChallenge::generate();
    write_challenge_frame(stream, &challenge).await?;
    let response = read_response_frame(stream).await?;
    let authenticated_peer = MobileClawVpnRendezvousAuthenticatedRelayPeer::from_signed_challenge(
        relay_addr,
        &response.relay_public_key,
        &challenge,
        &response.signature,
    )?;
    config.relay_auth_proof_for_authenticated_non_loopback_peer(&authenticated_peer)
}

async fn write_challenge_frame<W>(
    writer: &mut W,
    challenge: &MobileClawVpnRendezvousRelayAuthChallenge,
) -> Result<(), MobileClawVpnRendezvousRelayDialError>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(RELAY_AUTH_CHALLENGE_PREFIX)
        .await
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;
    writer
        .write_all(challenge.nonce_bytes())
        .await
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;
    writer
        .flush()
        .await
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)
}

async fn read_response_frame<R>(
    reader: &mut R,
) -> Result<MobileClawVpnRendezvousRelayAuthResponse, MobileClawVpnRendezvousRelayDialError>
where
    R: AsyncRead + Unpin,
{
    let mut frame = [0_u8; RELAY_AUTH_RESPONSE_LEN];
    reader
        .read_exact(&mut frame)
        .await
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;
    if !frame.starts_with(RELAY_AUTH_RESPONSE_PREFIX) {
        return Err(MobileClawVpnRendezvousRelayDialError::RelayAuthRequired);
    }

    let mut offset = RELAY_AUTH_RESPONSE_PREFIX.len();
    let public_key_end = offset + P256PublicKey::LEN;
    let relay_public_key = P256PublicKey::from_bytes(&frame[offset..public_key_end])
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;
    offset = public_key_end;
    let signature = P256Signature::from_bytes(&frame[offset..offset + P256Signature::LEN])
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;

    Ok(MobileClawVpnRendezvousRelayAuthResponse {
        relay_public_key,
        signature,
    })
}

#[cfg(test)]
pub(crate) async fn mobile_claw_vpn_answer_relay_auth_challenge_for_test<S>(
    stream: &mut S,
    relay_addr: SocketAddr,
    relay_key: &dyn household_rs::keys::IdentityKey,
) -> Result<(), MobileClawVpnRendezvousRelayDialError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let challenge = read_challenge_frame_for_test(stream).await?;
    let relay_public_key = relay_key.public();
    let signature = relay_key
        .sign(&challenge.signing_bytes(relay_addr, &relay_public_key))
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;
    write_response_frame_for_test(
        stream,
        &MobileClawVpnRendezvousRelayAuthResponse {
            relay_public_key,
            signature,
        },
    )
    .await
}

#[cfg(test)]
async fn read_challenge_frame_for_test<R>(
    reader: &mut R,
) -> Result<MobileClawVpnRendezvousRelayAuthChallenge, MobileClawVpnRendezvousRelayDialError>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; RELAY_AUTH_CHALLENGE_PREFIX.len()];
    reader
        .read_exact(&mut prefix)
        .await
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;
    if prefix != RELAY_AUTH_CHALLENGE_PREFIX {
        return Err(MobileClawVpnRendezvousRelayDialError::RelayAuthRequired);
    }
    let mut nonce = [0_u8; RELAY_AUTH_CHALLENGE_LEN];
    reader
        .read_exact(&mut nonce)
        .await
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;
    Ok(MobileClawVpnRendezvousRelayAuthChallenge::from_nonce_bytes(
        nonce,
    ))
}

#[cfg(test)]
async fn write_response_frame_for_test<W>(
    writer: &mut W,
    response: &MobileClawVpnRendezvousRelayAuthResponse,
) -> Result<(), MobileClawVpnRendezvousRelayDialError>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(RELAY_AUTH_RESPONSE_PREFIX)
        .await
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;
    writer
        .write_all(response.relay_public_key.as_bytes())
        .await
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;
    writer
        .write_all(response.signature.as_bytes())
        .await
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)?;
    writer
        .flush()
        .await
        .map_err(|_error| MobileClawVpnRendezvousRelayDialError::RelayAuthRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use household_rs::keys::{IdentityKey, P256Keypair};
    use tokio::io::duplex;
    use tokio::time::timeout;

    fn non_loopback_config_for(
        relay_addr: SocketAddr,
        relay_key: &P256Keypair,
    ) -> MobileClawVpnRendezvousRelayDialConfig {
        MobileClawVpnRendezvousRelayDialConfig {
            relay_addr: Some(relay_addr),
            connect_timeout: crate::mobile_claw_vpn_relay_dial_config::DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT,
            hello_timeout: crate::mobile_claw_vpn_relay_dial_config::DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT,
            allow_non_loopback_relay_addr: true,
            relay_peer_identity: Some(
                crate::mobile_claw_vpn_relay_dial_config::MobileClawVpnRendezvousRelayPeerIdentity::from_relay_public_key(
                    &relay_key.public(),
                ),
            ),
        }
    }

    #[tokio::test]
    async fn mobile_claw_vpn_relay_auth_stream_mints_bound_proof() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let relay_key = P256Keypair::generate();
        let config = non_loopback_config_for(relay_addr, &relay_key);
        let (mut client, mut relay) = duplex(512);

        let relay_task = tokio::spawn(async move {
            mobile_claw_vpn_answer_relay_auth_challenge_for_test(&mut relay, relay_addr, &relay_key)
                .await
        });
        let proof =
            mobile_claw_vpn_authenticate_rendezvous_relay_stream(&mut client, config, relay_addr)
                .await
                .unwrap();

        relay_task.await.unwrap().unwrap();
        config
            .validate_for_token_bearing_dial(Some(&proof))
            .unwrap();
    }

    #[tokio::test]
    async fn mobile_claw_vpn_relay_auth_stream_rejects_wrong_stream_addr_without_echo() {
        let signed_addr = "198.51.100.10:49152".parse().unwrap();
        let attempted_addr = "198.51.100.11:49152".parse().unwrap();
        let relay_key = P256Keypair::generate();
        let config = non_loopback_config_for(attempted_addr, &relay_key);
        let (mut client, mut relay) = duplex(512);

        let relay_task = tokio::spawn(async move {
            mobile_claw_vpn_answer_relay_auth_challenge_for_test(
                &mut relay,
                signed_addr,
                &relay_key,
            )
            .await
        });
        let error = mobile_claw_vpn_authenticate_rendezvous_relay_stream(
            &mut client,
            config,
            attempted_addr,
        )
        .await
        .unwrap_err();

        relay_task.await.unwrap().unwrap();
        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{error:?}").contains("198.51.100.11"));
        assert!(!error.to_string().contains("198.51.100.10"));
    }

    #[tokio::test]
    async fn mobile_claw_vpn_relay_auth_stream_requires_configured_identity_before_io() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let config = MobileClawVpnRendezvousRelayDialConfig {
            relay_addr: Some(relay_addr),
            connect_timeout: crate::mobile_claw_vpn_relay_dial_config::DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_CONNECT_TIMEOUT,
            hello_timeout: crate::mobile_claw_vpn_relay_dial_config::DEFAULT_MOBILE_CLAW_VPN_RELAY_DIAL_HELLO_TIMEOUT,
            allow_non_loopback_relay_addr: true,
            relay_peer_identity: None,
        };
        let (mut client, mut relay) = duplex(512);

        let error =
            mobile_claw_vpn_authenticate_rendezvous_relay_stream(&mut client, config, relay_addr)
                .await
                .unwrap_err();
        let mut leaked = [0_u8; 1];
        let read = timeout(Duration::from_millis(20), relay.read_exact(&mut leaked)).await;

        assert_eq!(error.kind(), "relay_auth_required");
        assert!(read.is_err());
        assert!(!format!("{config:?}").contains("198.51.100.10"));
    }

    #[tokio::test]
    async fn mobile_claw_vpn_relay_auth_stream_rejects_malformed_response_without_echo() {
        let relay_addr = "198.51.100.10:49152".parse().unwrap();
        let relay_key = P256Keypair::generate();
        let config = non_loopback_config_for(relay_addr, &relay_key);
        let (mut client, mut relay) = duplex(512);

        let relay_task = tokio::spawn(async move {
            let _challenge = read_challenge_frame_for_test(&mut relay).await.unwrap();
            relay
                .write_all(b"not-a-valid-relay-auth-response")
                .await
                .unwrap();
            relay.flush().await.unwrap();
        });
        let error =
            mobile_claw_vpn_authenticate_rendezvous_relay_stream(&mut client, config, relay_addr)
                .await
                .unwrap_err();

        relay_task.await.unwrap();
        assert_eq!(error.kind(), "relay_auth_required");
        assert!(!format!("{error:?}").contains("198.51.100.10"));
        assert!(!error.to_string().contains("not-a-valid"));
    }
}
