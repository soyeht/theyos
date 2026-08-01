//! Reverse-connect endpoint for the Product A `relay_stream` claw responder.
//!
//! This module is not product-wired: no bootstrap, claim ack, iOS, public
//! advertise, offer store, or runtime source of offers. The caller injects one
//! already-selected offer and responder params. The rendezvous relay remains a
//! blind byte splicer; this is the claw endpoint that dials the relay, sends
//! the relay-visible `Claw` hello, then runs Noise and the data tunnel locally.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use household_rs::claw_share_data_tunnel::ClawTargetRouter;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::claw_share_relay_stream_admission::RelayStreamAdmissionError;
use crate::claw_share_relay_stream_contract::RelayStreamOfferContract;
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;
use crate::claw_share_relay_stream_responder::{
    RelayStreamResponderError, ResponderDataTunnelDeps, serve_relay_stream_responder_connection,
};
use crate::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
use crate::claw_share_relay_stream_reverse_connect_binding::RelayStreamReverseConnectBinding;
use crate::claw_share_relay_stream_target_router::RelayStreamOfferTargetRouter;
use crate::claw_share_rendezvous_stream_relay::{RendezvousHello, RendezvousRole};
use crate::claw_share_session_clock::AdmissionInstant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStreamResponderReverseConnectConfig {
    pub relay_addr: SocketAddr,
    pub connect_timeout: Duration,
    pub hello_timeout: Duration,
    pub allow_non_loopback_relay_addr: bool,
}

impl Default for RelayStreamResponderReverseConnectConfig {
    fn default() -> Self {
        Self {
            relay_addr: SocketAddr::from(([127, 0, 0, 1], 49_152)),
            connect_timeout: Duration::from_secs(5),
            hello_timeout: Duration::from_secs(5),
            allow_non_loopback_relay_addr: false,
        }
    }
}

impl RelayStreamResponderReverseConnectConfig {
    pub fn validate(self) -> Result<Self, RelayStreamResponderReverseConnectError> {
        validate_relay_addr(self.relay_addr, self.allow_non_loopback_relay_addr)?;
        if self.connect_timeout.is_zero() {
            return Err(RelayStreamResponderReverseConnectError::InvalidDeadline(
                "connect_timeout",
            ));
        }
        if self.hello_timeout.is_zero() {
            return Err(RelayStreamResponderReverseConnectError::InvalidDeadline(
                "hello_timeout",
            ));
        }
        Ok(self)
    }
}

pub async fn serve_relay_stream_responder_reverse_connect<R>(
    config: RelayStreamResponderReverseConnectConfig,
    offer: Arc<RelayStreamOfferContract>,
    params: Arc<RelayStreamResponderParams>,
    deps: Arc<ResponderDataTunnelDeps<R>>,
) -> Result<(), RelayStreamResponderReverseConnectError>
where
    R: ClawTargetRouter + Send + Sync,
{
    let config = config.validate()?;
    // Capture the (wall, monotonic) pair ONCE, before dialing. `None` means the
    // wall clock is unusable, and with a broken clock `not_after` can never be
    // enforced — refuse rather than dial fail-open.
    let admission =
        capture_admission().ok_or(RelayStreamResponderReverseConnectError::ClockUnusable)?;
    let now = admission.wall();
    // Health-before-dial: admit before opening the relay connection so an
    // unhealthy trust runtime never dials. The admitted seam is reused for this
    // connection (no second admit downstream).
    let trust = params.admission.admit(now)?;

    let stream = timeout(
        config.connect_timeout,
        TcpStream::connect(config.relay_addr),
    )
    .await
    .map_err(|_| RelayStreamResponderReverseConnectError::ConnectTimeout)?
    .map_err(|source| RelayStreamResponderReverseConnectError::Dial {
        addr: config.relay_addr,
        source,
    })?;

    serve_relay_stream_responder_reverse_connected_with_trust(
        stream, &offer, &params, &trust, admission, &deps, config,
    )
    .await
}

/// Reverse-connect serve that admits its own per-connection trust seam.
///
/// Thin wrapper over [`serve_relay_stream_responder_reverse_connected_with_trust`]:
/// it runs the admission health gate, then serves with the admitted seam.
pub async fn serve_relay_stream_responder_reverse_connected<S, R>(
    stream: S,
    offer: &RelayStreamOfferContract,
    params: &RelayStreamResponderParams,
    admission: AdmissionInstant,
    deps: &ResponderDataTunnelDeps<R>,
    config: RelayStreamResponderReverseConnectConfig,
) -> Result<(), RelayStreamResponderReverseConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: ClawTargetRouter,
{
    let trust = params.admission.admit(admission.wall())?;
    serve_relay_stream_responder_reverse_connected_with_trust(
        stream, offer, params, &trust, admission, deps, config,
    )
    .await
}

/// Reverse-connect serve with a pre-admitted per-connection trust seam.
///
/// This variant does NOT admit; the caller must have admitted `trust` already
/// (e.g. before dialing, so an unhealthy runtime never connects). It writes the
/// relay-visible `Claw` hello, then runs the Noise handshake + data tunnel using
/// the supplied seam. C4e drives this from the pool after a pre-dial admission.
pub async fn serve_relay_stream_responder_reverse_connected_with_trust<S, R>(
    mut stream: S,
    offer: &RelayStreamOfferContract,
    params: &RelayStreamResponderParams,
    trust: &RelayStreamIssuerTrust,
    admission: AdmissionInstant,
    deps: &ResponderDataTunnelDeps<R>,
    config: RelayStreamResponderReverseConnectConfig,
) -> Result<(), RelayStreamResponderReverseConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: ClawTargetRouter,
{
    let config = config.validate()?;
    let hello =
        RendezvousHello::new(RendezvousRole::Claw, offer.payload.rendezvous_token.clone()).encode();

    timeout(config.hello_timeout, async {
        stream.write_all(&hello).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| RelayStreamResponderReverseConnectError::HelloTimeout)?
    .map_err(RelayStreamResponderReverseConnectError::HelloWrite)?;

    serve_relay_stream_responder_connection(stream, offer, params, trust, admission, deps).await?;
    Ok(())
}

/// Reverse-connect serve driven by a [`RelayStreamReverseConnectBinding`].
///
/// This is the single entry the pool uses: the offer, the pre-admitted trust
/// seam, and the target-router deps all come from the one binding, so the offer
/// that drives the Noise prologue is by construction the same offer the router
/// gates on (M2a airtight at the serve boundary). It does not admit; the binding
/// already carries a fresh seam.
pub async fn serve_relay_stream_responder_reverse_connected_binding<T, P, S, I>(
    stream: T,
    binding: &RelayStreamReverseConnectBinding<P, S, I>,
    params: &RelayStreamResponderParams,
    admission: AdmissionInstant,
    config: RelayStreamResponderReverseConnectConfig,
) -> Result<(), RelayStreamResponderReverseConnectError>
where
    T: AsyncRead + AsyncWrite + Unpin,
    P: ClawTargetRouter,
    S: ClawTargetRouter,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter,
{
    serve_relay_stream_responder_reverse_connected_with_trust(
        stream,
        &binding.offer,
        params,
        &binding.trust,
        admission,
        &binding.deps,
        config,
    )
    .await
}

/// Dial the relay and serve one reverse-connect attempt using a pre-built
/// binding. The binding must have been created after a fresh admission for this
/// attempt; this function performs no admission and never accepts separate
/// offer/deps arguments.
pub async fn serve_relay_stream_responder_reverse_connect_binding<P, S, I>(
    config: RelayStreamResponderReverseConnectConfig,
    binding: &RelayStreamReverseConnectBinding<P, S, I>,
    params: &RelayStreamResponderParams,
    admission: AdmissionInstant,
) -> Result<(), RelayStreamResponderReverseConnectError>
where
    P: ClawTargetRouter,
    S: ClawTargetRouter,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter,
{
    let config = config.validate()?;
    let stream = timeout(
        config.connect_timeout,
        TcpStream::connect(config.relay_addr),
    )
    .await
    .map_err(|_| RelayStreamResponderReverseConnectError::ConnectTimeout)?
    .map_err(|source| RelayStreamResponderReverseConnectError::Dial {
        addr: config.relay_addr,
        source,
    })?;

    serve_relay_stream_responder_reverse_connected_binding(
        stream, binding, params, admission, config,
    )
    .await
}

fn validate_relay_addr(
    addr: SocketAddr,
    allow_non_loopback: bool,
) -> Result<(), RelayStreamResponderReverseConnectError> {
    if !allow_non_loopback && !addr.ip().is_loopback() {
        return Err(RelayStreamResponderReverseConnectError::NonLoopbackRelayAddr);
    }
    if addr.port() == 0 {
        return Err(RelayStreamResponderReverseConnectError::InvalidRelayAddrPort);
    }
    Ok(())
}

/// Capture the admission clock pair for this track.
///
/// `None` means the wall clock is unusable (before the epoch, exactly at it, or
/// below the sanity floor). Callers MUST refuse; never substitute a sentinel.
fn capture_admission() -> Option<AdmissionInstant> {
    AdmissionInstant::capture("claw_share.relay_stream_responder.reverse_connect")
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamResponderReverseConnectError {
    #[error("relay stream reverse-connect relay address must be loopback")]
    NonLoopbackRelayAddr,

    #[error("relay stream reverse-connect relay address port is invalid")]
    InvalidRelayAddrPort,

    #[error("relay stream reverse-connect deadline is invalid: {0}")]
    InvalidDeadline(&'static str),

    #[error("relay stream reverse-connect dial timed out")]
    ConnectTimeout,

    #[error("relay stream reverse-connect dial failed for {addr}: {source}")]
    Dial {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("relay stream reverse-connect refused: implausible system clock")]
    ClockUnusable,

    #[error("relay stream reverse-connect hello timed out")]
    HelloTimeout,

    #[error("relay stream reverse-connect hello write failed: {0}")]
    HelloWrite(std::io::Error),

    #[error("relay stream reverse-connect admission failed: {0}")]
    Admission(#[from] RelayStreamAdmissionError),

    #[error("relay stream reverse-connect responder failed: {0}")]
    Responder(#[from] RelayStreamResponderError),
}

#[cfg(test)]
mod tests {
    use super::*;

    use household_rs::cbor;
    use household_rs::claw_share_data_tunnel::{
        HEALTH_PROBE, SessionAuthToken, TunnelAck, TunnelFrame, client_authenticate, client_health,
        client_open_stream, recv_frame, send_frame,
    };
    use household_rs::keys::IdentityKey;
    use tokio::io::{AsyncWriteExt, duplex};
    use tokio::net::TcpListener;

    use crate::claw_share_relay_stream_noise::{
        RelayStreamNoiseFramed, generate_relay_stream_noise_static_keypair,
    };
    use crate::claw_share_relay_stream_test_support::{
        attacker_signer, data_tunnel_credential, data_tunnel_deps_arc,
        data_tunnel_token as support_data_tunnel_token, guest_pub, owner_pub, relay_stream_offer,
        relay_stream_offer_signed_by, relay_stream_responder_params as params, rendezvous_token,
        spawn_ack_target,
    };
    use crate::claw_share_rendezvous_stream_relay::{RendezvousRole, RendezvousToken};
    use crate::claw_share_rendezvous_stream_relay_listener::{
        RendezvousStreamRelayListenerConfig, serve_rendezvous_stream_relay,
    };

    const TOKEN_AUDIENCE: &str = "relay-stream-reverse-connect-test";

    fn data_tunnel_token(credential_cbor: &[u8], nonce: &[u8]) -> SessionAuthToken {
        support_data_tunnel_token(TOKEN_AUDIENCE, credential_cbor, nonce)
    }

    fn test_relay_config() -> RendezvousStreamRelayListenerConfig {
        RendezvousStreamRelayListenerConfig {
            hello_timeout: Duration::from_secs(1),
            token_ttl: Duration::from_secs(2),
            max_pending: 16,
            max_active_connections: 16,
            reaper_interval: Duration::from_millis(50),
            splice_idle_timeout: Duration::from_secs(5),
            splice_max_lifetime: Duration::from_secs(60),
            abuse: crate::claw_share_relay_stream_abuse::RelayAbuseConfig::default(),
        }
    }

    fn reverse_config(relay_addr: SocketAddr) -> RelayStreamResponderReverseConnectConfig {
        RelayStreamResponderReverseConnectConfig {
            relay_addr,
            connect_timeout: Duration::from_secs(1),
            hello_timeout: Duration::from_secs(1),
            allow_non_loopback_relay_addr: false,
        }
    }

    async fn spawn_test_relay() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = serve_rendezvous_stream_relay(listener, test_relay_config());
        (addr, handle)
    }

    async fn connect_guest_with_hello(relay_addr: SocketAddr, token: RendezvousToken) -> TcpStream {
        let mut stream = TcpStream::connect(relay_addr).await.unwrap();
        stream
            .write_all(&RendezvousHello::new(RendezvousRole::Guest, token).encode())
            .await
            .unwrap();
        stream.flush().await.unwrap();
        stream
    }

    #[tokio::test]
    async fn relay_stream_reverse_connect_dials_rendezvous_and_pipes_data_to_target() {
        timeout(Duration::from_secs(5), async {
            let (relay_addr, relay_handle) = spawn_test_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = Arc::new(relay_stream_offer(rendezvous_token(0x91), &keypair));
            let params = Arc::new(params(keypair, Duration::from_secs(2)).await);
            let deps = data_tunnel_deps_arc(spawn_ack_target().await);
            let claw = tokio::spawn(serve_relay_stream_responder_reverse_connect(
                reverse_config(relay_addr),
                Arc::clone(&offer),
                Arc::clone(&params),
                Arc::clone(&deps),
            ));

            let guest =
                connect_guest_with_hello(relay_addr, offer.payload.rendezvous_token.clone()).await;
            let guest_key = guest_pub();
            let mut stream = RelayStreamNoiseFramed::initiator_handshake(
                guest,
                &offer,
                &owner_pub(),
                &guest_key,
                crate::claw_share_session_clock::wall_now_secs("test").expect("plausible clock"),
            )
            .await
            .unwrap()
            .into_async_stream();
            let cbor = cbor::to_canonical_vec(&data_tunnel_credential()).unwrap();
            assert!(matches!(
                client_authenticate(&mut stream, &cbor, data_tunnel_token(&cbor, b"reverse-ok"))
                    .await
                    .unwrap(),
                TunnelAck::Ok { .. }
            ));
            assert_eq!(
                client_health(&mut stream, HEALTH_PROBE).await.unwrap(),
                HEALTH_PROBE
            );
            client_open_stream(&mut stream).await.unwrap();
            send_frame(&mut stream, &TunnelFrame::Data(b"reverse-data".to_vec()))
                .await
                .unwrap();
            assert_eq!(
                recv_frame(&mut stream).await.unwrap(),
                TunnelFrame::Data(b"ACK:reverse-data".to_vec())
            );
            send_frame(&mut stream, &TunnelFrame::Close).await.unwrap();

            claw.await.unwrap().unwrap();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relay_stream_reverse_connect_different_token_does_not_open_data_tunnel() {
        timeout(Duration::from_secs(3), async {
            let (relay_addr, relay_handle) = spawn_test_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = Arc::new(relay_stream_offer(rendezvous_token(0x92), &keypair));
            let params = Arc::new(params(keypair, Duration::from_millis(100)).await);
            let deps = data_tunnel_deps_arc("127.0.0.1:1".to_string());
            let claw = tokio::spawn(serve_relay_stream_responder_reverse_connect(
                reverse_config(relay_addr),
                Arc::clone(&offer),
                Arc::clone(&params),
                Arc::clone(&deps),
            ));

            let guest = connect_guest_with_hello(relay_addr, rendezvous_token(0x93)).await;
            let guest_key = guest_pub();
            let guest_result = timeout(
                Duration::from_millis(300),
                RelayStreamNoiseFramed::initiator_handshake(
                    guest,
                    &offer,
                    &owner_pub(),
                    &guest_key,
                    crate::claw_share_session_clock::wall_now_secs("test")
                        .expect("plausible clock"),
                ),
            )
            .await;
            assert!(guest_result.is_err() || guest_result.unwrap().is_err());

            let claw_error = claw.await.unwrap().unwrap_err();
            assert!(matches!(
                claw_error,
                RelayStreamResponderReverseConnectError::Responder(
                    RelayStreamResponderError::HandshakeTimeout
                )
            ));
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relay_stream_reverse_connect_attacker_offer_fails_before_auth() {
        timeout(Duration::from_secs(3), async {
            let (relay_addr, relay_handle) = spawn_test_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = Arc::new(relay_stream_offer_signed_by(
                rendezvous_token(0x94),
                &keypair,
                &attacker_signer(),
            ));
            let params = Arc::new(params(keypair, Duration::from_secs(1)).await);
            let deps = data_tunnel_deps_arc("127.0.0.1:1".to_string());
            let claw = tokio::spawn(serve_relay_stream_responder_reverse_connect(
                reverse_config(relay_addr),
                Arc::clone(&offer),
                Arc::clone(&params),
                Arc::clone(&deps),
            ));

            let guest =
                connect_guest_with_hello(relay_addr, offer.payload.rendezvous_token.clone()).await;
            let guest_key = guest_pub();
            let result = RelayStreamNoiseFramed::initiator_handshake(
                guest,
                &offer,
                &attacker_signer().public(),
                &guest_key,
                crate::claw_share_session_clock::wall_now_secs("test").expect("plausible clock"),
            )
            .await;
            assert!(result.is_err());
            assert!(claw.await.unwrap().is_err());
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relay_stream_reverse_connect_rejects_non_loopback_relay_addr() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = Arc::new(relay_stream_offer(rendezvous_token(0x95), &keypair));
        let params = Arc::new(params(keypair, Duration::from_secs(1)).await);
        let error = serve_relay_stream_responder_reverse_connect(
            reverse_config("0.0.0.0:49152".parse().unwrap()),
            offer,
            params,
            data_tunnel_deps_arc("127.0.0.1:1".to_string()),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            RelayStreamResponderReverseConnectError::NonLoopbackRelayAddr
        ));
    }

    #[test]
    fn relay_stream_reverse_connect_accepts_non_loopback_with_explicit_opt_in() {
        let config = RelayStreamResponderReverseConnectConfig {
            relay_addr: "0.0.0.0:49152".parse().unwrap(),
            connect_timeout: Duration::from_secs(1),
            hello_timeout: Duration::from_secs(1),
            allow_non_loopback_relay_addr: true,
        };

        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn relay_stream_reverse_connected_hello_write_is_bounded() {
        timeout(Duration::from_secs(2), async {
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = relay_stream_offer(rendezvous_token(0x96), &keypair);
            let params = params(keypair, Duration::from_secs(1)).await;
            let deps = data_tunnel_deps_arc("127.0.0.1:1".to_string());
            let (stream, _peer) = duplex(1);
            let error = serve_relay_stream_responder_reverse_connected(
                stream,
                &offer,
                &params,
                capture_admission().expect("test host clock must be plausible"),
                &deps,
                RelayStreamResponderReverseConnectConfig {
                    relay_addr: "127.0.0.1:49152".parse().unwrap(),
                    connect_timeout: Duration::from_secs(1),
                    hello_timeout: Duration::from_millis(25),
                    allow_non_loopback_relay_addr: false,
                },
            )
            .await
            .unwrap_err();

            assert!(matches!(
                error,
                RelayStreamResponderReverseConnectError::HelloTimeout
            ));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relay_stream_reverse_connect_unhealthy_admission_does_not_dial() {
        use crate::claw_share_relay_stream_admission::RelayStreamAdmission;
        use crate::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
        use crate::claw_share_relay_stream_test_support::relay_stream_household_state;
        use crate::claw_share_relay_stream_trust_context_health::{
            RelayStreamTrustContextRefreshPolicy, RelayStreamTrustContextRuntime,
        };
        use household_rs::household_mesh_log::MeshLogStore;

        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = Arc::new(relay_stream_offer(rendezvous_token(0x97), &keypair));

        // Runtime whose last success is far in the past versus a 1s staleness
        // bound: admission fails closed.
        let policy = RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(1), 1).unwrap();
        let runtime = RelayStreamTrustContextRuntime::load(
            &relay_stream_household_state(),
            &MeshLogStore::new(),
            crate::claw_share_session_clock::wall_now_secs("test")
                .expect("plausible clock")
                .saturating_sub(10_000),
            policy,
        )
        .await
        .unwrap();
        let params = Arc::new(RelayStreamResponderParams {
            bind_addr: "127.0.0.1:49152".parse().unwrap(),
            auth_deadline: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(60),
            admission: RelayStreamAdmission::new(Arc::new(runtime)),
            noise_keypair: keypair,
        });
        // Loopback port with no listener: had we reached the dial, the error would
        // be a connect failure. An Admission error proves admit ran first.
        let error = serve_relay_stream_responder_reverse_connect(
            reverse_config("127.0.0.1:1".parse().unwrap()),
            offer,
            params,
            data_tunnel_deps_arc("127.0.0.1:1".to_string()),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            RelayStreamResponderReverseConnectError::Admission(_)
        ));
    }
}
