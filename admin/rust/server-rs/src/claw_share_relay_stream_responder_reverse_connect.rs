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

use household_rs::claw_share::data_tunnel::ClawTargetRouter;
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
mod tests;
