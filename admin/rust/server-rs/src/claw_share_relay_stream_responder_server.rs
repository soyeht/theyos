//! Default-off loopback accept loop for the Product A `relay_stream` responder.
//!
//! This is still not product-wired: no offer store, no claim ack, no bootstrap,
//! no iOS, and no public advertise. A caller must inject one already-selected
//! offer and the data-tunnel dependencies at init. The rendezvous relay remains
//! a blind byte splicer; this server is the claw endpoint.

use std::net::SocketAddr;
use std::sync::Arc;

use household_rs::claw_share::data_tunnel::ClawTargetRouter;
use keystore_rs::KeystoreBackend;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::claw_share_relay_stream_admission::RelayStreamAdmission;
use crate::claw_share_relay_stream_contract::RelayStreamOfferContract;
use crate::claw_share_relay_stream_responder::{
    ResponderDataTunnelDeps, serve_relay_stream_responder_connection,
};
use crate::claw_share_relay_stream_responder_config::RelayStreamResponderConfig;
use crate::claw_share_relay_stream_responder_params::{
    RelayStreamResponderParams, RelayStreamResponderParamsError,
    assemble_relay_stream_responder_params,
};
use crate::claw_share_session_clock::AdmissionInstant;

const DEFAULT_MAX_ACTIVE_CONNECTIONS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStreamResponderServerConfig {
    pub max_active_connections: usize,
}

impl Default for RelayStreamResponderServerConfig {
    fn default() -> Self {
        Self {
            max_active_connections: DEFAULT_MAX_ACTIVE_CONNECTIONS,
        }
    }
}

impl RelayStreamResponderServerConfig {
    pub fn validate(self) -> Result<Self, RelayStreamResponderServerError> {
        if self.max_active_connections == 0 {
            return Err(RelayStreamResponderServerError::InvalidMaxActiveConnections);
        }
        Ok(self)
    }
}

pub async fn spawn_relay_stream_responder_if_enabled<R>(
    config: Option<RelayStreamResponderConfig>,
    server_config: RelayStreamResponderServerConfig,
    keystore_backend: &dyn KeystoreBackend,
    admission: RelayStreamAdmission,
    offer: Arc<RelayStreamOfferContract>,
    deps: Arc<ResponderDataTunnelDeps<R>>,
) -> Result<Option<JoinHandle<()>>, RelayStreamResponderServerError>
where
    R: ClawTargetRouter + Send + Sync + 'static,
{
    let Some(config) = config else {
        return Ok(None);
    };
    if !config.enabled {
        return Ok(None);
    }
    let server_config = server_config.validate()?;
    validate_runtime_bind_addr(config.bind_addr)?;

    let params =
        match assemble_relay_stream_responder_params(&config, keystore_backend, admission).await {
            Ok(params) => params,
            Err(RelayStreamResponderParamsError::Disabled) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    let listener = TcpListener::bind(params.bind_addr)
        .await
        .map_err(|source| RelayStreamResponderServerError::Bind {
            addr: params.bind_addr,
            source,
        })?;

    spawn_relay_stream_responder_on_listener(listener, server_config, Arc::new(params), offer, deps)
        .map(Some)
}

pub async fn spawn_relay_stream_responder<R>(
    config: RelayStreamResponderConfig,
    server_config: RelayStreamResponderServerConfig,
    keystore_backend: &dyn KeystoreBackend,
    admission: RelayStreamAdmission,
    offer: Arc<RelayStreamOfferContract>,
    deps: Arc<ResponderDataTunnelDeps<R>>,
) -> Result<Option<JoinHandle<()>>, RelayStreamResponderServerError>
where
    R: ClawTargetRouter + Send + Sync + 'static,
{
    spawn_relay_stream_responder_if_enabled(
        Some(config),
        server_config,
        keystore_backend,
        admission,
        offer,
        deps,
    )
    .await
}

pub fn spawn_relay_stream_responder_on_listener<R>(
    listener: TcpListener,
    server_config: RelayStreamResponderServerConfig,
    params: Arc<RelayStreamResponderParams>,
    offer: Arc<RelayStreamOfferContract>,
    deps: Arc<ResponderDataTunnelDeps<R>>,
) -> Result<JoinHandle<()>, RelayStreamResponderServerError>
where
    R: ClawTargetRouter + Send + Sync + 'static,
{
    let server_config = server_config.validate()?;
    let local_addr = listener
        .local_addr()
        .map_err(RelayStreamResponderServerError::LocalAddr)?;
    validate_runtime_bind_addr(local_addr)?;

    let semaphore = Arc::new(Semaphore::new(server_config.max_active_connections));
    Ok(tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(
                        stage = "claw_share.relay_stream_responder.accept_error",
                        error = %error,
                    );
                    break;
                }
            };

            let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                tracing::debug!(
                    stage = "claw_share.relay_stream_responder.connection_rejected",
                    %peer,
                    reason = "active-cap"
                );
                drop(stream);
                continue;
            };

            // Clock gate, BEFORE the admission seam and any handshake: capture
            // the (wall, monotonic) pair ONCE for this connection. `None` means
            // the wall clock is unusable (before the epoch, at it, or below the
            // sanity floor), and with a broken clock `not_after` can never be
            // enforced — so refuse rather than serve fail-open. This same pair
            // is transported downstream; nothing recaptures an anchor later.
            let Some(admission_instant) =
                AdmissionInstant::capture("claw_share.relay_stream_responder.admission")
            else {
                tracing::warn!(
                    stage = "claw_share.relay_stream_responder.clock_rejected",
                    %peer,
                    "refusing connection: implausible system clock",
                );
                drop(stream);
                continue;
            };
            let accepted_at = admission_instant.wall();

            // C4c admission gate: mint a per-connection trust seam only while
            // the runtime is healthy; otherwise refuse to serve fail-closed,
            // before any Noise handshake or data-tunnel authorization.
            let trust = match params.admission.admit(accepted_at) {
                Ok(trust) => trust,
                Err(error) => {
                    tracing::debug!(
                        stage = "claw_share.relay_stream_responder.admission_rejected",
                        %peer,
                        error = %error,
                    );
                    drop(stream);
                    continue;
                }
            };

            let offer = Arc::clone(&offer);
            let params = Arc::clone(&params);
            let deps = Arc::clone(&deps);
            tokio::spawn(async move {
                let result = serve_relay_stream_responder_connection(
                    stream,
                    &offer,
                    &params,
                    &trust,
                    admission_instant,
                    &deps,
                )
                .await;
                match result {
                    Ok(()) => {
                        tracing::debug!(
                            stage = "claw_share.relay_stream_responder.connection_closed",
                            %peer,
                            result = "ok"
                        );
                    }
                    Err(error) => {
                        tracing::debug!(
                            stage = "claw_share.relay_stream_responder.connection_closed",
                            %peer,
                            result = "error",
                            error = %error
                        );
                    }
                }
                drop(permit);
            });
        }
    }))
}

fn validate_runtime_bind_addr(addr: SocketAddr) -> Result<(), RelayStreamResponderServerError> {
    if !addr.ip().is_loopback() {
        return Err(RelayStreamResponderServerError::NonLoopbackBindAddr);
    }
    if addr.port() == 0 {
        return Err(RelayStreamResponderServerError::InvalidBindAddrPort);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamResponderServerError {
    #[error("relay stream responder max active connections must be greater than zero")]
    InvalidMaxActiveConnections,

    #[error("relay stream responder bind address must be loopback")]
    NonLoopbackBindAddr,

    #[error("relay stream responder bind address port is invalid")]
    InvalidBindAddrPort,

    #[error("relay stream responder local address failed: {0}")]
    LocalAddr(std::io::Error),

    #[error("relay stream responder bind failed for {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("relay stream responder params failed: {0}")]
    Params(#[from] RelayStreamResponderParamsError),
}

#[cfg(test)]
mod tests;
