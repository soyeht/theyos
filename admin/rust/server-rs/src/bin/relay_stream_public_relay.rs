//! Standalone public `relay_stream` rendezvous helper.
//!
//! This binary is default-off and intentionally separate from the engine:
//! it owns only the public TCP listener and the blind rendezvous splicer. It
//! does not load household state, owner keys, catalog state, router mappings,
//! or any Product A engine services. The production shape is a supervised
//! helper with a small blast radius, not a public listener hosted in the engine.
//!
//! Enable it explicitly with:
//!
//! - `THEYOS_RELAY_STREAM_PUBLIC_RELAY=1`
//! - `THEYOS_RELAY_STREAM_PUBLIC_BIND_ADDR=<literal-ip>:49152`
//!
//! The bind address must be a concrete non-loopback, non-wildcard IP literal.
//! Hostnames are rejected in this first production-shaped cut so the operator
//! sees exactly which interface is exposed.

use std::io::{self, ErrorKind};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use server_rs::claw_share_relay_stream_public_relay_config::{
    RELAY_STREAM_PUBLIC_RELAY_ENV, RelayStreamPublicRelayConfig,
};
use server_rs::claw_share_rendezvous_stream_relay_listener::serve_rendezvous_stream_relay_with_status;
use server_rs::claw_share_rendezvous_stream_relay_status::RendezvousStreamRelayStatusHandle;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[tokio::main]
async fn main() -> io::Result<()> {
    let Some(config) = RelayStreamPublicRelayConfig::from_env().map_err(|error| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid relay_stream public relay config: {error}"),
        )
    })?
    else {
        eprintln!(
            "relay_stream public relay disabled ({RELAY_STREAM_PUBLIC_RELAY_ENV} is not enabled)"
        );
        return Ok(());
    };

    let listener = TcpListener::bind(config.bind_addr).await?;
    let local_addr = listener.local_addr()?;
    let status =
        RendezvousStreamRelayStatusHandle::new(local_addr.to_string(), true, &config.listener);
    let status_server = match &config.status {
        Some(status_config) => Some(
            spawn_status_server(
                status_config.bind_addr,
                read_status_token_file(&status_config.token_file)?,
                status.clone(),
            )
            .await?,
        ),
        None => None,
    };
    eprintln!(
        "WARNING: relay_stream public relay binding {local_addr}. This standalone helper accepts \
         unauthenticated public TCP rendezvous hellos and must run only under explicit owner/operator \
         supervision. Payload is end-to-end encrypted by guest<->claw Noise; the relay remains a \
         blind splicer and must not log tokens or payload."
    );
    eprintln!(
        "relay_stream public relay limits: global_active={} pending={} token_ttl_secs={} \
         idle_timeout_secs={} splice_lifetime_secs={} source_unpaired={} source_pending={} \
         source_paired={:?} source_buckets={} ipv6_prefix_len={}",
        config.listener.max_active_connections,
        config.listener.max_pending,
        config.listener.token_ttl.as_secs(),
        config.listener.splice_idle_timeout.as_secs(),
        config.listener.splice_max_lifetime.as_secs(),
        config.listener.abuse.max_unpaired_active_per_source,
        config.listener.abuse.max_pending_per_source,
        config.listener.abuse.max_paired_splices_per_source,
        config.listener.abuse.max_source_buckets,
        config.listener.abuse.ipv6_source_prefix_len,
    );

    let handle = serve_rendezvous_stream_relay_with_status(listener, config.listener, status);
    tokio::signal::ctrl_c().await?;
    eprintln!("relay_stream public relay shutting down");
    handle.abort();
    if let Some(status_server) = status_server {
        status_server.abort();
    }
    Ok(())
}

#[derive(Clone)]
struct StatusServerState {
    status: RendezvousStreamRelayStatusHandle,
    bearer_token: Arc<str>,
}

async fn spawn_status_server(
    bind_addr: std::net::SocketAddr,
    bearer_token: String,
    status: RendezvousStreamRelayStatusHandle,
) -> io::Result<JoinHandle<io::Result<()>>> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    let state = StatusServerState {
        status,
        bearer_token: Arc::<str>::from(bearer_token),
    };
    let app = Router::new()
        .route("/status", get(handle_status))
        .with_state(state);
    eprintln!(
        "relay_stream public relay status listening on {local_addr} (loopback, bearer-token auth)"
    );
    Ok(tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .map_err(|error| io::Error::other(format!("status server failed: {error}")))
    }))
}

async fn handle_status(
    State(state): State<StatusServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !authorized(&headers, &state.bearer_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(state.status.snapshot()).into_response()
}

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    value
        .strip_prefix("Bearer ")
        .is_some_and(|provided| provided.as_bytes().ct_eq(expected.as_bytes()).into())
}

fn read_status_token_file(path: &std::path::Path) -> io::Result<String> {
    let token = std::fs::read_to_string(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to read relay_stream status token file: {error}"),
        )
    })?;
    parse_status_token(token)
}

fn parse_status_token(token: String) -> io::Result<String> {
    let token = token.trim().to_string();
    if token.len() < 32 || token.chars().any(char::is_whitespace) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "relay_stream status bearer token must be at least 32 non-whitespace characters",
        ));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_token_requires_long_non_whitespace_secret() {
        assert!(parse_status_token("short".to_string()).is_err());
        assert!(parse_status_token("abcdefghijklmnopqrstuvwxyz123456".to_string()).is_ok());
        assert!(parse_status_token("abcdefghijklmnopqrstuvwxyz123456\n".to_string()).is_ok());
        assert!(parse_status_token("abcdefghijklmnopqrstuvwxyz 123456".to_string()).is_err());
    }

    #[test]
    fn status_endpoint_authorizes_only_matching_bearer_token() {
        let token = "abcdefghijklmnopqrstuvwxyz123456";
        let mut headers = HeaderMap::new();
        assert!(!authorized(&headers, token));

        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(!authorized(&headers, token));

        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}x").parse().unwrap(),
        );
        assert!(!authorized(&headers, token));

        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert!(authorized(&headers, token));
    }
}
