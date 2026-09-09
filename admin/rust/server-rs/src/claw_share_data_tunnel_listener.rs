//! Engine-side TCP listener for the claw-share data tunnel.
//!
//! Binds a TCP port and serves each connection through
//! [`household_rs::claw_share::data_tunnel::serve_connection`], using the
//! engine's live household id + slot store as the authorization policy
//! ([`authorize_credential`]). This is the real, reachable data-tunnel
//! endpoint the iOS bridge dials; the wire protocol + the credential
//! validation matrix are defined and tested in `household-rs`.
//!
//! Authorization never consults the source address — a connection from
//! any IP with a valid, non-revoked, correctly-bound `GuestCredential`
//! is accepted, and an invalid one is rejected regardless of origin.
//!
//! Wired into the daemon in `household_bootstrap.rs` either behind an explicit
//! `THEYOS_CLAW_DATA_TUNNEL_ADDR` diagnostic bind or an overlay-only
//! `THEYOS_CLAW_DATA_TUNNEL_PORT` bind derived from the active overlay config.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use household_rs::claw_share::data_tunnel::{
    ReplayGuard, TcpStreamRouter, authorize_session, serve_connection,
};
use household_rs::claw_share::{ClawShareSlotStore, SlotState};
use household_rs::ids::HouseholdId;
use tokio::net::{TcpListener, TcpStream};

use crate::claw_share_pty_target::{PtyPolicy, PtyTargetRouter};
use crate::household_state::HouseholdState;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What an authenticated session opens on the engine.
///
/// `Pty` (the default) spawns a real, policy-controlled interactive shell on
/// a local PTY — the friend gets a usable terminal. `Tcp` forwards to a fixed
/// address (an SSH endpoint or a staging fixture); it is raw bytes with no
/// terminal resize / exit status.
#[derive(Debug, Clone)]
pub enum TargetSpec {
    Pty(PtyPolicy),
    Tcp(String),
}

/// Serve one connection: full session auth (credential + proof-of-possession
/// token, single-use via the shared `replay` guard) against the engine's
/// household id, then open the configured [`TargetSpec`] and pipe both ways.
/// Revoking the slot mid-session blocks the next frame. Split out so it is
/// testable without a full [`HouseholdState`].
async fn serve_conn(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    local: Option<std::net::SocketAddr>,
    hh_id: HouseholdId,
    slots: Arc<ClawShareSlotStore>,
    target: TargetSpec,
    replay: Arc<ReplayGuard>,
) {
    let now = now_unix();
    tracing::info!(
        stage = "claw_share.data_tunnel.conn_start",
        %peer,
        local = local.map_or_else(|| "unknown".to_string(), |a| a.to_string()),
        target = ?target,
        now_unix = now,
    );
    let auth_slots = Arc::clone(&slots);
    // Per-frame revocation check: re-read the credential's slot live state.
    let rev_slots = Arc::clone(&slots);
    let verify =
        move |envelope: &_, n| authorize_session(envelope, &hh_id, &auth_slots, &replay, n);
    let is_revoked = move |cred: &household_rs::claw_share::GuestCredential| {
        matches!(
            rev_slots.get(&cred.slot_id).map(|r| r.state),
            Some(SlotState::Revoked { .. })
        )
    };
    let result = match target {
        TargetSpec::Tcp(addr) => {
            let router = TcpStreamRouter::new(addr);
            serve_connection(stream, now, verify, &router, is_revoked).await
        }
        TargetSpec::Pty(policy) => {
            let router = PtyTargetRouter::new(policy);
            serve_connection(stream, now, verify, &router, is_revoked).await
        }
    };
    match result {
        Ok(()) => {
            tracing::info!(stage = "claw_share.data_tunnel.conn_closed", %peer, result = "ok");
        }
        Err(e) => {
            tracing::warn!(stage = "claw_share.data_tunnel.conn_closed", %peer, result = "error", error = %e);
        }
    }
}

/// Accept loop. Resolves the engine's household id per connection so an
/// identity that loads (or rotates) after startup is picked up. A
/// connection that arrives before the identity is loaded is dropped.
/// `target` is what each authenticated session opens (interactive PTY, or a
/// forwarded address).
pub async fn serve(
    listener: TcpListener,
    household: HouseholdState,
    slots: Arc<ClawShareSlotStore>,
    target: TargetSpec,
) {
    // One replay guard per listener — single-use tokens across all
    // connections this engine accepts.
    serve_with_replay(
        listener,
        household,
        slots,
        target,
        Arc::new(ReplayGuard::new()),
    )
    .await;
}

/// Same accept loop as [`serve`], with an injected replay guard. Used when the
/// engine exposes more than one listener for the same claw-share data tunnel so
/// a token accepted on one socket cannot be replayed on its sibling.
pub async fn serve_with_replay(
    listener: TcpListener,
    household: HouseholdState,
    slots: Arc<ClawShareSlotStore>,
    target: TargetSpec,
    replay: Arc<ReplayGuard>,
) {
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(stage = "claw_share.data_tunnel.accept_failed", error = %e);
                continue;
            }
        };
        let local = sock.local_addr().ok();
        tracing::info!(
            stage = "claw_share.data_tunnel.accepted",
            %peer,
            local = local.map_or_else(|| "unknown".to_string(), |a| a.to_string()),
        );
        let Some(identity) = household.current().await else {
            tracing::warn!(
                stage = "claw_share.data_tunnel.no_identity",
                %peer,
                "dropping data-tunnel connection — household identity not loaded yet",
            );
            continue;
        };
        let hh_id = identity.record.hh_id.clone();
        let slots = Arc::clone(&slots);
        tokio::spawn(serve_conn(
            sock,
            peer,
            local,
            hh_id,
            slots,
            target.clone(),
            Arc::clone(&replay),
        ));
    }
}

/// Bind `addr` and spawn the accept loop on the current Tokio runtime.
/// Logs and returns without spawning if the bind fails (the rest of the
/// daemon keeps running). `target` is what each session opens.
pub async fn spawn(
    addr: &str,
    household: HouseholdState,
    slots: Arc<ClawShareSlotStore>,
    target: TargetSpec,
) -> Option<tokio::task::JoinHandle<()>> {
    spawn_with_replay(addr, household, slots, target, Arc::new(ReplayGuard::new())).await
}

/// Bind `addr` and spawn the accept loop using a caller-provided replay guard.
pub async fn spawn_with_replay(
    addr: &str,
    household: HouseholdState,
    slots: Arc<ClawShareSlotStore>,
    target: TargetSpec,
    replay: Arc<ReplayGuard>,
) -> Option<tokio::task::JoinHandle<()>> {
    spawn_with_replay_inner(addr, household, slots, target, replay, None).await
}

/// Bind `addr`, spawn the accept loop, and label the listener in logs.
pub async fn spawn_labeled_with_replay(
    addr: &str,
    listener: &'static str,
    household: HouseholdState,
    slots: Arc<ClawShareSlotStore>,
    target: TargetSpec,
    replay: Arc<ReplayGuard>,
) -> Option<tokio::task::JoinHandle<()>> {
    spawn_with_replay_inner(addr, household, slots, target, replay, Some(listener)).await
}

async fn spawn_with_replay_inner(
    addr: &str,
    household: HouseholdState,
    slots: Arc<ClawShareSlotStore>,
    target: TargetSpec,
    replay: Arc<ReplayGuard>,
    listener_role: Option<&'static str>,
) -> Option<tokio::task::JoinHandle<()>> {
    match TcpListener::bind(addr).await {
        Ok(tcp_listener) => {
            let bound = tcp_listener
                .local_addr()
                .map_or_else(|_| addr.to_string(), |a| a.to_string());
            if let Some(role) = listener_role {
                tracing::info!(
                    stage = "claw_share.data_tunnel.listening",
                    listener = role,
                    addr = %bound,
                    target = ?target,
                    "claw-share data tunnel listening"
                );
            } else {
                tracing::info!(stage = "claw_share.data_tunnel.listening", addr = %bound, target = ?target, "claw-share data tunnel listening");
            }
            Some(tokio::spawn(serve_with_replay(
                tcp_listener,
                household,
                slots,
                target,
                replay,
            )))
        }
        Err(e) => {
            if let Some(role) = listener_role {
                tracing::error!(
                    stage = "claw_share.data_tunnel.bind_failed",
                    listener = role,
                    addr = %addr,
                    error = %e,
                    "claw-share data tunnel disabled"
                );
            } else {
                tracing::error!(stage = "claw_share.data_tunnel.bind_failed", addr = %addr, error = %e, "claw-share data tunnel disabled");
            }
            None
        }
    }
}

#[cfg(test)]
mod tests;
