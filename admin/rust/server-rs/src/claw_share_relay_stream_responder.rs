//! Per-connection Product A `relay_stream` responder endpoint.
//!
//! This module does not bind sockets, spawn accept loops, discover offers,
//! advertise `relay_stream`, or wire bootstrap/iOS. The rendezvous relay stays
//! a blind byte splicer; this function is the claw endpoint that receives an
//! already-selected offer and already-assembled responder params.

use std::fmt;
use std::sync::Arc;

use household_rs::claw_share::{ClawShareSlotStore, SlotState};
use household_rs::claw_share::data_tunnel::{
    AuthEnvelope, ClawTargetRouter, DataTunnelError, ReplayGuard, authorize_session,
    serve_connection_io_with_auth_deadline,
};
use household_rs::ids::HouseholdId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::claw_share_relay_stream_contract::{
    RelayStreamAudience, RelayStreamOfferContract, RelayStreamResource,
};
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;
use crate::claw_share_relay_stream_noise::{RelayStreamNoiseError, responder_handshake_with_trust};
use crate::claw_share_relay_stream_reopen_limiter::ReopenStreamLimiter;
use crate::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
use crate::claw_share_relay_stream_session::{
    RelayStreamDeviceSession, RelayStreamOfferSession, relay_stream_offer_session_revoked,
    verify_relay_stream_offer_session,
};
use crate::claw_share_session_clock::{AdmissionInstant, ClockVerdict, SessionClock};

pub struct ResponderDataTunnelDeps<R> {
    pub household_id: HouseholdId,
    pub slots: Arc<ClawShareSlotStore>,
    pub replay: Arc<ReplayGuard>,
    pub router: R,
    /// Per-`(claw_id, guest_device_pub)` reopen-rate gate for `ClawSite`
    /// dials — see `claw_share_relay_stream_reopen_limiter` for why this is
    /// independent of the `OpenPersistent` per-connection byte/open budget.
    /// The Group/Public arm invokes it on the offer's authenticated pair and
    /// the Device arm on the authorized credential's pair, both ONLY when the
    /// resource is `RelayStreamResource::ClawSite` — `IpTunnel` (Product
    /// A/nvpn's T1 datapath) and `Pty` stay untouched.
    pub reopen_limiter: Arc<ReopenStreamLimiter>,
}

impl<R> ResponderDataTunnelDeps<R> {
    #[must_use]
    pub fn new(
        household_id: HouseholdId,
        slots: Arc<ClawShareSlotStore>,
        replay: Arc<ReplayGuard>,
        router: R,
        reopen_limiter: Arc<ReopenStreamLimiter>,
    ) -> Self {
        Self {
            household_id,
            slots,
            replay,
            router,
            reopen_limiter,
        }
    }
}

impl<R> fmt::Debug for ResponderDataTunnelDeps<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponderDataTunnelDeps")
            .field("household_id", &self.household_id)
            .field("slots", &"ClawShareSlotStore(redacted)")
            .field("replay", &"ReplayGuard(redacted)")
            .field("router", &"redacted")
            .field("reopen_limiter", &"redacted")
            .finish()
    }
}

pub async fn serve_relay_stream_responder_connection<S, R>(
    stream: S,
    offer: &RelayStreamOfferContract,
    params: &RelayStreamResponderParams,
    trust: &RelayStreamIssuerTrust,
    admission: AdmissionInstant,
    deps: &ResponderDataTunnelDeps<R>,
) -> Result<(), RelayStreamResponderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: ClawTargetRouter,
{
    serve_relay_stream_responder_connection_with_live_clock(
        stream,
        offer,
        params,
        trust,
        admission,
        deps,
        Arc::new(SessionClock::live_now),
    )
    .await
}

type SessionLiveNow =
    Arc<dyn Fn(&SessionClock) -> Result<u64, ClockVerdict> + Send + Sync + 'static>;

#[allow(clippy::too_many_arguments)]
async fn serve_relay_stream_responder_connection_with_live_clock<S, R>(
    stream: S,
    offer: &RelayStreamOfferContract,
    params: &RelayStreamResponderParams,
    trust: &RelayStreamIssuerTrust,
    admission: AdmissionInstant,
    deps: &ResponderDataTunnelDeps<R>,
    live_now: SessionLiveNow,
) -> Result<(), RelayStreamResponderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: ClawTargetRouter,
{
    // The SAME admission wall reading feeds the handshake and the auth gate —
    // no caller reads its own `now`.
    let now_unix = admission.wall();

    // Dual-clock authority for this session, derived ONCE from the admission
    // pair and never recaptured. Built BEFORE the Noise handshake so an
    // admission that has already expired cannot reach it, and re-checked right
    // after, so the time spent in dial/hello/scheduling cannot carry a stale
    // admission into Open. Applies to EVERY audience.
    let clock = SessionClock::admit(
        admission,
        offer.payload.not_after,
        "claw_share.relay_stream.session",
    )
    .map_err(|_| RelayStreamResponderError::ClockUnusable)?;
    live_now(&clock).map_err(|_| RelayStreamResponderError::ClockUnusable)?;

    // `trust` is the per-connection seam admitted upstream; this fn never holds
    // a long-lived seam, so the admission health gate is applied per connection.
    let framed = timeout(
        params.auth_deadline,
        responder_handshake_with_trust(
            stream,
            offer,
            trust,
            now_unix,
            params.noise_keypair.private_key(),
        ),
    )
    .await
    .map_err(|_| RelayStreamResponderError::HandshakeTimeout)??;

    // The handshake can take up to `auth_deadline`; re-check before Open so a
    // session whose signed bound passed meanwhile cannot proceed.
    live_now(&clock).map_err(|_| RelayStreamResponderError::ClockUnusable)?;

    let noise_stream = framed.into_async_stream();

    match offer.payload.audience() {
        // Device (1:1 slot): credential auth, then slot revocation OR clock
        // failure. The mid-session predicate includes the clock term, so an
        // unusable/regressed clock or a passed `not_after` tears a Device
        // session down like any other audience.
        RelayStreamAudience::Device => {
            let household_id = deps.household_id.clone();
            let auth_slots = Arc::clone(&deps.slots);
            let replay = Arc::clone(&deps.replay);
            let revocation_slots = Arc::clone(&deps.slots);
            let device_clock = clock.clone();
            let device_live_now = Arc::clone(&live_now);
            let reopen_limiter = Arc::clone(&deps.reopen_limiter);
            // Persistent-target eligibility keys on the OFFER's signed resource
            // (ClawSite only); the ack stays byte-identical because the wrapper
            // delegates session_id/mesh_ipv6 to the inner credential verbatim.
            let device_resource = offer.payload.resource;
            serve_connection_io_with_auth_deadline(
                noise_stream,
                now_unix,
                move |envelope: &AuthEnvelope, now| {
                    let cred =
                        authorize_session(envelope, &household_id, &auth_slots, &replay, now)?;
                    // ClawSite-only (same boundary as Group/Public): the
                    // per-connection budget resets on every reconnect, so bound
                    // how often this AUTHENTICATED principal mints a fresh one.
                    // Keyed on the authorized credential's own pair — never on
                    // caller-claimed fields before auth — and never consulted
                    // for Pty (legacy reconnects) or IpTunnel (Product A/nvpn).
                    if device_resource == RelayStreamResource::ClawSite {
                        reopen_limiter.check_and_record(
                            &cred.claw_id,
                            &cred.guest_device_pub,
                            now,
                        )?;
                    }
                    Ok(RelayStreamDeviceSession::new(cred, device_resource))
                },
                &deps.router,
                move |session: &RelayStreamDeviceSession| {
                    // Slot revocation OR clock failure. Without the clock term a
                    // Device session would survive an unusable/regressed clock
                    // and a passed `not_after` — the same mid-session fail-open
                    // the Group/Public path closes.
                    if device_live_now(&device_clock).is_err() {
                        return true;
                    }
                    matches!(
                        revocation_slots
                            .get(&session.credential().slot_id)
                            .map(|record| record.state),
                        Some(SlotState::Revoked { .. })
                    )
                },
                params.auth_deadline,
            )
            .await?;
        }
        // Group/Public (Fase E2.5/E3): credential-less PoP auth. The SOLE
        // authorization authority is the live gate — the mid-session predicate
        // re-runs the FULL open gate (verify_offer_with_context + the audience
        // branch) on a LIVE clock, polled on both the revoke tick and per inbound
        // Data frame, so a removed member / revoked grant / unpublished site /
        // expired offer / issuer-removed signer tears the LIVE session down. The
        // verifier + Rev read audience + guest_device_pub from THIS `offer` (the
        // same one the handshake + router used — single-source binding).
        RelayStreamAudience::Group { .. } | RelayStreamAudience::Public => {
            let verify_replay = Arc::clone(&deps.replay);
            let reopen_limiter = Arc::clone(&deps.reopen_limiter);
            let rev_offer = offer.clone();
            let rev_trust = trust.clone();
            let rev_live_now = Arc::clone(&live_now);
            // Reuses the SAME `clock` built pre-handshake — no recapture, which
            // would restart the session's life. Previously this closure read the
            // wall clock with `map_or(0, ..)`, so a host at/before the epoch
            // produced now = 0 and `relay_stream_offer_session_revoked` never
            // fired: a broken clock KEPT a live session that should have died.
            serve_connection_io_with_auth_deadline(
                noise_stream,
                now_unix,
                move |envelope: &AuthEnvelope, now| {
                    // Reopen-rate check runs AFTER possession is proven, keyed
                    // on the SAME (claw_id, guest_device_pub) the proof just
                    // authenticated — checking on caller-claimed fields before
                    // this would let an attacker burn another principal's
                    // bucket by spoofing its key.
                    let session =
                        verify_relay_stream_offer_session(offer, &verify_replay, envelope, now)?;
                    // ClawSite-only: this gate exists because of the ClawSite
                    // OpenPersistent byte/open budget specifically, not as a
                    // general Group/Public throttle. Pty can't reach here at
                    // all (validate_resource_for_audience already forbids Pty
                    // for Group/Public). IpTunnel — Product A/nvpn's T1
                    // datapath, reachable in dev_t1_datapath builds — must
                    // stay byte-identical/unbucketed: applying a ClawSite
                    // control there would extend into Product A/nvpn without
                    // authorization.
                    if offer.payload.resource == RelayStreamResource::ClawSite {
                        reopen_limiter.check_and_record(
                            &offer.payload.claw_id,
                            &offer.payload.guest_device_pub,
                            now,
                        )?;
                    }
                    Ok(session)
                },
                &deps.router,
                move |_session: &RelayStreamOfferSession| {
                    // A clock that cannot be trusted REVOKES: implausible or
                    // regressed wall, the signed `not_after` passing, the
                    // monotonic deadline passing, or any overflow.
                    let Ok(now) = rev_live_now(&clock) else {
                        return true;
                    };
                    relay_stream_offer_session_revoked(&rev_offer, &rev_trust, now)
                },
                params.auth_deadline,
            )
            .await?;
        }
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamResponderError {
    #[error("relay stream responder Noise handshake timed out")]
    HandshakeTimeout,

    #[error("relay stream responder Noise failed: {0}")]
    Noise(#[from] RelayStreamNoiseError),

    #[error("relay stream responder data tunnel failed: {0}")]
    DataTunnel(#[from] DataTunnelError),

    /// The wall clock is unusable, or the offer is already expired at
    /// admission. Refused BEFORE Open: with a broken clock expiry cannot be
    /// enforced at all, so serving would be fail-open.
    #[error("relay stream responder refused: implausible clock or expired offer at admission")]
    ClockUnusable,
}

#[cfg(test)]
mod tests;
