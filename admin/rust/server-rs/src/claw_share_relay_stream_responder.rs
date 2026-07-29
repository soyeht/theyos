//! Per-connection Product A `relay_stream` responder endpoint.
//!
//! This module does not bind sockets, spawn accept loops, discover offers,
//! advertise `relay_stream`, or wire bootstrap/iOS. The rendezvous relay stays
//! a blind byte splicer; this function is the claw endpoint that receives an
//! already-selected offer and already-assembled responder params.

use std::fmt;
use std::sync::Arc;

use household_rs::claw_share::{ClawShareSlotStore, GuestCredential, SlotState};
use household_rs::claw_share_data_tunnel::{
    AuthEnvelope, ClawTargetRouter, DataTunnelError, ReplayGuard, authorize_session,
    serve_connection_io_with_auth_deadline,
};
use household_rs::ids::HouseholdId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::claw_share_relay_stream_contract::{RelayStreamAudience, RelayStreamOfferContract};
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;
use crate::claw_share_relay_stream_noise::{RelayStreamNoiseError, responder_handshake_with_trust};
use crate::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
use crate::claw_share_relay_stream_session::{
    RelayStreamOfferSession, relay_stream_offer_session_revoked, verify_relay_stream_offer_session,
};
use crate::claw_share_session_clock::{AdmissionInstant, ClockVerdict, SessionClock};

pub struct ResponderDataTunnelDeps<R> {
    pub household_id: HouseholdId,
    pub slots: Arc<ClawShareSlotStore>,
    pub replay: Arc<ReplayGuard>,
    pub router: R,
}

impl<R> ResponderDataTunnelDeps<R> {
    #[must_use]
    pub fn new(
        household_id: HouseholdId,
        slots: Arc<ClawShareSlotStore>,
        replay: Arc<ReplayGuard>,
        router: R,
    ) -> Self {
        Self {
            household_id,
            slots,
            replay,
            router,
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
            serve_connection_io_with_auth_deadline(
                noise_stream,
                now_unix,
                move |envelope: &AuthEnvelope, now| {
                    authorize_session(envelope, &household_id, &auth_slots, &replay, now)
                },
                &deps.router,
                move |cred: &GuestCredential| {
                    // Slot revocation OR clock failure. Without the clock term a
                    // Device session would survive an unusable/regressed clock
                    // and a passed `not_after` — the same mid-session fail-open
                    // the Group/Public path closes.
                    if device_live_now(&device_clock).is_err() {
                        return true;
                    }
                    matches!(
                        revocation_slots
                            .get(&cred.slot_id)
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
                    verify_relay_stream_offer_session(offer, &verify_replay, envelope, now)
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
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use household_rs::cbor;
    use household_rs::claw_share_data_tunnel::{
        HEALTH_PROBE, SessionAuthToken, TunnelAck, TunnelFrame, client_authenticate, client_health,
        client_open_stream, recv_frame, send_frame,
    };
    use household_rs::keys::P256Keypair;
    use tokio::io::duplex;

    use crate::claw_share_relay_stream_contract::{
        RelayStreamContractError, RelayStreamOfferContract, RelayStreamResource,
        mint_relay_stream_group_offer,
    };
    use crate::claw_share_relay_stream_issuer_trust::{
        RelayStreamIssuerTrust, RelayStreamTrustContext,
    };
    use crate::claw_share_relay_stream_noise::{
        RelayStreamNoiseError, generate_relay_stream_noise_static_keypair,
    };
    use crate::claw_share_relay_stream_test_support::{
        DATA_TUNNEL_SLOT, RELAY_STREAM_CLAW_ID, RELAY_STREAM_ENDPOINT, attacker_signer,
        data_tunnel_credential, data_tunnel_deps, data_tunnel_store,
        data_tunnel_token as support_data_tunnel_token,
        data_tunnel_token_signed as support_data_tunnel_token_signed, guest_pub, guest_signer,
        now_unix, owner_pub, owner_signer, relay_stream_household_record,
        relay_stream_machine_cert, relay_stream_offer, relay_stream_offer_signed_by,
        relay_stream_responder_params as params, rendezvous_token, spawn_ack_target,
    };
    use household_rs::claw_share::SlotId;
    use household_rs::household_mesh_log::{
        MeshMembership, ProjectedGroup, ProjectedMemberDevice, ProjectedState,
    };

    const TOKEN_AUDIENCE: &str = "relay-stream-responder-test";

    fn data_tunnel_token_signed(
        credential_cbor: &[u8],
        signer: &P256Keypair,
        nonce: &[u8],
    ) -> SessionAuthToken {
        support_data_tunnel_token_signed(TOKEN_AUDIENCE, credential_cbor, signer, nonce)
    }

    fn data_tunnel_token(credential_cbor: &[u8], nonce: &[u8]) -> SessionAuthToken {
        support_data_tunnel_token(TOKEN_AUDIENCE, credential_cbor, nonce)
    }

    fn device_offer_expiring_at(
        rendezvous_label: u8,
        keypair: &crate::claw_share_relay_stream_noise::RelayStreamNoiseStaticKeypair,
        not_after: u64,
    ) -> RelayStreamOfferContract {
        let mut offer = relay_stream_offer(rendezvous_token(rendezvous_label), keypair);
        offer.payload.not_after = not_after;
        RelayStreamOfferContract::sign(offer.payload, &owner_signer()).unwrap()
    }

    #[derive(Clone, Copy, Debug)]
    enum LiveClockFailure {
        Unusable,
        WallRegressed,
        SignedExpiryPassed,
    }

    fn controlled_live_now(
        armed: Arc<AtomicBool>,
        failure: LiveClockFailure,
        admitted_at: u64,
        not_after: u64,
    ) -> SessionLiveNow {
        Arc::new(move |clock| {
            if !armed.load(Ordering::SeqCst) {
                return clock.live_at_for_test(Some(admitted_at), Duration::ZERO);
            }
            match failure {
                LiveClockFailure::Unusable => {
                    clock.live_at_for_test(None, Duration::from_millis(1))
                }
                LiveClockFailure::WallRegressed => clock.live_at_for_test(
                    Some(crate::claw_share_session_clock::MIN_PLAUSIBLE_UNIX_SECS + 1),
                    Duration::from_secs(1),
                ),
                LiveClockFailure::SignedExpiryPassed => {
                    clock.live_at_for_test(Some(not_after), Duration::from_millis(1))
                }
            }
        })
    }

    async fn client_noise_stream(
        stream: tokio::io::DuplexStream,
        offer: &RelayStreamOfferContract,
        now: u64,
    ) -> crate::claw_share_relay_stream_noise::RelayStreamNoiseAsyncStream<tokio::io::DuplexStream>
    {
        let guest = guest_pub();
        crate::claw_share_relay_stream_noise::RelayStreamNoiseFramed::initiator_handshake(
            stream,
            offer,
            &owner_pub(),
            &guest,
            now,
        )
        .await
        .unwrap()
        .into_async_stream()
    }

    #[tokio::test]
    async fn relay_stream_responder_auth_ok_pipes_data_to_target() {
        timeout(Duration::from_secs(5), async {
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = relay_stream_offer(rendezvous_token(0x71), &keypair);
            let params = params(keypair, Duration::from_secs(2)).await;
            let slots = data_tunnel_store();
            let deps = data_tunnel_deps(
                Arc::clone(&slots),
                Arc::new(ReplayGuard::new()),
                spawn_ack_target().await,
            );
            let cbor = cbor::to_canonical_vec(&data_tunnel_credential()).unwrap();
            let (client_io, server_io) = duplex(64 * 1024);
            let serve_now = now_unix();
            let trust = params.admission.admit(serve_now).unwrap();

            let server = serve_relay_stream_responder_connection(
                server_io,
                &offer,
                &params,
                &trust,
                AdmissionInstant::from_seam_wall(serve_now).expect("plausible test clock"),
                &deps,
            );
            let client = async {
                let mut stream = client_noise_stream(client_io, &offer, serve_now).await;
                assert!(matches!(
                    client_authenticate(&mut stream, &cbor, data_tunnel_token(&cbor, b"ok"))
                        .await
                        .unwrap(),
                    TunnelAck::Ok { .. }
                ));
                assert_eq!(
                    client_health(&mut stream, HEALTH_PROBE).await.unwrap(),
                    HEALTH_PROBE
                );
                client_open_stream(&mut stream).await.unwrap();
                send_frame(&mut stream, &TunnelFrame::Data(b"via-responder".to_vec()))
                    .await
                    .unwrap();
                assert_eq!(
                    recv_frame(&mut stream).await.unwrap(),
                    TunnelFrame::Data(b"ACK:via-responder".to_vec())
                );
                send_frame(&mut stream, &TunnelFrame::Close).await.unwrap();
            };

            let (server_result, ()) = tokio::join!(server, client);
            server_result.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relay_stream_responder_bad_token_fails_closed_inside_noise() {
        timeout(Duration::from_secs(5), async {
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = relay_stream_offer(rendezvous_token(0x72), &keypair);
            let params = params(keypair, Duration::from_secs(2)).await;
            let slots = data_tunnel_store();
            let deps = data_tunnel_deps(
                Arc::clone(&slots),
                Arc::new(ReplayGuard::new()),
                "127.0.0.1:1".to_string(),
            );
            let cbor = cbor::to_canonical_vec(&data_tunnel_credential()).unwrap();
            let (client_io, server_io) = duplex(64 * 1024);
            let serve_now = now_unix();
            let trust = params.admission.admit(serve_now).unwrap();

            let server = serve_relay_stream_responder_connection(
                server_io,
                &offer,
                &params,
                &trust,
                AdmissionInstant::from_seam_wall(serve_now).expect("plausible test clock"),
                &deps,
            );
            let client = async {
                let mut stream = client_noise_stream(client_io, &offer, serve_now).await;
                match client_authenticate(
                    &mut stream,
                    &cbor,
                    data_tunnel_token_signed(&cbor, &attacker_signer(), b"bad-token"),
                )
                .await
                .unwrap()
                {
                    TunnelAck::Rejected { reason } => assert_eq!(reason, "signature-invalid"),
                    other => panic!("bad token must be rejected inside Noise, got {other:?}"),
                }
            };

            let (server_result, ()) = tokio::join!(server, client);
            assert!(matches!(
                server_result,
                Err(RelayStreamResponderError::DataTunnel(
                    DataTunnelError::TokenRejected(reason)
                )) if reason == "signature-invalid"
            ));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relay_stream_responder_revoke_post_open_tears_down_inside_noise() {
        timeout(Duration::from_secs(5), async {
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = relay_stream_offer(rendezvous_token(0x73), &keypair);
            let params = params(keypair, Duration::from_secs(2)).await;
            let slots = data_tunnel_store();
            let deps = data_tunnel_deps(
                Arc::clone(&slots),
                Arc::new(ReplayGuard::new()),
                spawn_ack_target().await,
            );
            let cbor = cbor::to_canonical_vec(&data_tunnel_credential()).unwrap();
            let (client_io, server_io) = duplex(64 * 1024);
            let serve_now = now_unix();
            let trust = params.admission.admit(serve_now).unwrap();

            let server = serve_relay_stream_responder_connection(
                server_io,
                &offer,
                &params,
                &trust,
                AdmissionInstant::from_seam_wall(serve_now).expect("plausible test clock"),
                &deps,
            );
            let client = async {
                let mut stream = client_noise_stream(client_io, &offer, serve_now).await;
                assert!(matches!(
                    client_authenticate(&mut stream, &cbor, data_tunnel_token(&cbor, b"revoke"))
                        .await
                        .unwrap(),
                    TunnelAck::Ok { .. }
                ));
                assert_eq!(
                    client_health(&mut stream, HEALTH_PROBE).await.unwrap(),
                    HEALTH_PROBE
                );
                client_open_stream(&mut stream).await.unwrap();
                send_frame(&mut stream, &TunnelFrame::Data(b"before-revoke".to_vec()))
                    .await
                    .unwrap();
                assert_eq!(
                    recv_frame(&mut stream).await.unwrap(),
                    TunnelFrame::Data(b"ACK:before-revoke".to_vec())
                );

                slots.revoke(&DATA_TUNNEL_SLOT, now_unix()).unwrap();
                match timeout(
                    Duration::from_secs(2),
                    send_frame(&mut stream, &TunnelFrame::Data(b"after-revoke".to_vec())),
                )
                .await
                {
                    Ok(Ok(())) => {
                        match timeout(Duration::from_secs(2), recv_frame(&mut stream)).await {
                            Ok(Ok(frame)) => panic!(
                                "revoked relay stream responder session must close, got {frame:?}"
                            ),
                            Ok(Err(_)) | Err(_) => {}
                        }
                    }
                    Ok(Err(_)) => {}
                    Err(_) => panic!("write after revoke hung"),
                }
            };

            let (server_result, ()) = tokio::join!(server, client);
            assert!(matches!(
                server_result,
                Err(RelayStreamResponderError::DataTunnel(
                    DataTunnelError::Rejected(reason)
                )) if reason == "slot-revoked"
            ));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relay_stream_responder_device_live_clock_failures_tear_down_real_serve() {
        for (index, failure) in [
            LiveClockFailure::Unusable,
            LiveClockFailure::WallRegressed,
            LiveClockFailure::SignedExpiryPassed,
        ]
        .into_iter()
        .enumerate()
        {
            timeout(Duration::from_secs(5), async {
                let keypair = generate_relay_stream_noise_static_keypair().unwrap();
                let serve_now = now_unix();
                let not_after = serve_now + 60;
                let offer = device_offer_expiring_at(
                    0x76 + u8::try_from(index).unwrap(),
                    &keypair,
                    not_after,
                );
                let params = params(keypair, Duration::from_secs(3)).await;
                let deps = data_tunnel_deps(
                    data_tunnel_store(),
                    Arc::new(ReplayGuard::new()),
                    spawn_ack_target().await,
                );
                let cbor = cbor::to_canonical_vec(&data_tunnel_credential()).unwrap();
                let (client_io, server_io) = duplex(64 * 1024);
                let trust = params.admission.admit(serve_now).unwrap();
                let armed = Arc::new(AtomicBool::new(false));

                let server = serve_relay_stream_responder_connection_with_live_clock(
                    server_io,
                    &offer,
                    &params,
                    &trust,
                    AdmissionInstant::from_seam_wall(serve_now).expect("plausible test clock"),
                    &deps,
                    controlled_live_now(Arc::clone(&armed), failure, serve_now, not_after),
                );
                let client = async {
                    let mut stream = client_noise_stream(client_io, &offer, serve_now).await;
                    assert!(matches!(
                        client_authenticate(
                            &mut stream,
                            &cbor,
                            data_tunnel_token(&cbor, b"device-live-clock")
                        )
                        .await
                        .unwrap(),
                        TunnelAck::Ok { .. }
                    ));
                    client_open_stream(&mut stream).await.unwrap();

                    armed.store(true, Ordering::SeqCst);
                    send_frame(
                        &mut stream,
                        &TunnelFrame::Data(b"after-clock-failure".to_vec()),
                    )
                    .await
                    .unwrap();
                    assert!(
                        recv_frame(&mut stream).await.is_err(),
                        "{failure:?} must tear down the live Device session"
                    );
                };

                let (server_result, ()) = tokio::join!(server, client);
                assert!(matches!(
                    server_result,
                    Err(RelayStreamResponderError::DataTunnel(
                        DataTunnelError::Rejected(reason)
                    )) if reason == "slot-revoked"
                ));
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn relay_stream_responder_noise_handshake_times_out_before_auth() {
        timeout(Duration::from_secs(2), async {
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = relay_stream_offer(rendezvous_token(0x74), &keypair);
            let params = params(keypair, Duration::from_millis(75)).await;
            let deps = data_tunnel_deps(
                data_tunnel_store(),
                Arc::new(ReplayGuard::new()),
                "127.0.0.1:1".to_string(),
            );
            let (client_io, server_io) = duplex(1024);
            let serve_now = now_unix();
            let trust = params.admission.admit(serve_now).unwrap();
            let server = serve_relay_stream_responder_connection(
                server_io,
                &offer,
                &params,
                &trust,
                AdmissionInstant::from_seam_wall(serve_now).expect("plausible test clock"),
                &deps,
            );
            let keep_client_open = async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                drop(client_io);
            };

            let (server_result, ()) = tokio::join!(server, keep_client_open);
            assert!(matches!(
                server_result,
                Err(RelayStreamResponderError::HandshakeTimeout)
            ));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relay_stream_responder_attacker_offer_is_rejected_before_data_tunnel() {
        timeout(Duration::from_secs(2), async {
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer =
                relay_stream_offer_signed_by(rendezvous_token(0x75), &keypair, &attacker_signer());
            let params = params(keypair, Duration::from_secs(2)).await;
            let deps = data_tunnel_deps(
                data_tunnel_store(),
                Arc::new(ReplayGuard::new()),
                "127.0.0.1:1".to_string(),
            );
            let (_client_io, server_io) = duplex(1024);
            let serve_now = now_unix();
            let trust = params.admission.admit(serve_now).unwrap();

            let result = serve_relay_stream_responder_connection(
                server_io,
                &offer,
                &params,
                &trust,
                AdmissionInstant::from_seam_wall(serve_now).expect("plausible test clock"),
                &deps,
            )
            .await;

            assert!(matches!(
                result,
                Err(RelayStreamResponderError::Noise(
                    RelayStreamNoiseError::Contract(RelayStreamContractError::IssuerUnauthorized(
                        _
                    ))
                ))
            ));
        })
        .await
        .unwrap();
    }

    #[test]
    fn relay_stream_responder_debug_redacts_secret_fields() {
        let deps = data_tunnel_deps(
            data_tunnel_store(),
            Arc::new(ReplayGuard::new()),
            "127.0.0.1:1".to_string(),
        );
        let debug = format!("{deps:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("ReplayGuard {"));
    }

    // Live projection granting member g_a (device guest_pub()) access to the claw.
    fn group_projection_active() -> ProjectedState {
        let mut p = ProjectedState::default();
        p.groups.insert(
            "g".to_string(),
            ProjectedGroup {
                group_id: "g".to_string(),
                name: "G".to_string(),
                members: [("g_a".to_string(), MeshMembership::Active)]
                    .into_iter()
                    .collect(),
                member_labels: Default::default(),
                granted_claws: [(RELAY_STREAM_CLAW_ID.to_string(), MeshMembership::Active)]
                    .into_iter()
                    .collect(),
                revision: 1,
            },
        );
        p.member_devices.insert(
            "g_a".to_string(),
            [(
                guest_pub().as_bytes()[..].to_vec(),
                ProjectedMemberDevice {
                    participant_npub: "npub".to_string(),
                    status: MeshMembership::Active,
                },
            )]
            .into_iter()
            .collect(),
        );
        p
    }

    // Capstone e2e through the REAL responder: a credential-less GROUP dial over
    // Noise (responder_handshake_with_trust) → the audience branch →
    // verify_relay_stream_offer_session → live-gate Rev → PTY echo marker. Proves
    // the whole stack (Noise + branch + real verifier + real Rev) accepts a group
    // dial. The offer's claw_static_pub is the responder's Noise key; the PoP token
    // binds to blake3(offer) and is signed by the dialing device key (guest_signer).
    #[tokio::test]
    async fn relay_stream_responder_group_dial_e2e_pipes_pty_marker() {
        timeout(Duration::from_secs(5), async {
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let serve_now = now_unix();
            let offer = mint_relay_stream_group_offer(
                rendezvous_token(0x7a),
                SlotId([0x99; 16]),
                "g".to_string(),
                "g_a".to_string(),
                guest_pub(),
                RELAY_STREAM_CLAW_ID.to_string(),
                RelayStreamResource::Pty,
                RELAY_STREAM_ENDPOINT.to_string(),
                keypair.public_key().clone(),
                serve_now + 60,
                serve_now,
                &owner_signer(),
            )
            .unwrap();
            let params = params(keypair, Duration::from_secs(3)).await;
            let deps = data_tunnel_deps(
                data_tunnel_store(),
                Arc::new(ReplayGuard::new()),
                spawn_ack_target().await,
            );
            let proj = group_projection_active();
            let trust = RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
                record: relay_stream_household_record(),
                cert: relay_stream_machine_cert(),
                projection: proj.clone(),
            });
            let (client_io, server_io) = duplex(64 * 1024);

            let server = serve_relay_stream_responder_connection(
                server_io,
                &offer,
                &params,
                &trust,
                AdmissionInstant::from_seam_wall(serve_now).expect("plausible test clock"),
                &deps,
            );
            let client = async {
                let mut stream = client_noise_stream(client_io, &offer, serve_now).await;
                // Credential-less group PoP: token binds to blake3(offer), signed by
                // the dialing device key (== offer.guest_device_pub).
                let offer_cbor = offer.payload.to_canonical_bytes().unwrap();
                let token = SessionAuthToken::sign(
                    "relay-stream-group-e2e".to_string(),
                    &offer_cbor,
                    RELAY_STREAM_ENDPOINT.to_string(),
                    RELAY_STREAM_CLAW_ID.to_string(),
                    b"g1".to_vec(),
                    serve_now + 60,
                    &guest_signer(),
                )
                .unwrap();
                assert!(matches!(
                    client_authenticate(&mut stream, &offer_cbor, token)
                        .await
                        .unwrap(),
                    TunnelAck::Ok { .. }
                ));
                assert_eq!(
                    client_health(&mut stream, HEALTH_PROBE).await.unwrap(),
                    HEALTH_PROBE
                );
                client_open_stream(&mut stream).await.unwrap();
                send_frame(
                    &mut stream,
                    &TunnelFrame::Data(b"echo relay-stream-ok".to_vec()),
                )
                .await
                .unwrap();
                match recv_frame(&mut stream).await.unwrap() {
                    TunnelFrame::Data(d) => assert!(
                        String::from_utf8_lossy(&d).contains("relay-stream-ok"),
                        "expected echoed marker, got {d:?}"
                    ),
                    other => panic!("expected echoed Data, got {other:?}"),
                }
                send_frame(&mut stream, &TunnelFrame::Close).await.unwrap();
            };

            let (server_result, ()) = tokio::join!(server, client);
            server_result.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn relay_stream_responder_group_iptunnel_clock_failure_tears_down_live_session() {
        timeout(Duration::from_secs(5), async {
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let serve_now = now_unix();
            let not_after = serve_now + 60;
            let offer = mint_relay_stream_group_offer(
                rendezvous_token(0x7b),
                SlotId([0x9a; 16]),
                "g".to_string(),
                "g_a".to_string(),
                guest_pub(),
                RELAY_STREAM_CLAW_ID.to_string(),
                RelayStreamResource::IpTunnel,
                RELAY_STREAM_ENDPOINT.to_string(),
                keypair.public_key().clone(),
                not_after,
                serve_now,
                &owner_signer(),
            )
            .unwrap();
            let params = params(keypair, Duration::from_secs(3)).await;
            let deps = data_tunnel_deps(
                data_tunnel_store(),
                Arc::new(ReplayGuard::new()),
                spawn_ack_target().await,
            );
            let projection = group_projection_active();
            let trust = RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
                record: relay_stream_household_record(),
                cert: relay_stream_machine_cert(),
                projection: projection.clone(),
            });
            let (client_io, server_io) = duplex(64 * 1024);
            let armed = Arc::new(AtomicBool::new(false));

            let server = serve_relay_stream_responder_connection_with_live_clock(
                server_io,
                &offer,
                &params,
                &trust,
                AdmissionInstant::from_seam_wall(serve_now).expect("plausible test clock"),
                &deps,
                controlled_live_now(
                    Arc::clone(&armed),
                    LiveClockFailure::Unusable,
                    serve_now,
                    not_after,
                ),
            );
            let client = async {
                let mut stream = client_noise_stream(client_io, &offer, serve_now).await;
                let offer_cbor = offer.payload.to_canonical_bytes().unwrap();
                let token = SessionAuthToken::sign(
                    "relay-stream-group-iptunnel-expiry".to_string(),
                    &offer_cbor,
                    RELAY_STREAM_ENDPOINT.to_string(),
                    RELAY_STREAM_CLAW_ID.to_string(),
                    b"g2".to_vec(),
                    not_after,
                    &guest_signer(),
                )
                .unwrap();
                assert!(matches!(
                    client_authenticate(&mut stream, &offer_cbor, token)
                        .await
                        .unwrap(),
                    TunnelAck::Ok { .. }
                ));
                client_open_stream(&mut stream).await.unwrap();
                send_frame(&mut stream, &TunnelFrame::Data(b"before-expiry".to_vec()))
                    .await
                    .unwrap();
                assert_eq!(
                    recv_frame(&mut stream).await.unwrap(),
                    TunnelFrame::Data(b"ACK:before-expiry".to_vec())
                );

                armed.store(true, Ordering::SeqCst);
                let write = send_frame(
                    &mut stream,
                    &TunnelFrame::Data(b"after-clock-failure".to_vec()),
                )
                .await;
                if write.is_ok() {
                    assert!(
                        recv_frame(&mut stream).await.is_err(),
                        "unusable clock must tear down live Group IpTunnel stream"
                    );
                }
            };

            let (server_result, ()) = tokio::join!(server, client);
            assert!(matches!(
                server_result,
                Err(RelayStreamResponderError::DataTunnel(
                    DataTunnelError::Rejected(reason)
                )) if reason == "slot-revoked"
            ));
        })
        .await
        .unwrap();
    }
}
