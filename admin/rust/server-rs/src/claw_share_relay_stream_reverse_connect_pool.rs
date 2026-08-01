//! Product side of the `relay_stream` reverse-connect pool.
//!
//! S0 cutover: parking, the global connection cap, the backoff policy, the
//! cancellation flag, `Drop`-based teardown and the reconcile algorithm now live
//! in [`tunnel_wire_rs::worker_pool`]. What remains here is everything that was
//! ever product-specific — the offer store, the trust seam, the admission clock,
//! the expiry check, the binding and the serve call — behind one attempt
//! callback.
//!
//! Critical invariant, unchanged: every attempt builds a fresh binding from a
//! fresh admission (`admit -> bind -> dial -> serve`). No
//! `RelayStreamReverseConnectBinding` is reused across attempts, so the
//! per-admission trust-health gate from C4c remains effective.
//!
//! # Why the callback, and not a factory plus a serve call
//!
//! The neutral pool can name neither `RelayStreamReverseConnectBinding` nor
//! `serve_relay_stream_responder_reverse_connect_binding`, so it cannot build a
//! binding and then serve it. The two collapse into one callback here — which
//! also means the router generics `P`/`S`/`I` never cross the boundary, since
//! they only ever existed to name the binding type.
//!
//! # The admission clock stays on this side, and that is load-bearing
//!
//! [`AdmissionInstant::capture_with`] samples its monotonic anchor BEFORE
//! running the wall seam; its own docs call the reverse "the late-anchor bug",
//! kept out of production by a `#[cfg(test)]`-only constructor. If the neutral
//! pool held a `now_unix()` seam and passed a time value down, this callback
//! would anchor AFTER that wall read — a production path on the test-only
//! anti-pattern. So the capture happens here, first thing, and the pool never
//! sees a clock.
//!
//! The order inside the callback is the pre-extraction worker's, unchanged:
//! capture the admission, revalidate `not_after` against that fresh reading,
//! build the binding, serve it.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use household_rs::claw_share_data_tunnel::ClawTargetRouter;
use tunnel_wire_rs::worker_pool::{
    AttemptOutcome, ItemAttempt, PoolWorkItem, ResyncView, WorkerPoolConfig, WorkerPoolError,
    spawn_item_resync_driver, spawn_worker_pool,
};

use crate::claw_share_relay_stream_contract::RelayStreamOfferContract;
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;
use crate::claw_share_relay_stream_offer_store::{RelayStreamOfferStore, RelayStreamOfferStoreKey};
use crate::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
use crate::claw_share_relay_stream_responder_reverse_connect::{
    RelayStreamResponderReverseConnectConfig, RelayStreamResponderReverseConnectError,
    serve_relay_stream_responder_reverse_connect_binding,
};
use crate::claw_share_relay_stream_reverse_connect_binding::RelayStreamReverseConnectBinding;
use crate::claw_share_relay_stream_target_router::{
    RelayStreamIpTunnelUnavailableRouter, RelayStreamOfferTargetRouter,
};
use crate::claw_share_session_clock::AdmissionInstant;

// Neutral names, re-exported under the spellings this crate already uses. These
// are claw-named paths to neutral symbols, which is the case the S0 guard's
// positive control blesses: the property is reachability, not spelling.
pub use tunnel_wire_rs::worker_pool::{
    BackoffPolicy as RelayStreamReverseConnectBackoffPolicy,
    WorkerPoolConfig as RelayStreamReverseConnectPoolConfig,
    WorkerPoolError as RelayStreamReverseConnectPoolError,
    WorkerPoolHandle as RelayStreamReverseConnectPoolHandle,
};

/// One offer, as a unit of parked work.
///
/// A newtype rather than an impl on `RelayStreamOfferContract` directly: the
/// contract lives in `household-rs` and the trait in `tunnel-wire-rs`, so an
/// impl here would be an orphan. The wrapper is the local type that makes it
/// legal, and it carries no behaviour of its own.
#[derive(PartialEq)]
pub struct RelayStreamOfferItem(pub RelayStreamOfferContract);

impl PoolWorkItem for RelayStreamOfferItem {
    type Key = RelayStreamOfferStoreKey;

    fn key(&self) -> Self::Key {
        RelayStreamOfferStoreKey::new(self.0.payload.slot_id.clone(), self.0.payload.resource)
    }
}

/// The driver handle with its work-item bound. An alias rather than a bare
/// re-export so consumers keep naming one type with no generic argument, exactly
/// as before the extraction.
pub type RelayStreamOfferResyncDriverHandle =
    tunnel_wire_rs::worker_pool::ItemResyncDriverHandle<RelayStreamOfferItem>;

/// The product's name for the neutral handle's item count.
///
/// An extension trait rather than a rename at the call sites: `offer_count`
/// appears inside existing ASSERTIONS, and those are the oracle for behaviour
/// identity across this move. Preserving the spelling keeps them untouched, and
/// it is the honest name here anyway — every work item in this pool is an offer.
pub trait RelayStreamOfferResyncDriverHandleExt {
    fn offer_count(&self) -> usize;
}

impl RelayStreamOfferResyncDriverHandleExt for RelayStreamOfferResyncDriverHandle {
    fn offer_count(&self) -> usize {
        self.item_count()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamReverseConnectBindingBuildError {
    #[error("relay stream reverse-connect offer expired")]
    Expired,

    #[error("relay stream reverse-connect trust unhealthy: {0}")]
    Unhealthy(String),
}

pub type RelayStreamReverseConnectBindingFactory<P, S, I = RelayStreamIpTunnelUnavailableRouter> =
    dyn Fn(
            Arc<RelayStreamOfferContract>,
            u64,
        ) -> Result<
            RelayStreamReverseConnectBinding<P, S, I>,
            RelayStreamReverseConnectBindingBuildError,
        > + Send
        + Sync;

/// Build the attempt callback the neutral pool parks.
///
/// Everything the pre-extraction worker did between acquiring the permit and
/// returning happens in here, in the same order, and reports back as one of
/// three neutral outcomes.
fn offer_attempt<P, S, I>(
    reverse_config: RelayStreamResponderReverseConnectConfig,
    params: Arc<RelayStreamResponderParams>,
    binding_factory: Arc<RelayStreamReverseConnectBindingFactory<P, S, I>>,
    now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
) -> Arc<ItemAttempt<RelayStreamOfferItem>>
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    Arc::new(move |item: Arc<RelayStreamOfferItem>| {
        let reverse_config = reverse_config;
        let params = Arc::clone(&params);
        let binding_factory = Arc::clone(&binding_factory);
        let now_unix = Arc::clone(&now_unix);
        Box::pin(async move {
            // Sample the clock, anchor-before-wall by construction. `None` means
            // the wall clock is unusable, and with a broken clock expiry cannot
            // be enforced — stop rather than dialing fail-open.
            let Some(admission) = AdmissionInstant::capture_with(&*now_unix) else {
                return AttemptOutcome::Stop;
            };
            let now = admission.wall();
            // Revalidate the offer against that fresh reading.
            //
            // BOUND BY `pool_expiry_precheck_runs_before_the_binding_factory`,
            // which asserts the factory is never invoked for an expired offer.
            // That is the property this line carries: expiry is caught BEFORE
            // we build, so a product whose factory forgets expiry still stops.
            //
            // An earlier revision of this comment said nothing in the suite
            // could bite its removal. That was an assertion of an ABSENCE, and
            // it was wrong — the discriminator was already in the harness, since
            // `binding_factory` counts attempts before its own expiry check.
            let offer = Arc::new(item.0.clone());
            if offer.payload.not_after <= now {
                return AttemptOutcome::Stop;
            }

            let binding = match binding_factory(Arc::clone(&offer), now) {
                Ok(binding) => binding,
                Err(RelayStreamReverseConnectBindingBuildError::Expired) => {
                    return AttemptOutcome::Stop;
                }
                Err(RelayStreamReverseConnectBindingBuildError::Unhealthy(_)) => {
                    return AttemptOutcome::Backoff;
                }
            };

            let result = serve_relay_stream_responder_reverse_connect_binding(
                reverse_config,
                &binding,
                &params,
                admission,
            )
            .await;

            match result {
                // A clean finish and a handshake timeout both reset the backoff.
                // Two arms in the pre-extraction worker, merged here because
                // they now share one expression body rather than two assignment
                // statements — the effect is identical and both reasons stay
                // visible.
                Ok(())
                | Err(RelayStreamResponderReverseConnectError::Responder(
                    crate::claw_share_relay_stream_responder::RelayStreamResponderError::HandshakeTimeout,
                )) => AttemptOutcome::ResetBackoff,
                Err(_) => AttemptOutcome::Backoff,
            }
        }) as tunnel_wire_rs::worker_pool::AttemptFuture
    })
}

// Takes the shared `Arc` handles by value: callers hand the pool ownership of
// one `params`/`binding_factory`/`now_unix` handle. The owned `now_unix`
// parameter also lets a concrete `Arc<fn()>` unsize-coerce to `Arc<dyn Fn>` at
// the call site, which an `&Arc` parameter could not.
#[allow(clippy::needless_pass_by_value)]
pub fn spawn_relay_stream_reverse_connect_pool<P, S, I>(
    config: WorkerPoolConfig,
    reverse_config: RelayStreamResponderReverseConnectConfig,
    params: Arc<RelayStreamResponderParams>,
    offers: Vec<Arc<RelayStreamOfferContract>>,
    binding_factory: Arc<RelayStreamReverseConnectBindingFactory<P, S, I>>,
    now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
) -> Result<RelayStreamReverseConnectPoolHandle, WorkerPoolError>
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    let attempt = offer_attempt(reverse_config, params, binding_factory, now_unix);
    let items = offers
        .into_iter()
        .map(|offer| Arc::new(RelayStreamOfferItem((*offer).clone())))
        .collect();
    spawn_worker_pool(config, items, attempt)
}

/// Spawn the dynamic offer re-sync driver.
///
/// The store, the trust seam and the clock stay here: the source closure re-reads
/// from disk every tick and hands the neutral reconcile an opaque item list.
/// `None` means the wall clock is unusable, which drains rather than coasts —
/// the same fail-closed shape the pre-extraction driver had.
///
/// CRITICAL: re-load from disk every tick. The claim path opens its own store,
/// `put_minted` persists and drops it; a load-once in-memory store would never
/// see the claim's write.
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn spawn_relay_stream_offer_resync_driver<P, S, I>(
    state_dir: PathBuf,
    trust: RelayStreamIssuerTrust,
    tick: Duration,
    config: WorkerPoolConfig,
    reverse_config: RelayStreamResponderReverseConnectConfig,
    params: Arc<RelayStreamResponderParams>,
    binding_factory: Arc<RelayStreamReverseConnectBindingFactory<P, S, I>>,
    now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
) -> Result<RelayStreamOfferResyncDriverHandle, WorkerPoolError>
where
    P: ClawTargetRouter + 'static,
    S: ClawTargetRouter + 'static,
    RelayStreamOfferTargetRouter<P, S, I>: ClawTargetRouter + 'static,
{
    let attempt = offer_attempt(
        reverse_config,
        params,
        binding_factory,
        Arc::clone(&now_unix),
    );
    let source: Arc<dyn Fn() -> ResyncView<RelayStreamOfferItem> + Send + Sync> =
        Arc::new(move || {
            // Clock gate: an unusable wall clock cannot judge `not_after`, so
            // existing workers must not keep dialing on a view nothing can
            // vouch for. DRAIN — the one case that does.
            //
            // The stage is logged HERE, product-side, because the extraction
            // moved the drain decision's *effect* to the neutral pool but the
            // product still owns the reason. It was dropped in the first cut
            // while both sibling stages survived, which is what made it a slip
            // rather than a decision: observable telemetry is behaviour, and
            // this slice's bar is behaviour identity. Stage and message are the
            // pre-extraction ones verbatim.
            let Some(now) = (now_unix)() else {
                tracing::warn!(
                    stage = "claw_share.relay_stream.resync.clock_unusable",
                    "wall clock unusable; drained offer workers and skipped resync",
                );
                return ResyncView::Drain;
            };
            let mut store = match RelayStreamOfferStore::load(&state_dir, &trust, now) {
                Ok(store) => store,
                Err(error) => {
                    tracing::warn!(
                        stage = "claw_share.relay_stream.resync.store_load_failed",
                        error = %error,
                    );
                    // NOT a drain. The pre-extraction driver logged and returned
                    // early, leaving workers running on the last good view; a
                    // transient disk error is not a reason to tear down live
                    // connections.
                    return ResyncView::Unchanged;
                }
            };
            let active = match store.list_active(&trust, now) {
                Ok(active) => active,
                Err(error) => {
                    tracing::warn!(
                        stage = "claw_share.relay_stream.resync.list_active_failed",
                        error = %error,
                    );
                    return ResyncView::Unchanged;
                }
            };
            ResyncView::Items(
                active
                    .into_iter()
                    .map(|offer| Arc::new(RelayStreamOfferItem(offer)))
                    .collect(),
            )
        });

    spawn_item_resync_driver(tick, config, source, attempt)
}
#[cfg(test)]
mod tests {
    use super::*;

    // S0 cutover: IMPORTS ONLY. `AtomicBool` and `JoinHandle` used to arrive
    // through `use super::*` from the mechanics that now live in the neutral
    // crate. Not one assertion below is touched — they are the oracle for
    // behaviour identity across this move.
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::task::JoinHandle;

    use household_rs::cbor;
    use household_rs::claw_share::{ClawShareSlotStore, SlotRecord, SlotState};
    use household_rs::claw_share_data_tunnel::{
        HEALTH_PROBE, ReplayGuard, SessionAuthToken, TcpStreamRouter, TunnelAck, TunnelFrame,
        client_authenticate, client_health, client_open_stream, recv_frame, send_frame,
    };
    use household_rs::household_mesh_log::MeshLogStore;
    use household_rs::ids::derive_household_id;
    use household_rs::keys::IdentityKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::{Duration, timeout};

    use crate::claw_share_relay_stream_admission::RelayStreamAdmission;
    use crate::claw_share_relay_stream_contract::{
        RelayStreamClawStaticPublicKey, RelayStreamExpectedPath, RelayStreamOfferPayload,
        RelayStreamResource,
    };
    use crate::claw_share_relay_stream_noise::{
        RelayStreamNoiseFramed, generate_relay_stream_noise_static_keypair,
    };
    use crate::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
    use crate::claw_share_relay_stream_responder_reverse_connect::{
        RelayStreamResponderReverseConnectConfig,
        serve_relay_stream_responder_reverse_connect_binding,
    };
    use crate::claw_share_relay_stream_reverse_connect_binding::bind_relay_stream_reverse_connect;
    use crate::claw_share_relay_stream_test_support::{
        DATA_TUNNEL_CLAW_ID, DATA_TUNNEL_SLOT, data_tunnel_credential,
        data_tunnel_token as support_data_tunnel_token, guest_pub, guest_signer, now_unix,
        owner_pub, owner_signer, relay_stream_admission, relay_stream_household_state,
        rendezvous_token, spawn_ack_target,
    };
    use crate::claw_share_relay_stream_trust_context_health::{
        RelayStreamTrustContextRefreshPolicy, RelayStreamTrustContextRuntime,
    };
    use crate::claw_share_rendezvous_stream_relay::{
        RendezvousHello, RendezvousRole, RendezvousToken,
    };
    use crate::claw_share_rendezvous_stream_relay_listener::{
        RendezvousStreamRelayListenerConfig, serve_rendezvous_stream_relay,
    };

    const TOKEN_AUDIENCE: &str = "relay-stream-pool-test";

    fn pool_config(
        per_offer_parked: usize,
        max_total_connections: usize,
    ) -> RelayStreamReverseConnectPoolConfig {
        RelayStreamReverseConnectPoolConfig {
            per_item_parked: per_offer_parked,
            max_total_connections,
            backoff: RelayStreamReverseConnectBackoffPolicy::new(
                Duration::from_millis(25),
                Duration::from_millis(100),
            )
            .unwrap(),
        }
    }

    fn reverse_config(
        relay_addr: std::net::SocketAddr,
    ) -> RelayStreamResponderReverseConnectConfig {
        RelayStreamResponderReverseConnectConfig {
            relay_addr,
            connect_timeout: Duration::from_millis(200),
            hello_timeout: Duration::from_millis(200),
            allow_non_loopback_relay_addr: false,
        }
    }

    fn consumed_slots() -> Arc<ClawShareSlotStore> {
        let store = ClawShareSlotStore::new();
        store
            .insert(SlotRecord {
                slot_id: DATA_TUNNEL_SLOT,
                claw_id: DATA_TUNNEL_CLAW_ID.to_string(),
                expires_at: now_unix() + 86_400,
                state: SlotState::Open,
            })
            .unwrap();
        store
            .consume_atomic(
                &DATA_TUNNEL_SLOT,
                DATA_TUNNEL_CLAW_ID,
                guest_signer().public(),
                now_unix(),
            )
            .unwrap();
        Arc::new(store)
    }

    fn offer_for_resource(
        token_label: u8,
        resource: RelayStreamResource,
        static_pub: RelayStreamClawStaticPublicKey,
        not_after: u64,
    ) -> Arc<RelayStreamOfferContract> {
        let payload = RelayStreamOfferPayload::new(
            rendezvous_token(token_label),
            DATA_TUNNEL_CLAW_ID.to_string(),
            DATA_TUNNEL_SLOT,
            guest_pub(),
            resource,
            RelayStreamExpectedPath::RelayStream,
            "relay-stream://127.0.0.1:49152".to_string(),
            static_pub,
            not_after,
        );
        Arc::new(RelayStreamOfferContract::sign(payload, &owner_signer()).unwrap())
    }

    async fn params_for(
        keypair: crate::claw_share_relay_stream_noise::RelayStreamNoiseStaticKeypair,
        auth_deadline: Duration,
        admission: RelayStreamAdmission,
    ) -> RelayStreamResponderParams {
        RelayStreamResponderParams {
            bind_addr: "127.0.0.1:49152".parse().unwrap(),
            auth_deadline,
            idle_timeout: Duration::from_secs(60),
            admission,
            noise_keypair: keypair,
        }
    }

    fn data_tunnel_token(credential_cbor: &[u8], nonce: &[u8]) -> SessionAuthToken {
        support_data_tunnel_token(TOKEN_AUDIENCE, credential_cbor, nonce)
    }

    async fn spawn_pairing_relay() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RendezvousStreamRelayListenerConfig {
            hello_timeout: Duration::from_secs(1),
            token_ttl: Duration::from_secs(2),
            max_pending: 16,
            max_active_connections: 16,
            reaper_interval: Duration::from_millis(50),
            splice_idle_timeout: Duration::from_secs(5),
            splice_max_lifetime: Duration::from_secs(60),
            abuse: crate::claw_share_relay_stream_abuse::RelayAbuseConfig::default(),
        };
        let handle = serve_rendezvous_stream_relay(listener, config);
        (addr, handle)
    }

    async fn connect_guest_with_hello(
        relay_addr: std::net::SocketAddr,
        token: RendezvousToken,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(relay_addr).await.unwrap();
        stream
            .write_all(&RendezvousHello::new(RendezvousRole::Guest, token).encode())
            .await
            .unwrap();
        stream.flush().await.unwrap();
        stream
    }

    async fn spawn_counting_relay() -> (
        std::net::SocketAddr,
        mpsc::Receiver<RendezvousHello>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel(64);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut header = [0u8; 4];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let token_len = u16::from_be_bytes([header[2], header[3]]) as usize;
                    let mut token = vec![0u8; token_len];
                    if stream.read_exact(&mut token).await.is_err() {
                        return;
                    }
                    let mut bytes = header.to_vec();
                    bytes.extend_from_slice(&token);
                    if let Ok(hello) = RendezvousHello::decode(&bytes) {
                        let _ = tx.send(hello).await;
                    }
                    let mut hold = [0u8; 1];
                    let _ = stream.read(&mut hold).await;
                });
            }
        });
        (addr, rx, handle)
    }

    fn binding_factory(
        admission: RelayStreamAdmission,
        slots: Arc<ClawShareSlotStore>,
        pty_addr: String,
        site_addr: String,
        attempts: Arc<AtomicUsize>,
    ) -> Arc<RelayStreamReverseConnectBindingFactory<TcpStreamRouter, TcpStreamRouter>> {
        Arc::new(move |offer, now| {
            attempts.fetch_add(1, Ordering::SeqCst);
            if offer.payload.not_after <= now {
                return Err(RelayStreamReverseConnectBindingBuildError::Expired);
            }
            let trust = admission.admit(now).map_err(|error| {
                RelayStreamReverseConnectBindingBuildError::Unhealthy(error.to_string())
            })?;
            Ok(bind_relay_stream_reverse_connect(
                offer,
                trust,
                derive_household_id(&owner_pub()),
                Arc::clone(&slots),
                Arc::new(ReplayGuard::new()),
                TcpStreamRouter::new(pty_addr.clone()),
                TcpStreamRouter::new(site_addr.clone()),
                || Some(now_unix()),
            ))
        })
    }

    #[tokio::test]
    async fn reverse_connect_binding_serves_end_to_end_composition() {
        timeout(Duration::from_secs(5), async {
            let (relay_addr, relay_handle) = spawn_pairing_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB1,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix() + 60,
            );
            let params = params_for(
                keypair,
                Duration::from_secs(2),
                relay_stream_admission().await,
            )
            .await;
            let pty_addr = spawn_ack_target().await;
            let site_addr = "127.0.0.1:1".to_string();
            let trust = params.admission.admit(now_unix()).unwrap();
            let binding = bind_relay_stream_reverse_connect(
                Arc::clone(&offer),
                trust,
                derive_household_id(&owner_pub()),
                consumed_slots(),
                Arc::new(ReplayGuard::new()),
                TcpStreamRouter::new(pty_addr),
                TcpStreamRouter::new(site_addr),
                || Some(now_unix()),
            );
            let claw = tokio::spawn(async move {
                serve_relay_stream_responder_reverse_connect_binding(
                    reverse_config(relay_addr),
                    &binding,
                    &params,
                    AdmissionInstant::from_seam_wall(now_unix()).expect("plausible test clock"),
                )
                .await
            });

            let guest =
                connect_guest_with_hello(relay_addr, offer.payload.rendezvous_token.clone()).await;
            let mut stream = RelayStreamNoiseFramed::initiator_handshake(
                guest,
                &offer,
                &owner_pub(),
                &guest_pub(),
                now_unix(),
            )
            .await
            .unwrap()
            .into_async_stream();
            let cbor = cbor::to_canonical_vec(&data_tunnel_credential()).unwrap();
            assert!(matches!(
                client_authenticate(&mut stream, &cbor, data_tunnel_token(&cbor, b"pool-e2e"))
                    .await
                    .unwrap(),
                TunnelAck::Ok { .. }
            ));
            assert_eq!(
                client_health(&mut stream, HEALTH_PROBE).await.unwrap(),
                HEALTH_PROBE
            );
            client_open_stream(&mut stream).await.unwrap();
            send_frame(&mut stream, &TunnelFrame::Data(b"via-binding".to_vec()))
                .await
                .unwrap();
            assert_eq!(
                recv_frame(&mut stream).await.unwrap(),
                TunnelFrame::Data(b"ACK:via-binding".to_vec())
            );
            send_frame(&mut stream, &TunnelFrame::Close).await.unwrap();
            claw.await.unwrap().unwrap();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pool_parks_k_per_offer_bounded_by_global_cap() {
        timeout(Duration::from_secs(3), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB2,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix() + 60,
            );
            let params = Arc::new(
                params_for(
                    keypair,
                    Duration::from_secs(5),
                    relay_stream_admission().await,
                )
                .await,
            );
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                Arc::clone(&attempts),
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(3, 2),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(|| Some(now_unix())),
            )
            .unwrap();

            let mut count = 0usize;
            while count < 2 {
                let hello = timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(hello.role, RendezvousRole::Claw);
                count += 1;
            }
            assert!(
                timeout(Duration::from_millis(150), rx.recv())
                    .await
                    .is_err()
            );
            assert_eq!(handle.task_count(), 3);
            handle.shutdown();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pool_skips_expired_offer_without_dialing() {
        timeout(Duration::from_secs(2), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB3,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix().saturating_sub(1),
            );
            let params = Arc::new(
                params_for(
                    keypair,
                    Duration::from_millis(100),
                    relay_stream_admission().await,
                )
                .await,
            );
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                attempts,
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(1, 1),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(|| Some(now_unix())),
            )
            .unwrap();

            assert!(
                timeout(Duration::from_millis(150), rx.recv())
                    .await
                    .is_err()
            );
            handle.shutdown();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    /// The `not_after` pre-check runs BEFORE the binding factory, and this test
    /// binds that ordering rather than the outcome.
    ///
    /// The sibling test above cannot: the factory reports `Expired` too, so no
    /// dial happens either way and removing the pre-check leaves it green. The
    /// discriminator is already in the harness — `binding_factory` increments
    /// `attempts` at its FIRST line, before its own expiry check. So with the
    /// pre-check the factory is never reached and `attempts == 0`; without it
    /// the factory runs and the counter moves. That is the whole difference
    /// between "expiry is enforced somewhere" and "expiry is enforced before we
    /// build", which is the property the pre-check exists for — a product whose
    /// factory forgets expiry still stops.
    #[tokio::test]
    async fn pool_expiry_precheck_runs_before_the_binding_factory() {
        timeout(Duration::from_secs(2), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB4,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix().saturating_sub(1),
            );
            let params = Arc::new(
                params_for(
                    keypair,
                    Duration::from_millis(100),
                    relay_stream_admission().await,
                )
                .await,
            );
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                Arc::clone(&attempts),
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(1, 1),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(|| Some(now_unix())),
            )
            .unwrap();

            // No dial, as the sibling test asserts — the positive control that
            // the fixture is actually running an expired offer.
            assert!(
                timeout(Duration::from_millis(150), rx.recv())
                    .await
                    .is_err()
            );
            // The load-bearing assertion: the factory was never invoked.
            assert_eq!(
                attempts.load(Ordering::SeqCst),
                0,
                "expiry must be caught before the binding factory is called"
            );
            handle.shutdown();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pool_unusable_clock_does_not_build_binding_or_dial() {
        timeout(Duration::from_secs(2), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB9,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix() + 60,
            );
            let params = Arc::new(
                params_for(
                    keypair,
                    Duration::from_millis(100),
                    relay_stream_admission().await,
                )
                .await,
            );
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                Arc::clone(&attempts),
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(1, 1),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(|| None),
            )
            .unwrap();

            tokio::time::sleep(Duration::from_millis(75)).await;
            assert_eq!(attempts.load(Ordering::SeqCst), 0);
            assert!(timeout(Duration::from_millis(75), rx.recv()).await.is_err());
            handle.shutdown();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pool_unhealthy_admission_does_not_dial_and_retries() {
        timeout(Duration::from_secs(2), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB4,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix() + 60,
            );
            let policy =
                RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(1), 1).unwrap();
            let runtime = RelayStreamTrustContextRuntime::load(
                &relay_stream_household_state(),
                &MeshLogStore::new(),
                now_unix().saturating_sub(10_000),
                policy,
            )
            .await
            .unwrap();
            let admission = RelayStreamAdmission::new(Arc::new(runtime));
            let params = Arc::new(params_for(keypair, Duration::from_millis(100), admission).await);
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                Arc::clone(&attempts),
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(1, 1),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(|| Some(now_unix())),
            )
            .unwrap();

            tokio::time::sleep(Duration::from_millis(160)).await;
            assert!(attempts.load(Ordering::SeqCst) >= 1);
            assert!(timeout(Duration::from_millis(50), rx.recv()).await.is_err());
            handle.shutdown();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pool_respawns_after_handshake_timeout() {
        timeout(Duration::from_secs(3), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB5,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix() + 60,
            );
            let params = Arc::new(
                params_for(
                    keypair,
                    Duration::from_millis(75),
                    relay_stream_admission().await,
                )
                .await,
            );
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                attempts,
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(1, 1),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(|| Some(now_unix())),
            )
            .unwrap();

            let first = timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first.role, RendezvousRole::Claw);
            let second = timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(second.role, RendezvousRole::Claw);
            handle.shutdown();
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pool_shutdown_stops_new_dials_and_debug_redacts() {
        timeout(Duration::from_secs(2), async {
            let (relay_addr, mut rx, relay_handle) = spawn_counting_relay().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let offer = offer_for_resource(
                0xB6,
                RelayStreamResource::Pty,
                keypair.public_key().clone(),
                now_unix() + 60,
            );
            let params = Arc::new(
                params_for(
                    keypair,
                    Duration::from_secs(5),
                    relay_stream_admission().await,
                )
                .await,
            );
            let attempts = Arc::new(AtomicUsize::new(0));
            let factory = binding_factory(
                params.admission.clone(),
                consumed_slots(),
                "127.0.0.1:1".to_string(),
                "127.0.0.1:1".to_string(),
                attempts,
            );
            let handle = spawn_relay_stream_reverse_connect_pool(
                pool_config(1, 1),
                reverse_config(relay_addr),
                params,
                vec![offer],
                factory,
                Arc::new(|| Some(now_unix())),
            )
            .unwrap();
            let debug = format!("{handle:?}");
            assert!(!debug.contains("private"));
            assert!(!debug.contains("secret"));
            assert!(!debug.contains("token"));
            let _ = timeout(Duration::from_secs(1), rx.recv()).await.unwrap();
            handle.shutdown();
            assert!(
                timeout(Duration::from_millis(200), rx.recv())
                    .await
                    .is_err()
            );
            relay_handle.abort();
        })
        .await
        .unwrap();
    }

    mod resync {
        use super::*;

        use std::net::SocketAddr;
        use std::path::Path;

        use crate::claw_share_relay_stream_contract::RelayStreamOfferMintInput;
        use crate::claw_share_relay_stream_offer_store::RelayStreamOfferStore;
        use crate::claw_share_relay_stream_test_support::relay_stream_issuer_trust;

        // Mint + persist an offer for `(DATA_TUNNEL_SLOT, resource)` with a known
        // rendezvous token, like the claim provisioning path does.
        fn seed_offer(
            state_dir: &Path,
            token: RendezvousToken,
            resource: RelayStreamResource,
            not_after: u64,
        ) {
            let trust = relay_stream_issuer_trust();
            let credential = data_tunnel_credential();
            let mut store = RelayStreamOfferStore::load(state_dir, &trust, now_unix()).unwrap();
            store
                .put_minted(
                    RelayStreamOfferMintInput {
                        rendezvous_token: token,
                        credential: &credential,
                        resource,
                        expected_path: RelayStreamExpectedPath::RelayStream,
                        relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
                        claw_static_pub: RelayStreamClawStaticPublicKey::try_new([0x77; 32])
                            .unwrap(),
                        not_after,
                        now_unix: now_unix(),
                    },
                    &owner_signer(),
                    &trust,
                )
                .unwrap();
        }

        fn remove_offer(state_dir: &Path, resource: RelayStreamResource) {
            let trust = relay_stream_issuer_trust();
            let mut store = RelayStreamOfferStore::load(state_dir, &trust, now_unix()).unwrap();
            store.remove(&DATA_TUNNEL_SLOT, resource).unwrap();
        }

        async fn wait_until<F: Fn() -> bool>(predicate: F) {
            for _ in 0..200 {
                if predicate() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("condition not met in time");
        }

        // Drain the relay's Claw hellos until one carries `token`.
        async fn wait_for_hello_token(
            rx: &mut mpsc::Receiver<RendezvousHello>,
            token: &RendezvousToken,
        ) {
            timeout(Duration::from_secs(3), async {
                loop {
                    let hello = rx.recv().await.expect("relay closed");
                    if &hello.token == token {
                        return;
                    }
                }
            })
            .await
            .expect("expected a Claw hello carrying the token");
        }

        async fn start_driver(
            state_dir: &Path,
            relay_addr: SocketAddr,
            tick: Duration,
            config: RelayStreamReverseConnectPoolConfig,
        ) -> RelayStreamOfferResyncDriverHandle {
            start_driver_with_clock(
                state_dir,
                relay_addr,
                tick,
                config,
                Arc::new(|| Some(now_unix())),
            )
            .await
        }

        async fn start_driver_with_clock(
            state_dir: &Path,
            relay_addr: SocketAddr,
            tick: Duration,
            config: RelayStreamReverseConnectPoolConfig,
            now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
        ) -> RelayStreamOfferResyncDriverHandle {
            let admission = relay_stream_admission().await;
            let keypair = generate_relay_stream_noise_static_keypair().unwrap();
            let params =
                Arc::new(params_for(keypair, Duration::from_millis(200), admission.clone()).await);
            let slots = consumed_slots();
            let pty = spawn_ack_target().await;
            let site = spawn_ack_target().await;
            let factory =
                binding_factory(admission, slots, pty, site, Arc::new(AtomicUsize::new(0)));
            spawn_relay_stream_offer_resync_driver(
                state_dir.to_path_buf(),
                relay_stream_issuer_trust(),
                tick,
                config,
                reverse_config(relay_addr),
                params,
                factory,
                now_unix,
            )
            .unwrap()
        }

        // Counts peak concurrent accepted connections, to assert the global cap.
        async fn spawn_concurrency_relay() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let peak = Arc::new(AtomicUsize::new(0));
            let active = Arc::new(AtomicUsize::new(0));
            let peak_for_loop = Arc::clone(&peak);
            let handle = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    let active = Arc::clone(&active);
                    let peak = Arc::clone(&peak_for_loop);
                    tokio::spawn(async move {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        let mut buf = [0u8; 64];
                        let _ = stream.read(&mut buf).await;
                        let mut hold = [0u8; 1];
                        let _ = stream.read(&mut hold).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            });
            (addr, peak, handle)
        }

        #[tokio::test]
        async fn resync_spawns_worker_for_offer_added_after_start() {
            timeout(Duration::from_secs(5), async {
                let dir = tempfile::tempdir().unwrap();
                let (relay_addr, mut rx, relay) = spawn_counting_relay().await;
                let handle = start_driver(
                    dir.path(),
                    relay_addr,
                    Duration::from_millis(50),
                    pool_config(1, 4),
                )
                .await;
                assert_eq!(handle.offer_count(), 0);

                let token = rendezvous_token(0x42);
                seed_offer(
                    dir.path(),
                    token.clone(),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );

                wait_for_hello_token(&mut rx, &token).await;
                assert_eq!(handle.offer_count(), 1);
                handle.shutdown();
                relay.abort();
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn resync_drains_worker_when_offer_removed() {
            timeout(Duration::from_secs(5), async {
                let dir = tempfile::tempdir().unwrap();
                let (relay_addr, mut rx, relay) = spawn_counting_relay().await;
                seed_offer(
                    dir.path(),
                    rendezvous_token(0x43),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );
                let handle = start_driver(
                    dir.path(),
                    relay_addr,
                    Duration::from_millis(50),
                    pool_config(1, 4),
                )
                .await;
                wait_for_hello_token(&mut rx, &rendezvous_token(0x43)).await;
                assert_eq!(handle.offer_count(), 1);

                remove_offer(dir.path(), RelayStreamResource::Pty);
                wait_until(|| handle.offer_count() == 0).await;
                handle.shutdown();
                relay.abort();
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn resync_unusable_clock_drains_existing_workers() {
            timeout(Duration::from_secs(5), async {
                let dir = tempfile::tempdir().unwrap();
                let (relay_addr, mut rx, relay) = spawn_counting_relay().await;
                seed_offer(
                    dir.path(),
                    rendezvous_token(0x49),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );
                let clock_usable = Arc::new(AtomicBool::new(true));
                let now_seam: Arc<dyn Fn() -> Option<u64> + Send + Sync> = {
                    let clock_usable = Arc::clone(&clock_usable);
                    Arc::new(move || clock_usable.load(Ordering::SeqCst).then(now_unix))
                };
                let handle = start_driver_with_clock(
                    dir.path(),
                    relay_addr,
                    Duration::from_secs(30),
                    pool_config(1, 4),
                    now_seam,
                )
                .await;
                wait_for_hello_token(&mut rx, &rendezvous_token(0x49)).await;
                assert_eq!(handle.offer_count(), 1);

                clock_usable.store(false, Ordering::SeqCst);
                handle.trigger_resync();
                wait_until(|| handle.offer_count() == 0 && handle.task_count() == 0).await;
                assert!(
                    timeout(Duration::from_millis(150), rx.recv())
                        .await
                        .is_err(),
                    "a drained stale worker must not dial again"
                );

                handle.shutdown();
                relay.abort();
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn resync_respawns_workers_on_offer_content_change() {
            timeout(Duration::from_secs(6), async {
                let dir = tempfile::tempdir().unwrap();
                let (relay_addr, mut rx, relay) = spawn_counting_relay().await;
                seed_offer(
                    dir.path(),
                    rendezvous_token(0x44),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );
                let handle = start_driver(
                    dir.path(),
                    relay_addr,
                    Duration::from_millis(50),
                    pool_config(1, 4),
                )
                .await;
                wait_for_hello_token(&mut rx, &rendezvous_token(0x44)).await;

                // Re-mint the SAME key with a NEW token: the stale worker is drained
                // and a fresh one parks with the new token.
                let new_token = rendezvous_token(0x55);
                seed_offer(
                    dir.path(),
                    new_token.clone(),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );
                wait_for_hello_token(&mut rx, &new_token).await;
                assert_eq!(handle.offer_count(), 1);
                handle.shutdown();
                relay.abort();
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn resync_respects_global_cap_during_churn() {
            timeout(Duration::from_secs(5), async {
                let dir = tempfile::tempdir().unwrap();
                let (relay_addr, peak, relay) = spawn_concurrency_relay().await;
                // Two distinct keys (same slot, Pty + ClawSite), global cap of 1.
                seed_offer(
                    dir.path(),
                    rendezvous_token(0x46),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );
                seed_offer(
                    dir.path(),
                    rendezvous_token(0x47),
                    RelayStreamResource::ClawSite,
                    now_unix() + 600,
                );
                let handle = start_driver(
                    dir.path(),
                    relay_addr,
                    Duration::from_millis(50),
                    pool_config(1, 1),
                )
                .await;

                wait_until(|| handle.offer_count() == 2).await;
                // Let the workers churn (dial / handshake-timeout / retry) for a
                // while; the shared semaphore must keep concurrent dials <= cap.
                tokio::time::sleep(Duration::from_millis(800)).await;
                assert!(
                    peak.load(Ordering::SeqCst) <= 1,
                    "peak concurrent connections {} exceeded cap 1",
                    peak.load(Ordering::SeqCst)
                );
                handle.shutdown();
                relay.abort();
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn resync_shutdown_stops_driver_and_workers() {
            timeout(Duration::from_secs(5), async {
                let dir = tempfile::tempdir().unwrap();
                let (relay_addr, mut rx, relay) = spawn_counting_relay().await;
                seed_offer(
                    dir.path(),
                    rendezvous_token(0x48),
                    RelayStreamResource::Pty,
                    now_unix() + 600,
                );
                let handle = start_driver(
                    dir.path(),
                    relay_addr,
                    Duration::from_millis(50),
                    pool_config(1, 4),
                )
                .await;
                wait_for_hello_token(&mut rx, &rendezvous_token(0x48)).await;

                handle.shutdown();
                // All workers were aborted: live worker count drops to zero.
                wait_until(|| handle.task_count() == 0).await;
                relay.abort();
            })
            .await
            .unwrap();
        }
    }
}
