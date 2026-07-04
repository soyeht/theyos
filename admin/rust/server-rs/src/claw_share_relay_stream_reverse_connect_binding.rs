//! Per-connection M2 binding for Product A `relay_stream` reverse connect.
//!
//! C4d. [`bind_relay_stream_reverse_connect`] is the single-source constructor
//! that ties one offer to one target router and one slot store, closing the M2
//! confused-deputy gap:
//!   * the same offer drives the Noise handshake (`binding.offer`) and the
//!     `RelayStreamOfferTargetRouter` inside `binding.deps`;
//!   * the router and the data-tunnel deps share the same
//!     `Arc<ClawShareSlotStore>`, so revocation observed by one is observed by
//!     the other;
//!   * the router carries the same pre-admitted `trust` seam the handshake uses.
//!
//! There is no API that accepts a separate handshake-offer and router-offer.
//! This is NOT the pool: no multiplicity, sizing, eviction, or backoff (C4e),
//! and no live wiring.

use std::fmt;
use std::sync::Arc;

use household_rs::claw_share::ClawShareSlotStore;
use household_rs::claw_share_data_tunnel::{ClawTargetRouter, ReplayGuard};
use household_rs::ids::HouseholdId;

use crate::claw_share_relay_stream_contract::RelayStreamOfferContract;
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;
use crate::claw_share_relay_stream_responder::ResponderDataTunnelDeps;
use crate::claw_share_relay_stream_target_router::{
    RelayStreamIpTunnelRouter, RelayStreamIpTunnelUnavailableRouter, RelayStreamOfferTargetRouter,
};

/// One offer bound to its target router and data-tunnel deps for a single
/// reverse-connect attempt.
///
/// `offer` is the source of truth: the handshake uses `offer`, and the router
/// inside `deps` was built from the same offer + the same `trust` seam + the
/// same slot store, so the two cannot diverge.
pub struct RelayStreamReverseConnectBinding<P, S, I = RelayStreamIpTunnelUnavailableRouter> {
    pub offer: Arc<RelayStreamOfferContract>,
    pub trust: RelayStreamIssuerTrust,
    pub deps: ResponderDataTunnelDeps<RelayStreamOfferTargetRouter<P, S, I>>,
}

impl<P, S, I> fmt::Debug for RelayStreamReverseConnectBinding<P, S, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamReverseConnectBinding")
            .field("offer", &"redacted")
            .field("trust", &self.trust)
            .field("deps", &self.deps)
            .finish()
    }
}

/// Bind one offer to a fresh target router + data-tunnel deps.
///
/// Takes the offer and the slot store ONCE so the handshake offer, the router's
/// offer, and the router/deps slot store cannot diverge. The router is built
/// from `(*offer).clone()` and `trust.clone()`, and both the router and the
/// deps hold `Arc::clone(&slots)` — the same store.
// `slots` is taken by value on purpose: the constructor's contract is to own the
// single slot-store handle once (see doc above) and fan it out internally, so it
// is not reduced to `&Arc` here.
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn bind_relay_stream_reverse_connect<P, S>(
    offer: Arc<RelayStreamOfferContract>,
    trust: RelayStreamIssuerTrust,
    household_id: HouseholdId,
    slots: Arc<ClawShareSlotStore>,
    replay: Arc<ReplayGuard>,
    pty_router: P,
    clawsite_router: S,
    now_unix: impl Fn() -> u64 + Send + Sync + 'static,
) -> RelayStreamReverseConnectBinding<P, S>
where
    P: ClawTargetRouter,
    S: ClawTargetRouter,
{
    bind_relay_stream_reverse_connect_with_ip_tunnel_router(
        offer,
        trust,
        household_id,
        slots,
        replay,
        pty_router,
        clawsite_router,
        RelayStreamIpTunnelUnavailableRouter,
        now_unix,
    )
}

#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn bind_relay_stream_reverse_connect_with_ip_tunnel_router<P, S, I>(
    offer: Arc<RelayStreamOfferContract>,
    trust: RelayStreamIssuerTrust,
    household_id: HouseholdId,
    slots: Arc<ClawShareSlotStore>,
    replay: Arc<ReplayGuard>,
    pty_router: P,
    clawsite_router: S,
    ip_tunnel_router: I,
    now_unix: impl Fn() -> u64 + Send + Sync + 'static,
) -> RelayStreamReverseConnectBinding<P, S, I>
where
    P: ClawTargetRouter,
    S: ClawTargetRouter,
    I: RelayStreamIpTunnelRouter,
{
    let router = RelayStreamOfferTargetRouter::new_with_ip_tunnel_router(
        (*offer).clone(),
        trust.clone(),
        Arc::clone(&slots),
        pty_router,
        clawsite_router,
        ip_tunnel_router,
        now_unix,
    );
    let deps = ResponderDataTunnelDeps::new(household_id, Arc::clone(&slots), replay, router);
    RelayStreamReverseConnectBinding { offer, trust, deps }
}

#[cfg(test)]
mod tests {
    use super::*;

    use household_rs::claw_share::{SlotRecord, SlotState};
    use household_rs::claw_share_data_tunnel::{
        ClawTargetRouter, DataTunnelError, TargetSession, TcpStreamRouter,
    };
    use household_rs::household_mesh_log::{
        MeshMembership, ProjectedGroup, ProjectedMemberDevice, ProjectedState,
    };
    use household_rs::ids::derive_household_id;
    use household_rs::keys::IdentityKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::claw_share_relay_stream_target_router::RelayStreamIpTunnelTarget;

    use crate::claw_share_relay_stream_contract::{
        RelayStreamClawStaticPublicKey, RelayStreamExpectedPath, RelayStreamOfferPayload,
        RelayStreamResource, mint_relay_stream_group_offer,
    };
    use crate::claw_share_relay_stream_issuer_trust::RelayStreamTrustContext;
    use crate::claw_share_relay_stream_test_support::{
        DATA_TUNNEL_SLOT, RELAY_STREAM_CLAW_ID, attacker_signer, guest_pub, guest_signer,
        owner_signer, relay_stream_household_record, relay_stream_issuer_trust,
        relay_stream_machine_cert, rendezvous_token,
    };

    const NOW: u64 = 1_800_000_000;

    fn offer_with(
        resource: RelayStreamResource,
        signer: &dyn IdentityKey,
    ) -> Arc<RelayStreamOfferContract> {
        let payload = RelayStreamOfferPayload::new(
            rendezvous_token(0x42),
            RELAY_STREAM_CLAW_ID.to_string(),
            DATA_TUNNEL_SLOT,
            guest_pub(),
            resource,
            RelayStreamExpectedPath::RelayStream,
            "relay-stream://127.0.0.1:49152".to_string(),
            RelayStreamClawStaticPublicKey::try_new([0x77; 32]).unwrap(),
            NOW + 600,
        );
        Arc::new(RelayStreamOfferContract::sign(payload, signer).unwrap())
    }

    fn group_offer_with(
        resource: RelayStreamResource,
        signer: &dyn IdentityKey,
    ) -> Arc<RelayStreamOfferContract> {
        Arc::new(
            mint_relay_stream_group_offer(
                rendezvous_token(0x42),
                DATA_TUNNEL_SLOT,
                "g".to_string(),
                "g_a".to_string(),
                guest_pub(),
                RELAY_STREAM_CLAW_ID.to_string(),
                resource,
                "relay-stream://127.0.0.1:49152".to_string(),
                RelayStreamClawStaticPublicKey::try_new([0x77; 32]).unwrap(),
                NOW + 600,
                NOW,
                signer,
            )
            .unwrap(),
        )
    }

    fn group_projection() -> ProjectedState {
        let mut projection = ProjectedState::default();
        projection.groups.insert(
            "g".to_string(),
            ProjectedGroup {
                group_id: "g".to_string(),
                name: "Family".to_string(),
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
        projection.member_devices.insert(
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
        projection
    }

    fn group_trust() -> RelayStreamIssuerTrust {
        RelayStreamIssuerTrust::new(|| RelayStreamTrustContext {
            record: relay_stream_household_record(),
            cert: relay_stream_machine_cert(),
            projection: group_projection(),
        })
    }

    // Slot store consumed by the offer's guest, matching the offer's claw/slot.
    fn consumed_slots() -> Arc<ClawShareSlotStore> {
        let store = ClawShareSlotStore::new();
        store
            .insert(SlotRecord {
                slot_id: DATA_TUNNEL_SLOT,
                claw_id: RELAY_STREAM_CLAW_ID.to_string(),
                expires_at: NOW + 86_400,
                state: SlotState::Open,
            })
            .unwrap();
        store
            .consume_atomic(
                &DATA_TUNNEL_SLOT,
                RELAY_STREAM_CLAW_ID,
                guest_signer().public(),
                NOW,
            )
            .unwrap();
        Arc::new(store)
    }

    async fn spawn_prefixed_ack(prefix: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let mut response = prefix.to_vec();
                response.extend_from_slice(&buf[..n]);
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            }
        });
        addr
    }

    async fn binding_for(
        resource: RelayStreamResource,
        signer: &dyn IdentityKey,
        slots: Arc<ClawShareSlotStore>,
    ) -> RelayStreamReverseConnectBinding<TcpStreamRouter, TcpStreamRouter> {
        let pty_addr = spawn_prefixed_ack(b"PTY:").await;
        let site_addr = spawn_prefixed_ack(b"SITE:").await;
        bind_relay_stream_reverse_connect(
            offer_with(resource, signer),
            relay_stream_issuer_trust(),
            derive_household_id(&owner_signer().public()),
            slots,
            Arc::new(ReplayGuard::new()),
            TcpStreamRouter::new(pty_addr),
            TcpStreamRouter::new(site_addr),
            || NOW,
        )
    }

    async fn open_roundtrip<P, S, I>(
        binding: &RelayStreamReverseConnectBinding<P, S, I>,
    ) -> Result<Vec<u8>, DataTunnelError>
    where
        P: ClawTargetRouter,
        S: ClawTargetRouter,
        I: RelayStreamIpTunnelRouter,
    {
        let mut session = binding.deps.router.open(RELAY_STREAM_CLAW_ID).await?;
        session
            .writer
            .write_all(b"x")
            .await
            .map_err(|e| DataTunnelError::Io(e.to_string()))?;
        session
            .writer
            .flush()
            .await
            .map_err(|e| DataTunnelError::Io(e.to_string()))?;
        let mut buf = [0u8; 64];
        let n = session
            .reader
            .read(&mut buf)
            .await
            .map_err(|e| DataTunnelError::Io(e.to_string()))?;
        Ok(buf[..n].to_vec())
    }

    async fn open_error<P, S, I>(
        binding: &RelayStreamReverseConnectBinding<P, S, I>,
    ) -> DataTunnelError
    where
        P: ClawTargetRouter,
        S: ClawTargetRouter,
        I: RelayStreamIpTunnelRouter,
    {
        match binding.deps.router.open(RELAY_STREAM_CLAW_ID).await {
            Ok(_) => panic!("expected target open to fail"),
            Err(error) => error,
        }
    }

    struct AckIpTunnelRouter {
        addr: String,
    }

    impl AckIpTunnelRouter {
        fn new(addr: String) -> Self {
            Self { addr }
        }
    }

    impl RelayStreamIpTunnelRouter for AckIpTunnelRouter {
        async fn open_ip_tunnel(
            &self,
            target: RelayStreamIpTunnelTarget,
        ) -> Result<TargetSession, DataTunnelError> {
            TcpStreamRouter::new(self.addr.clone())
                .open(target.claw_id())
                .await
        }
    }

    #[tokio::test]
    async fn binding_routes_pty_offer_to_pty_subrouter() {
        let binding =
            binding_for(RelayStreamResource::Pty, &owner_signer(), consumed_slots()).await;

        let response = open_roundtrip(&binding).await.unwrap();

        assert_eq!(response, b"PTY:x");
    }

    #[tokio::test]
    async fn binding_routes_clawsite_offer_to_clawsite_subrouter() {
        let binding = binding_for(
            RelayStreamResource::ClawSite,
            &owner_signer(),
            consumed_slots(),
        )
        .await;

        let response = open_roundtrip(&binding).await.unwrap();

        assert_eq!(response, b"SITE:x");
    }

    #[tokio::test]
    async fn binding_routes_iptunnel_offer_to_injected_subrouter() {
        let pty_addr = spawn_prefixed_ack(b"PTY:").await;
        let site_addr = spawn_prefixed_ack(b"SITE:").await;
        let ip_addr = spawn_prefixed_ack(b"IPTUNNEL:").await;
        let binding = bind_relay_stream_reverse_connect_with_ip_tunnel_router(
            group_offer_with(RelayStreamResource::IpTunnel, &owner_signer()),
            group_trust(),
            derive_household_id(&owner_signer().public()),
            consumed_slots(),
            Arc::new(ReplayGuard::new()),
            TcpStreamRouter::new(pty_addr),
            TcpStreamRouter::new(site_addr),
            AckIpTunnelRouter::new(ip_addr),
            || NOW,
        );

        let response = open_roundtrip(&binding).await.unwrap();

        assert_eq!(response, b"IPTUNNEL:x");
    }

    #[tokio::test]
    async fn binding_offer_resource_matches_router_routing() {
        // The handshake-side offer and the router are the same source: the offer
        // says Pty and the router routes to the pty sub-router.
        let binding =
            binding_for(RelayStreamResource::Pty, &owner_signer(), consumed_slots()).await;

        assert_eq!(binding.offer.payload.resource, RelayStreamResource::Pty);
        assert_eq!(open_roundtrip(&binding).await.unwrap(), b"PTY:x");
    }

    #[tokio::test]
    async fn binding_router_and_deps_share_one_slot_store() {
        let slots = consumed_slots();
        let binding = binding_for(
            RelayStreamResource::Pty,
            &owner_signer(),
            Arc::clone(&slots),
        )
        .await;

        // Revoke through the deps' slot store; the router must observe it,
        // proving both hold the same Arc.
        binding.deps.slots.revoke(&DATA_TUNNEL_SLOT, NOW).unwrap();

        let error = open_error(&binding).await;
        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-slot-revoked")
        );
    }

    #[tokio::test]
    async fn binding_rejects_unauthorized_offer_before_backend() {
        // Offer signed by an attacker (not the certified machine issuer): the
        // router's trust gate rejects it, collapsed to the opaque reason, before
        // any backend dial.
        let binding = binding_for(
            RelayStreamResource::Pty,
            &attacker_signer(),
            consumed_slots(),
        )
        .await;

        let error = open_error(&binding).await;
        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-offer-invalid")
        );
    }

    #[tokio::test]
    async fn binding_debug_does_not_leak_secret() {
        let binding =
            binding_for(RelayStreamResource::Pty, &owner_signer(), consumed_slots()).await;

        let debug = format!("{binding:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("secret"));
        // The rendezvous token bytes must not appear.
        assert!(!debug.contains("42424242424242424242424242424242"));
    }
}
