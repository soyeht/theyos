//! Per-offer target router for Product A `relay_stream`.
//!
//! The offer store is only a provisioning cache. This router is the local
//! authorization boundary before opening PTY/ClawSite backends: it re-checks
//! the selected offer against slot state, claw binding, guest binding, expiry,
//! and revocation on every target open. Owner-key CRL/revocation remains a
//! higher-level consumer boundary and is not faked here.

use std::fmt;
#[cfg(any(test, feature = "dev_t1_datapath"))]
use std::future::Future;
#[cfg(not(any(test, feature = "dev_t1_datapath")))]
use std::marker::PhantomData;
use std::sync::Arc;

use household_rs::claw_share::{ClawShareSlotStore, SlotState};
use household_rs::claw_share_data_tunnel::{ClawTargetRouter, DataTunnelError, TargetSession};
#[cfg(any(test, feature = "dev_t1_datapath"))]
use household_rs::keys::P256PublicKey;

use crate::claw_share_relay_stream_contract::{
    RelayStreamAudience, RelayStreamExpectedPath, RelayStreamOfferContract,
    RelayStreamOfferPayload, RelayStreamResource, check_relay_stream_group_membership,
    check_relay_stream_public,
};
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;

pub(crate) struct RelayStreamOfferTargetGate {
    offer: RelayStreamOfferContract,
    trust: RelayStreamIssuerTrust,
    slots: Arc<ClawShareSlotStore>,
    now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
}

pub struct RelayStreamOfferTargetRouter<P, S, I = RelayStreamIpTunnelUnavailableRouter> {
    gate: RelayStreamOfferTargetGate,
    pty_router: P,
    clawsite_router: S,
    #[cfg(any(test, feature = "dev_t1_datapath"))]
    ip_tunnel_router: I,
    #[cfg(not(any(test, feature = "dev_t1_datapath")))]
    phase0_router: PhantomData<fn() -> I>,
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
#[derive(Clone, PartialEq, Eq)]
pub struct RelayStreamIpTunnelTarget {
    group_id: String,
    member_id: String,
    member_device_pub: P256PublicKey,
    claw_id: String,
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
impl RelayStreamIpTunnelTarget {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        group_id: impl Into<String>,
        member_id: impl Into<String>,
        member_device_pub: P256PublicKey,
        claw_id: impl Into<String>,
    ) -> Self {
        Self {
            group_id: group_id.into(),
            member_id: member_id.into(),
            member_device_pub,
            claw_id: claw_id.into(),
        }
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    #[must_use]
    pub fn member_id(&self) -> &str {
        &self.member_id
    }

    #[must_use]
    pub fn member_device_pub(&self) -> &P256PublicKey {
        &self.member_device_pub
    }

    #[must_use]
    pub fn claw_id(&self) -> &str {
        &self.claw_id
    }
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
impl fmt::Debug for RelayStreamIpTunnelTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStreamIpTunnelTarget")
            .field("group_id", &"<redacted>")
            .field("member_id", &"<redacted>")
            .field("member_device_pub", &"<redacted>")
            .field("claw_id", &"<redacted>")
            .finish()
    }
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
pub trait RelayStreamIpTunnelRouter: Send + Sync {
    fn open_ip_tunnel(
        &self,
        target: RelayStreamIpTunnelTarget,
    ) -> impl Future<Output = Result<TargetSession, DataTunnelError>> + Send;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RelayStreamIpTunnelUnavailableRouter;

impl ClawTargetRouter for RelayStreamIpTunnelUnavailableRouter {
    async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
        Err(target_unavailable("relay-stream-iptunnel-not-configured"))
    }
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
impl RelayStreamIpTunnelRouter for RelayStreamIpTunnelUnavailableRouter {
    async fn open_ip_tunnel(
        &self,
        _target: RelayStreamIpTunnelTarget,
    ) -> Result<TargetSession, DataTunnelError> {
        Err(target_unavailable("relay-stream-iptunnel-not-configured"))
    }
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
impl<T> RelayStreamIpTunnelRouter for Arc<T>
where
    T: RelayStreamIpTunnelRouter + ?Sized,
{
    async fn open_ip_tunnel(
        &self,
        target: RelayStreamIpTunnelTarget,
    ) -> Result<TargetSession, DataTunnelError> {
        (**self).open_ip_tunnel(target).await
    }
}

impl RelayStreamOfferTargetGate {
    #[must_use]
    pub(crate) fn new(
        offer: RelayStreamOfferContract,
        trust: RelayStreamIssuerTrust,
        slots: Arc<ClawShareSlotStore>,
        now_unix: impl Fn() -> Option<u64> + Send + Sync + 'static,
    ) -> Self {
        Self {
            offer,
            trust,
            slots,
            now_unix: Arc::new(now_unix),
        }
    }

    fn resource(&self) -> RelayStreamResource {
        self.offer.payload.resource
    }

    #[cfg(any(test, feature = "dev_t1_datapath"))]
    pub(crate) fn validate_ip_tunnel_target(
        &self,
        target_id: &str,
    ) -> Result<RelayStreamIpTunnelTarget, DataTunnelError> {
        // An unusable wall clock cannot enforce `not_after`, so it can only
        // DENY. Reuses the existing opaque reason: a broken clock must not be
        // distinguishable from an invalid offer.
        let Some(now) = (self.now_unix)() else {
            return Err(target_unavailable("relay-stream-offer-invalid"));
        };
        let ctx = self
            .trust
            .verify_offer_with_context(&self.offer, now)
            .map_err(|_| target_unavailable("relay-stream-offer-invalid"))?;
        let payload = &self.offer.payload;
        if payload.expected_path != RelayStreamExpectedPath::RelayStream {
            return Err(target_unavailable("relay-stream-path-mismatch"));
        }
        if payload.resource != RelayStreamResource::IpTunnel {
            return Err(target_unavailable("relay-stream-resource-mismatch"));
        }
        if target_id != payload.claw_id {
            return Err(target_unavailable("relay-stream-target-mismatch"));
        }
        let RelayStreamAudience::Group {
            group_id,
            member_id,
        } = payload.audience()
        else {
            return Err(target_unavailable("relay-stream-iptunnel-member-required"));
        };
        check_relay_stream_group_membership(
            &ctx.projection,
            &group_id,
            &member_id,
            &payload.claw_id,
            &payload.guest_device_pub,
        )
        .map_err(target_unavailable)?;

        Ok(RelayStreamIpTunnelTarget {
            group_id,
            member_id,
            member_device_pub: payload.guest_device_pub.clone(),
            claw_id: payload.claw_id.clone(),
        })
    }

    fn validate_target_for_resource(
        &self,
        target_id: &str,
        expected_resource: RelayStreamResource,
    ) -> Result<(), DataTunnelError> {
        // Same fail-closed rule as `validate_ip_tunnel_target`: no clock, no
        // authorization. Opaque reason, no backend reached.
        let Some(now) = (self.now_unix)() else {
            return Err(target_unavailable("relay-stream-offer-invalid"));
        };
        // Authorize the offer's signer as an active household machine issuer on
        // every open, via the live trust source: re-verifies signature + signer,
        // enforces `payload.not_after`, membership, and the directory-device
        // revocation kill switch. `_with_context` returns the SAME live context
        // so the Group path checks membership on the EXACT projection that gated
        // the signer (no second snapshot). Any failure maps to one static reason;
        // no token, signature, payload, or key leaks.
        let ctx = self
            .trust
            .verify_offer_with_context(&self.offer, now)
            .map_err(|_| target_unavailable("relay-stream-offer-invalid"))?;
        let payload = &self.offer.payload;
        if payload.expected_path != RelayStreamExpectedPath::RelayStream {
            return Err(target_unavailable("relay-stream-path-mismatch"));
        }
        if payload.resource != expected_resource {
            return Err(target_unavailable("relay-stream-resource-mismatch"));
        }
        if target_id != payload.claw_id {
            return Err(target_unavailable("relay-stream-target-mismatch"));
        }
        let audience = payload.audience();
        if expected_resource == RelayStreamResource::IpTunnel
            && !matches!(audience, RelayStreamAudience::Group { .. })
        {
            return Err(target_unavailable("relay-stream-iptunnel-member-required"));
        }
        // `guest_device_pub` is always the dialing device (the Noise transcript
        // pin); the audience decides HOW it is authorized. `IpTunnel` is
        // narrower than PTY/ClawSite: it requires the member-scoped Group path
        // because the VPN ACL is keyed by (member, device, claw).
        match audience {
            RelayStreamAudience::Device => self.validate_device_target(payload, now),
            RelayStreamAudience::Group {
                group_id,
                member_id,
            } => check_relay_stream_group_membership(
                &ctx.projection,
                &group_id,
                &member_id,
                &payload.claw_id,
                &payload.guest_device_pub,
            )
            .map_err(target_unavailable),
            // Fase E3: public — anyone may dial, gated ONLY by the live
            // published flag (signer-trust + expiry already enforced above).
            RelayStreamAudience::Public => {
                check_relay_stream_public(&ctx.projection, &payload.claw_id)
                    .map_err(target_unavailable)
            }
        }
    }

    /// The existing 1:1 single-guest slot pin (Device audience): the offer's
    /// `slot_id` must be `Consumed` by exactly this `guest_device_pub`.
    fn validate_device_target(
        &self,
        payload: &RelayStreamOfferPayload,
        now: u64,
    ) -> Result<(), DataTunnelError> {
        let record = self
            .slots
            .get(&payload.slot_id)
            .ok_or_else(|| target_unavailable("relay-stream-slot-not-found"))?;
        if record.claw_id != payload.claw_id {
            return Err(target_unavailable("relay-stream-slot-claw-mismatch"));
        }
        if record.expires_at <= now {
            return Err(target_unavailable("relay-stream-slot-expired"));
        }
        match record.state {
            SlotState::Open => Err(target_unavailable("relay-stream-slot-open")),
            SlotState::Revoked { .. } => Err(target_unavailable("relay-stream-slot-revoked")),
            SlotState::Consumed {
                guest_device_pub, ..
            } => {
                if guest_device_pub != payload.guest_device_pub {
                    return Err(target_unavailable("relay-stream-guest-device-mismatch"));
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for RelayStreamOfferTargetGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Curated view: `trust`, `slots`, and `now_unix` are internal collaborators
        // and the offer is redacted, so the remaining fields are omitted.
        f.debug_struct("RelayStreamOfferTargetGate")
            .field("claw_id", &self.offer.payload.claw_id)
            .field("slot_id", &self.offer.payload.slot_id)
            .field("resource", &self.offer.payload.resource)
            .field("offer", &"redacted")
            .finish_non_exhaustive()
    }
}

impl<P, S> RelayStreamOfferTargetRouter<P, S> {
    #[must_use]
    pub fn new(
        offer: RelayStreamOfferContract,
        trust: RelayStreamIssuerTrust,
        slots: Arc<ClawShareSlotStore>,
        pty_router: P,
        clawsite_router: S,
        now_unix: impl Fn() -> Option<u64> + Send + Sync + 'static,
    ) -> Self {
        Self {
            gate: RelayStreamOfferTargetGate::new(offer, trust, slots, now_unix),
            pty_router,
            clawsite_router,
            #[cfg(any(test, feature = "dev_t1_datapath"))]
            ip_tunnel_router: RelayStreamIpTunnelUnavailableRouter,
            #[cfg(not(any(test, feature = "dev_t1_datapath")))]
            phase0_router: PhantomData,
        }
    }
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
impl<P, S, I> RelayStreamOfferTargetRouter<P, S, I> {
    #[must_use]
    pub fn new_with_ip_tunnel_router(
        offer: RelayStreamOfferContract,
        trust: RelayStreamIssuerTrust,
        slots: Arc<ClawShareSlotStore>,
        pty_router: P,
        clawsite_router: S,
        ip_tunnel_router: I,
        now_unix: impl Fn() -> Option<u64> + Send + Sync + 'static,
    ) -> Self {
        Self {
            gate: RelayStreamOfferTargetGate::new(offer, trust, slots, now_unix),
            pty_router,
            clawsite_router,
            ip_tunnel_router,
        }
    }
}

impl<P, S, I> fmt::Debug for RelayStreamOfferTargetRouter<P, S, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Curated view: the offer gate and routers are redacted, so the remaining
        // fields are omitted.
        let mut debug = f.debug_struct("RelayStreamOfferTargetRouter");
        debug
            .field("gate", &self.gate)
            .field("pty_router", &"redacted")
            .field("clawsite_router", &"redacted");
        #[cfg(any(test, feature = "dev_t1_datapath"))]
        debug.field("ip_tunnel_router", &"redacted");
        debug.finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
impl<P, S, I> ClawTargetRouter for RelayStreamOfferTargetRouter<P, S, I>
where
    P: ClawTargetRouter,
    S: ClawTargetRouter,
    I: RelayStreamIpTunnelRouter,
{
    async fn open(&self, target_id: &str) -> Result<TargetSession, DataTunnelError> {
        match self.gate.resource() {
            RelayStreamResource::Pty => {
                self.gate
                    .validate_target_for_resource(target_id, RelayStreamResource::Pty)?;
                self.pty_router.open(target_id).await
            }
            RelayStreamResource::ClawSite => {
                self.gate
                    .validate_target_for_resource(target_id, RelayStreamResource::ClawSite)?;
                self.clawsite_router.open(target_id).await
            }
            RelayStreamResource::IpTunnel => {
                let target = self.gate.validate_ip_tunnel_target(target_id)?;
                self.ip_tunnel_router.open_ip_tunnel(target).await
            }
        }
    }
}

#[cfg(not(any(test, feature = "dev_t1_datapath")))]
impl<P, S> ClawTargetRouter for RelayStreamOfferTargetRouter<P, S>
where
    P: ClawTargetRouter,
    S: ClawTargetRouter,
{
    async fn open(&self, target_id: &str) -> Result<TargetSession, DataTunnelError> {
        match self.gate.resource() {
            RelayStreamResource::Pty => {
                self.gate
                    .validate_target_for_resource(target_id, RelayStreamResource::Pty)?;
                self.pty_router.open(target_id).await
            }
            RelayStreamResource::ClawSite => {
                self.gate
                    .validate_target_for_resource(target_id, RelayStreamResource::ClawSite)?;
                self.clawsite_router.open(target_id).await
            }
            RelayStreamResource::IpTunnel => {
                Err(target_unavailable("relay-stream-iptunnel-compiled-out"))
            }
        }
    }
}

fn target_unavailable(reason: &'static str) -> DataTunnelError {
    DataTunnelError::TargetUnavailable(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::claw_share::{GuestCredential, SlotId, SlotRecord};
    use household_rs::claw_share_data_tunnel::TcpStreamRouter;
    use household_rs::household_mesh_log::{
        DirectoryDeviceStatus, MeshMembership, ProjectedDirectoryDevice, ProjectedGroup,
        ProjectedMemberDevice, ProjectedState,
    };
    use household_rs::household_record::HouseholdRecord;
    use household_rs::ids::{derive_household_id, derive_machine_id};
    use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
    use household_rs::machine_cert::{MachineCert, Platform, SignOptions};
    use household_rs::person_cert::derive_person_id;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::claw_share_relay_stream_contract::{
        RelayStreamClawStaticPublicKey, RelayStreamExpectedPath, RelayStreamOfferMintInput,
        mint_relay_stream_group_offer, mint_relay_stream_offer, mint_relay_stream_public_offer,
    };
    use crate::claw_share_relay_stream_issuer_trust::{
        RelayStreamIssuerTrust, RelayStreamTrustContext,
    };
    use crate::claw_share_rendezvous_stream_relay::RendezvousToken;

    const NOW: u64 = 1_800_000_000;
    const SLOT: SlotId = SlotId([0x22; 16]);
    const CLAW_ID: &str = "claw_alpha";

    fn owner() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
    }

    fn owner_pub() -> P256PublicKey {
        owner().public()
    }

    fn attacker() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap()
    }

    fn hh() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0xAA; 32]).unwrap()
    }

    fn machine_cert() -> MachineCert {
        MachineCert::sign(
            &hh(),
            &owner().public(),
            &SignOptions {
                hh_id: derive_household_id(&hh().public()),
                hostname: "engine-mac".into(),
                platform: Platform::Macos,
                joined_at: NOW - 1_000,
            },
        )
        .unwrap()
    }

    fn record() -> HouseholdRecord {
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: derive_household_id(&hh().public()),
            hh_pub: hh().public(),
            name: "home".into(),
            created_at: 0,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![derive_machine_id(&owner().public())],
            is_follower: false,
        }
    }

    // Trust source authorizing the offer signer `owner()` (the engine machine
    // key); empty projection means no revocation.
    fn trust() -> RelayStreamIssuerTrust {
        RelayStreamIssuerTrust::new(|| RelayStreamTrustContext {
            record: record(),
            cert: machine_cert(),
            projection: ProjectedState::default(),
        })
    }

    // Trust source whose live projection has the issuing machine removed from
    // the household directory — exercises the revocation kill switch at open.
    fn trust_revoked() -> RelayStreamIssuerTrust {
        RelayStreamIssuerTrust::new(|| {
            let mut projection = ProjectedState::default();
            projection.directory_devices.insert(
                owner_pub().as_bytes().to_vec(),
                ProjectedDirectoryDevice {
                    label: "engine-mac".to_string(),
                    status: DirectoryDeviceStatus::Removed,
                },
            );
            RelayStreamTrustContext {
                record: record(),
                cert: machine_cert(),
                projection,
            }
        })
    }

    fn guest() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap()
    }

    fn other_guest_pub() -> P256PublicKey {
        P256Keypair::from_secret_scalar(&[0x44; 32])
            .unwrap()
            .public()
    }

    fn credential() -> GuestCredential {
        GuestCredential::sign(
            derive_household_id(&owner_pub()),
            derive_person_id(&owner_pub()),
            owner_pub(),
            CLAW_ID.to_string(),
            guest().public(),
            SLOT,
            NOW - 60,
            NOW + 600,
            &owner(),
        )
        .unwrap()
    }

    fn static_pub() -> RelayStreamClawStaticPublicKey {
        RelayStreamClawStaticPublicKey::try_new([0x77; 32]).unwrap()
    }

    fn offer(resource: RelayStreamResource) -> RelayStreamOfferContract {
        offer_with_path(resource, RelayStreamExpectedPath::RelayStream)
    }

    fn offer_with_path(
        resource: RelayStreamResource,
        expected_path: RelayStreamExpectedPath,
    ) -> RelayStreamOfferContract {
        let credential = credential();
        mint_relay_stream_offer(
            RelayStreamOfferMintInput {
                rendezvous_token: RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
                credential: &credential,
                resource,
                expected_path,
                relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
                claw_static_pub: static_pub(),
                not_after: NOW + 60,
                now_unix: NOW,
                app_presentation: None,
            },
            &owner(),
        )
        .unwrap()
    }

    fn slots_with(state: SlotState) -> Arc<ClawShareSlotStore> {
        slots_with_record(SlotRecord {
            slot_id: SLOT,
            claw_id: CLAW_ID.to_string(),
            expires_at: NOW + 600,
            state,
            app_presentation: None,
            created_at: None,
        })
    }

    fn slots_with_record(record: SlotRecord) -> Arc<ClawShareSlotStore> {
        let slots = ClawShareSlotStore::new();
        slots.insert(record).unwrap();
        Arc::new(slots)
    }

    fn consumed_slots() -> Arc<ClawShareSlotStore> {
        slots_with(SlotState::Consumed {
            guest_device_pub: guest().public(),
            consumed_at: NOW - 30,
        })
    }

    fn empty_slots() -> Arc<ClawShareSlotStore> {
        Arc::new(ClawShareSlotStore::new())
    }

    async fn spawn_ack_target(prefix: &'static [u8]) -> String {
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

    async fn open_and_roundtrip<P, S, I>(
        router: &RelayStreamOfferTargetRouter<P, S, I>,
    ) -> Result<Vec<u8>, DataTunnelError>
    where
        P: ClawTargetRouter,
        S: ClawTargetRouter,
        I: RelayStreamIpTunnelRouter,
    {
        let mut session = router.open(CLAW_ID).await?;
        session
            .writer
            .write_all(b"hello")
            .await
            .map_err(|error| DataTunnelError::Io(error.to_string()))?;
        session
            .writer
            .flush()
            .await
            .map_err(|error| DataTunnelError::Io(error.to_string()))?;
        let mut buf = [0u8; 64];
        let n = session
            .reader
            .read(&mut buf)
            .await
            .map_err(|error| DataTunnelError::Io(error.to_string()))?;
        Ok(buf[..n].to_vec())
    }

    async fn open_error<P, S, I>(router: &RelayStreamOfferTargetRouter<P, S, I>) -> DataTunnelError
    where
        P: ClawTargetRouter,
        S: ClawTargetRouter,
        I: RelayStreamIpTunnelRouter,
    {
        match router.open(CLAW_ID).await {
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

    async fn router_for(
        resource: RelayStreamResource,
        slots: Arc<ClawShareSlotStore>,
    ) -> RelayStreamOfferTargetRouter<TcpStreamRouter, TcpStreamRouter> {
        let pty_addr = spawn_ack_target(b"PTY:").await;
        let site_addr = spawn_ack_target(b"SITE:").await;
        RelayStreamOfferTargetRouter::new(
            offer(resource),
            trust(),
            slots,
            TcpStreamRouter::new(pty_addr),
            TcpStreamRouter::new(site_addr),
            || Some(NOW),
        )
    }

    fn gate_for(
        resource: RelayStreamResource,
        slots: Arc<ClawShareSlotStore>,
    ) -> RelayStreamOfferTargetGate {
        RelayStreamOfferTargetGate::new(offer(resource), trust(), slots, || Some(NOW))
    }

    // Builds a router over unreachable backends, so a validation failure surfaces
    // as `TargetUnavailable` rather than a backend connect error: any open that
    // resolves to `TargetUnavailable` provably rejected before dialing a backend.
    fn router_with(
        offer: RelayStreamOfferContract,
        slots: Arc<ClawShareSlotStore>,
        now_unix: impl Fn() -> Option<u64> + Send + Sync + 'static,
    ) -> RelayStreamOfferTargetRouter<TcpStreamRouter, TcpStreamRouter> {
        RelayStreamOfferTargetRouter::new(
            offer,
            trust(),
            slots,
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new("127.0.0.1:1"),
            now_unix,
        )
    }

    #[tokio::test]
    async fn relay_stream_target_router_denies_when_clock_unusable_without_touching_backend() {
        // An unusable wall clock cannot enforce `not_after`, so it can only
        // deny. `router_with` points at an unreachable backend, so resolving to
        // `TargetUnavailable` proves nothing was dialed. The reason stays the
        // existing opaque one: a broken clock must not be distinguishable from
        // an invalid offer.
        let router = router_with(offer(RelayStreamResource::Pty), consumed_slots(), || None);

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(ref reason)
                if reason == "relay-stream-offer-invalid"),
            "expected opaque deny, got {error:?}"
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_denies_clock_at_epoch_and_below_floor() {
        // `Ok(0)` is the SUCCESS branch of `duration_since`, and a merely late
        // clock weakens expiry proportionally. Both must deny, not just `Err`.
        for reading in [
            0_u64,
            crate::claw_share_session_clock::MIN_PLAUSIBLE_UNIX_SECS - 1,
        ] {
            let router = router_with(
                offer(RelayStreamResource::Pty),
                consumed_slots(),
                move || crate::claw_share_session_clock::plausible_unix_secs(reading),
            );

            let error = open_error(&router).await;

            assert!(
                matches!(error, DataTunnelError::TargetUnavailable(ref reason)
                    if reason == "relay-stream-offer-invalid"),
                "clock reading {reading} must deny, got {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn relay_stream_target_router_pty_happy_path_opens_backend_after_slot_gate() {
        let router = router_for(RelayStreamResource::Pty, consumed_slots()).await;

        let response = open_and_roundtrip(&router).await.unwrap();

        assert_eq!(response, b"PTY:hello");
    }

    #[tokio::test]
    async fn relay_stream_target_router_clawsite_uses_site_router_not_pty() {
        let router = router_for(RelayStreamResource::ClawSite, consumed_slots()).await;

        let response = open_and_roundtrip(&router).await.unwrap();

        assert_eq!(response, b"SITE:hello");
    }

    #[tokio::test]
    async fn relay_stream_target_router_iptunnel_fails_closed_until_vpn_agent_exists() {
        let router = RelayStreamOfferTargetRouter::new(
            group_iptunnel_offer(),
            group_trust(group_projection(true, true, true)),
            empty_slots(),
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new("127.0.0.1:1"),
            || Some(NOW),
        );

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-iptunnel-not-configured")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_iptunnel_delegates_to_injected_router_after_gate() {
        let ip_addr = spawn_ack_target(b"IP:").await;
        let router = RelayStreamOfferTargetRouter::new_with_ip_tunnel_router(
            group_iptunnel_offer(),
            group_trust(group_projection(true, true, true)),
            empty_slots(),
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new("127.0.0.1:1"),
            AckIpTunnelRouter::new(ip_addr),
            || Some(NOW),
        );

        let response = open_and_roundtrip(&router).await.unwrap();

        assert_eq!(response, b"IP:hello");
    }

    #[derive(Clone)]
    struct RecordingIpTunnelRouter {
        seen: Arc<Mutex<Option<RelayStreamIpTunnelTarget>>>,
    }

    impl RelayStreamIpTunnelRouter for RecordingIpTunnelRouter {
        async fn open_ip_tunnel(
            &self,
            target: RelayStreamIpTunnelTarget,
        ) -> Result<TargetSession, DataTunnelError> {
            *self.seen.lock().unwrap() = Some(target);
            Err(target_unavailable("recording-iptunnel-router"))
        }
    }

    #[tokio::test]
    async fn relay_stream_target_router_iptunnel_passes_group_context_to_backend() {
        let seen = Arc::new(Mutex::new(None));
        let router = RelayStreamOfferTargetRouter::new_with_ip_tunnel_router(
            group_iptunnel_offer(),
            group_trust(group_projection(true, true, true)),
            empty_slots(),
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new("127.0.0.1:1"),
            RecordingIpTunnelRouter {
                seen: Arc::clone(&seen),
            },
            || Some(NOW),
        );

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "recording-iptunnel-router")
        );
        let target = seen.lock().unwrap().clone().expect("backend saw context");
        assert_eq!(target.group_id(), "g");
        assert_eq!(target.member_id(), "g_a");
        assert_eq!(target.member_device_pub(), &guest().public());
        assert_eq!(target.claw_id(), CLAW_ID);
    }

    #[test]
    fn relay_stream_target_gate_resource_is_exact_before_future_packet_path() {
        for (offer_resource, expected_resource) in [
            (RelayStreamResource::Pty, RelayStreamResource::IpTunnel),
            (RelayStreamResource::ClawSite, RelayStreamResource::IpTunnel),
            (RelayStreamResource::IpTunnel, RelayStreamResource::Pty),
            (RelayStreamResource::IpTunnel, RelayStreamResource::ClawSite),
        ] {
            let gate = gate_for(offer_resource, consumed_slots());
            let error = gate
                .validate_target_for_resource(CLAW_ID, expected_resource)
                .unwrap_err();
            assert!(
                matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-resource-mismatch"),
                "{offer_resource:?} offer must not authorize {expected_resource:?}"
            );
        }

        let ip_gate = RelayStreamOfferTargetGate::new(
            group_iptunnel_offer(),
            group_trust(group_projection(true, true, true)),
            empty_slots(),
            || Some(NOW),
        );
        ip_gate.validate_ip_tunnel_target(CLAW_ID).expect(
            "Group-scoped IpTunnel offer should pass the exact resource/member gate before runtime remains fail-closed",
        );
    }

    // ── Fase E2: Group + Public dial-path ────────────────────────────────────

    fn group_trust(projection: ProjectedState) -> RelayStreamIssuerTrust {
        // Same signer authorization as `trust()`, but a custom projection so the
        // Group branch sees real groups/member_devices. The offer signer (owner)
        // is authorized exactly as in the Device tests.
        RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
            record: record(),
            cert: machine_cert(),
            projection: projection.clone(),
        })
    }

    fn group_projection(
        member_active: bool,
        claw_granted: bool,
        device_active: bool,
    ) -> ProjectedState {
        let st = |on: bool| {
            if on {
                MeshMembership::Active
            } else {
                MeshMembership::Removed
            }
        };
        let mut p = ProjectedState::default();
        p.groups.insert(
            "g".to_string(),
            ProjectedGroup {
                group_id: "g".to_string(),
                name: "Família".to_string(),
                members: [("g_a".to_string(), st(member_active))]
                    .into_iter()
                    .collect(),
                member_labels: Default::default(),
                granted_claws: [(CLAW_ID.to_string(), st(claw_granted))]
                    .into_iter()
                    .collect(),
                revision: 1,
            },
        );
        p.member_devices.insert(
            "g_a".to_string(),
            [(
                guest().public().as_bytes()[..].to_vec(),
                ProjectedMemberDevice {
                    participant_npub: "npub".to_string(),
                    status: st(device_active),
                },
            )]
            .into_iter()
            .collect(),
        );
        p
    }

    fn group_offer(resource: RelayStreamResource) -> RelayStreamOfferContract {
        mint_relay_stream_group_offer(
            RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
            SlotId([0x99; 16]),
            "g".to_string(),
            "g_a".to_string(),
            guest().public(),
            CLAW_ID.to_string(),
            resource,
            "relay-stream://127.0.0.1:49152".to_string(),
            static_pub(),
            NOW + 60,
            NOW,
            &owner(),
        )
        .unwrap()
    }

    fn group_clawsite_offer() -> RelayStreamOfferContract {
        group_offer(RelayStreamResource::ClawSite)
    }

    // Simulates a validly signed Group/PTY contract minted before the policy
    // fix (or assembled without the official mint helper). The open-time gate
    // must reject it before either backend is contacted.
    fn legacy_group_pty_offer() -> RelayStreamOfferContract {
        let mut payload = offer(RelayStreamResource::Pty).payload;
        payload.authz = Some(RelayStreamAudience::Group {
            group_id: "g".to_string(),
            member_id: "g_a".to_string(),
        });
        RelayStreamOfferContract::sign(payload, &owner()).unwrap()
    }

    fn group_iptunnel_offer() -> RelayStreamOfferContract {
        group_offer(RelayStreamResource::IpTunnel)
    }

    async fn group_router(
        projection: ProjectedState,
        site_addr: String,
    ) -> RelayStreamOfferTargetRouter<TcpStreamRouter, TcpStreamRouter> {
        RelayStreamOfferTargetRouter::new(
            group_clawsite_offer(),
            group_trust(projection),
            empty_slots(), // Group path must NOT consult the slot store.
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new(site_addr),
            || Some(NOW),
        )
    }

    #[tokio::test]
    async fn relay_stream_target_router_group_member_opens_site_without_slot() {
        let site_addr = spawn_ack_target(b"SITE:").await;
        let router = group_router(group_projection(true, true, true), site_addr).await;

        let response = open_and_roundtrip(&router).await.unwrap();

        assert_eq!(response, b"SITE:hello");
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_legacy_group_pty_before_backend() {
        let router = RelayStreamOfferTargetRouter::new(
            legacy_group_pty_offer(),
            group_trust(group_projection(true, true, true)),
            empty_slots(),
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new("127.0.0.1:1"),
            || Some(NOW),
        );

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-offer-invalid")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_group_fails_closed_on_membership_loss() {
        // Member removed / grant revoked / device retired / unknown group all
        // collapse to one opaque TargetUnavailable — the live-projection gate.
        for projection in [
            group_projection(false, true, true),
            group_projection(true, false, true),
            group_projection(true, true, false),
            ProjectedState::default(),
        ] {
            let router = group_router(projection, "127.0.0.1:1".to_string()).await;
            let error = open_error(&router).await;
            assert!(matches!(error, DataTunnelError::TargetUnavailable(_)));
        }
    }

    fn public_offer(resource: RelayStreamResource) -> RelayStreamOfferContract {
        mint_relay_stream_public_offer(
            RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
            SlotId([0x98; 16]),
            guest().public(),
            CLAW_ID.to_string(),
            resource,
            "relay-stream://127.0.0.1:49152".to_string(),
            static_pub(),
            NOW + 60,
            NOW,
            &owner(),
        )
        .unwrap()
    }

    fn public_clawsite_offer() -> RelayStreamOfferContract {
        public_offer(RelayStreamResource::ClawSite)
    }

    async fn public_router(
        projection: ProjectedState,
        site_addr: String,
    ) -> RelayStreamOfferTargetRouter<TcpStreamRouter, TcpStreamRouter> {
        RelayStreamOfferTargetRouter::new(
            public_clawsite_offer(),
            group_trust(projection),
            empty_slots(),
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new(site_addr),
            || Some(NOW),
        )
    }

    #[tokio::test]
    async fn relay_stream_target_router_public_opens_only_when_published() {
        // Published → anyone opens (no slot, no group).
        let mut published = ProjectedState::default();
        published
            .published_claws
            .insert(CLAW_ID.to_string(), MeshMembership::Active);
        let site_addr = spawn_ack_target(b"SITE:").await;
        let router = public_router(published, site_addr).await;
        assert_eq!(open_and_roundtrip(&router).await.unwrap(), b"SITE:hello");

        // Unpublished / absent → fail closed.
        let router = public_router(ProjectedState::default(), "127.0.0.1:1".to_string()).await;
        let error = open_error(&router).await;
        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-claw-not-published")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_iptunnel_rejects_device_audience_before_backend() {
        let ip_addr = spawn_ack_target(b"IP:").await;
        let router = RelayStreamOfferTargetRouter::new_with_ip_tunnel_router(
            offer(RelayStreamResource::IpTunnel),
            trust(),
            consumed_slots(),
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new("127.0.0.1:1"),
            AckIpTunnelRouter::new(ip_addr),
            || Some(NOW),
        );

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-iptunnel-member-required")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_iptunnel_rejects_public_audience_before_backend() {
        let mut published = ProjectedState::default();
        published
            .published_claws
            .insert(CLAW_ID.to_string(), MeshMembership::Active);
        let ip_addr = spawn_ack_target(b"IP:").await;
        let router = RelayStreamOfferTargetRouter::new_with_ip_tunnel_router(
            public_offer(RelayStreamResource::IpTunnel),
            group_trust(published),
            empty_slots(),
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new("127.0.0.1:1"),
            AckIpTunnelRouter::new(ip_addr),
            || Some(NOW),
        );

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-iptunnel-member-required")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_wrong_target_id() {
        let router = router_for(RelayStreamResource::Pty, consumed_slots()).await;

        let error = match router.open("other_claw").await {
            Ok(_) => panic!("expected target open to fail"),
            Err(error) => error,
        };

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-target-mismatch")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_missing_slot() {
        let router = router_for(RelayStreamResource::Pty, empty_slots()).await;

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-slot-not-found")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_slot_claw_mismatch() {
        let slots = slots_with_record(SlotRecord {
            slot_id: SLOT,
            claw_id: "other_claw".to_string(),
            expires_at: NOW + 600,
            state: SlotState::Consumed {
                guest_device_pub: guest().public(),
                consumed_at: NOW - 30,
            },
            app_presentation: None,
            created_at: None,
        });
        let router = router_for(RelayStreamResource::Pty, slots).await;

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-slot-claw-mismatch")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_open_slot() {
        let router = router_for(RelayStreamResource::Pty, slots_with(SlotState::Open)).await;

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-slot-open")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_revoked_slot() {
        let router = router_for(
            RelayStreamResource::Pty,
            slots_with(SlotState::Revoked {
                revoked_at: NOW,
                accepted_at: None,
            }),
        )
        .await;

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-slot-revoked")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_consumed_guest_mismatch() {
        let router = router_for(
            RelayStreamResource::Pty,
            slots_with(SlotState::Consumed {
                guest_device_pub: other_guest_pub(),
                consumed_at: NOW - 30,
            }),
        )
        .await;

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-guest-device-mismatch")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_expired_slot_by_clock() {
        let slots = slots_with_record(SlotRecord {
            slot_id: SLOT,
            claw_id: CLAW_ID.to_string(),
            expires_at: NOW,
            state: SlotState::Consumed {
                guest_device_pub: guest().public(),
                consumed_at: NOW - 30,
            },
            app_presentation: None,
            created_at: None,
        });
        let router = router_for(RelayStreamResource::Pty, slots).await;

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-slot-expired")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_expired_offer_with_valid_slot() {
        // The offer is minted valid at NOW with not_after = NOW + 60, but the
        // router clock is past that horizon while the slot still lives until
        // NOW + 600. The offer's own expiry gate must reject the open even though
        // the slot has not expired and its signature is untampered.
        let router = router_with(offer(RelayStreamResource::Pty), consumed_slots(), || {
            Some(NOW + 120)
        });

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-offer-invalid")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_attacker_signed_offer_before_backend() {
        let forged =
            RelayStreamOfferContract::sign(offer(RelayStreamResource::Pty).payload, &attacker())
                .unwrap();
        let router = router_with(forged, consumed_slots(), || Some(NOW));

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-offer-invalid")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_tampered_offer_before_backend() {
        let mut tampered = offer(RelayStreamResource::Pty);
        tampered.payload.relay_endpoint = "relay-stream://127.0.0.1:49153".to_string();
        let router = router_with(tampered, consumed_slots(), || Some(NOW));

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-offer-invalid")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_non_relay_stream_path() {
        let community_offer = offer_with_path(
            RelayStreamResource::Pty,
            RelayStreamExpectedPath::CommunityRelay,
        );
        let router = router_with(community_offer, consumed_slots(), || Some(NOW));

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-path-mismatch")
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_rejects_revoked_issuer_offer() {
        // The offer is well-formed and machine-signed, but the live projection
        // has removed the issuing machine from the household directory. The open
        // gate must honor that kill switch and collapse to the opaque reason.
        let router = RelayStreamOfferTargetRouter::new(
            offer(RelayStreamResource::Pty),
            trust_revoked(),
            consumed_slots(),
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new("127.0.0.1:1"),
            || Some(NOW),
        );

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-offer-invalid")
        );
    }

    #[test]
    fn relay_stream_target_router_debug_does_not_leak_rendezvous_token() {
        let pty = TcpStreamRouter::new("127.0.0.1:1");
        let site = TcpStreamRouter::new("127.0.0.1:1");
        let router = RelayStreamOfferTargetRouter::new(
            offer(RelayStreamResource::Pty),
            trust(),
            consumed_slots(),
            pty,
            site,
            || Some(NOW),
        );

        let debug = format!("{router:?}");

        assert!(!debug.contains("42424242424242424242424242424242"));
        assert!(!debug.contains("BBBBBBBBBBBBBBBB"));
        assert!(debug.contains("redacted"));
        assert!(debug.contains(CLAW_ID));
    }

    // ── Fase E2/E3: invariant #4 (single snapshot) + cross-mode isolation ─────

    #[tokio::test]
    async fn relay_stream_target_router_group_reads_one_projection_snapshot_per_open() {
        // Invariant #4 (the #1 fail-closed property): the Group membership check
        // must run on the SAME live projection that gated the signer — exactly ONE
        // (self.source)() read per open, never a second snapshot (no TOCTOU).
        //
        // Proven two ways at once: (1) the trust source is invoked exactly once per
        // open; (2) a source that would FLIP the member/grant/device to Removed on
        // any second read still OPENS, because both the issuer-trust check and the
        // membership check consume the single first snapshot. A regression that
        // re-read the source for the membership check would observe the removed
        // member and fail closed — tripping both assertions below.
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_src = Arc::clone(&calls);
        let trust = RelayStreamIssuerTrust::new(move || {
            let n = calls_src.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let projection = if n == 0 {
                group_projection(true, true, true)
            } else {
                group_projection(false, false, false)
            };
            RelayStreamTrustContext {
                record: record(),
                cert: machine_cert(),
                projection,
            }
        });
        let site_addr = spawn_ack_target(b"SITE:").await;
        let router = RelayStreamOfferTargetRouter::new(
            group_clawsite_offer(),
            trust,
            empty_slots(),
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new(site_addr),
            || Some(NOW),
        );

        let response = open_and_roundtrip(&router).await.unwrap();

        assert_eq!(response, b"SITE:hello");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "Group-verify must read the trust projection exactly ONCE per open \
             (single snapshot; no TOCTOU between issuer-trust and membership)"
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_device_offer_not_authorized_by_group_membership() {
        // Cross-mode isolation: a device that IS an active group member still
        // cannot open a DEVICE-audience offer without a consumed slot. Group
        // membership must never leak into the Device gate.
        let router = RelayStreamOfferTargetRouter::new(
            offer(RelayStreamResource::Pty),                 // Device audience
            group_trust(group_projection(true, true, true)), // device is an active group member
            empty_slots(),                                   // but no consumed slot
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new("127.0.0.1:1"),
            || Some(NOW),
        );

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-slot-not-found"),
            "group membership must not satisfy the Device slot gate"
        );
    }

    #[tokio::test]
    async fn relay_stream_target_router_group_offer_not_authorized_by_consumed_slot() {
        // Cross-mode isolation: a slot consumed by the dialing device does NOT
        // authorize a GROUP-audience offer when group membership is absent. Slot
        // consumption must never leak into the Group gate.
        let router = RelayStreamOfferTargetRouter::new(
            group_clawsite_offer(),                 // Group audience, device = guest()
            group_trust(ProjectedState::default()), // no group / grant / member at all
            consumed_slots(), // slot consumed by guest() (would pass the Device gate)
            TcpStreamRouter::new("127.0.0.1:1"),
            TcpStreamRouter::new("127.0.0.1:1"),
            || Some(NOW),
        );

        let error = open_error(&router).await;

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "relay-stream-group-unknown"),
            "a consumed slot must not authorize a Group offer"
        );
    }
}
