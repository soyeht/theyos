//! Internal Claw-responder rendezvous preflight for mobile Claw VPN.
//!
//! This module does not open sockets, spawn Relay-R, install TUN/utun routes,
//! expose handlers, or mutate host networking. It only turns a Mesh-C-authorized
//! Claw-side rendezvous capability into the relay-visible `Claw` hello bytes.

use household_rs::{
    claw_share_rendezvous_hello::{RendezvousHello, RendezvousRole},
    claw_vpn_mobile_mesh_store::{ClawVpnMobileMeshStore, ClawVpnMobileMeshStoreError},
    claw_vpn_mobile_state::{ClawVpnMobileClawId, ClawVpnMobileRendezvousToken},
};

struct MobileClawVpnRendezvousResponderPreflight {
    hello: RendezvousHello,
}

impl MobileClawVpnRendezvousResponderPreflight {
    fn claw(
        store: &ClawVpnMobileMeshStore,
        rendezvous_token: &ClawVpnMobileRendezvousToken,
        claw: &ClawVpnMobileClawId,
    ) -> Result<Self, ClawVpnMobileMeshStoreError> {
        let relay_token = store.authorize_rendezvous_token_for_claw(rendezvous_token, claw)?;
        Ok(Self {
            hello: RendezvousHello::new(RendezvousRole::Claw, relay_token),
        })
    }

    fn into_hello_bytes(self) -> Vec<u8> {
        self.hello.encode()
    }
}

/// Builds a relay-visible `Claw` hello after revalidating the active Mesh-C
/// session for the locally trusted Claw responder identity.
///
/// The caller must provide `claw` from local responder identity/configuration,
/// not from network input. This helper is intentionally not wired to a handler
/// or socket path yet.
pub fn mobile_claw_vpn_rendezvous_responder_preflight_hello_bytes(
    store: &ClawVpnMobileMeshStore,
    rendezvous_token: &ClawVpnMobileRendezvousToken,
    claw: &ClawVpnMobileClawId,
) -> Result<Vec<u8>, ClawVpnMobileMeshStoreError> {
    MobileClawVpnRendezvousResponderPreflight::claw(store, rendezvous_token, claw)
        .map(MobileClawVpnRendezvousResponderPreflight::into_hello_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    use household_rs::claw_share_rendezvous_hello::RendezvousRole;
    use household_rs::claw_vpn_mobile_state::{
        ClawVpnMobileAclGrant, ClawVpnMobileDeviceId, ClawVpnMobileMemberId, ClawVpnMobileMeshError,
    };

    fn member() -> ClawVpnMobileMemberId {
        ClawVpnMobileMemberId::try_new("member-alpha").unwrap()
    }

    fn device() -> ClawVpnMobileDeviceId {
        ClawVpnMobileDeviceId::try_new("device-alpha").unwrap()
    }

    fn claw_alpha() -> ClawVpnMobileClawId {
        ClawVpnMobileClawId::try_new("claw-alpha").unwrap()
    }

    fn claw_beta() -> ClawVpnMobileClawId {
        ClawVpnMobileClawId::try_new("claw-beta").unwrap()
    }

    fn grant(claw: ClawVpnMobileClawId) -> ClawVpnMobileAclGrant {
        ClawVpnMobileAclGrant::new(member(), device(), claw)
    }

    fn ready_store() -> (
        tempfile::TempDir,
        ClawVpnMobileMeshStore,
        ClawVpnMobileRendezvousToken,
    ) {
        let td = tempfile::tempdir().unwrap();
        let store = ClawVpnMobileMeshStore::new(td.path(), 600).unwrap();
        let grant = grant(claw_alpha());
        assert!(store.owner_approved_enroll_device(device()).unwrap());
        assert!(store.set_claw_available(claw_alpha()).unwrap());
        assert!(store.owner_approved_grant(grant.clone()).unwrap());
        let offer_token = store.mint_offer_token(&grant, 100).unwrap();
        let rendezvous_token = store
            .consume_offer_token(&offer_token, &grant, 101)
            .unwrap();
        (td, store, rendezvous_token)
    }

    #[test]
    fn mobile_claw_vpn_responder_preflight_builds_claw_hello_after_revalidation() {
        let (_td, store, rendezvous_token) = ready_store();

        let hello_bytes = mobile_claw_vpn_rendezvous_responder_preflight_hello_bytes(
            &store,
            &rendezvous_token,
            &claw_alpha(),
        )
        .unwrap();
        let decoded = RendezvousHello::decode(&hello_bytes).unwrap();

        assert_eq!(decoded.role, RendezvousRole::Claw);
        assert_eq!(decoded.token, rendezvous_token.relay_token().unwrap());
    }

    #[test]
    fn mobile_claw_vpn_responder_preflight_denies_wrong_claw_without_hello() {
        let (_td, store, rendezvous_token) = ready_store();
        assert!(store.set_claw_available(claw_beta()).unwrap());

        let error = mobile_claw_vpn_rendezvous_responder_preflight_hello_bytes(
            &store,
            &rendezvous_token,
            &claw_beta(),
        )
        .unwrap_err();

        assert_eq!(error.operation(), "authorize_rendezvous_token_for_claw");
        assert_eq!(
            error.model_error(),
            Some(ClawVpnMobileMeshError::SelectedClawMismatch)
        );
    }
}
