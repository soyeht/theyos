//! Internal Claw-responder rendezvous preflight for mobile Claw VPN.
//!
//! This module does not open sockets, spawn Relay-R, install TUN/utun routes,
//! expose handlers, or mutate host networking. It only turns a Mesh-C-authorized
//! Claw-side rendezvous capability into the relay-visible `Claw` hello bytes or
//! writes those bytes to a caller-provided stream.

use std::fmt;

use household_rs::{
    claw_share_rendezvous_hello::{RendezvousHello, RendezvousRole},
    claw_vpn_mobile_mesh_store::{ClawVpnMobileMeshStore, ClawVpnMobileMeshStoreError},
    claw_vpn_mobile_state::{ClawVpnMobileClawId, ClawVpnMobileRendezvousToken},
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

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

#[derive(PartialEq, Eq)]
pub enum MobileClawVpnRendezvousResponderWriteError {
    Authorization(ClawVpnMobileMeshStoreError),
    HelloWriteFailed,
}

impl MobileClawVpnRendezvousResponderWriteError {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Authorization(_) => "authorization_failed",
            Self::HelloWriteFailed => "hello_write_failed",
        }
    }

    #[must_use]
    pub fn authorization_error(&self) -> Option<&ClawVpnMobileMeshStoreError> {
        match self {
            Self::Authorization(error) => Some(error),
            Self::HelloWriteFailed => None,
        }
    }
}

impl fmt::Debug for MobileClawVpnRendezvousResponderWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileClawVpnRendezvousResponderWriteError")
            .field("kind", &self.kind())
            .finish()
    }
}

impl fmt::Display for MobileClawVpnRendezvousResponderWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mobile Claw VPN rendezvous responder hello write failed")
    }
}

impl std::error::Error for MobileClawVpnRendezvousResponderWriteError {}

/// Writes the relay-visible `Claw` hello after revalidating the active Mesh-C
/// session for the locally trusted Claw responder identity.
///
/// The caller supplies the stream. This helper does not open sockets, choose a
/// relay endpoint, or expose the hello bytes to a public response.
pub async fn mobile_claw_vpn_write_rendezvous_responder_hello<W>(
    writer: &mut W,
    store: &ClawVpnMobileMeshStore,
    rendezvous_token: &ClawVpnMobileRendezvousToken,
    claw: &ClawVpnMobileClawId,
) -> Result<(), MobileClawVpnRendezvousResponderWriteError>
where
    W: AsyncWrite + Unpin,
{
    let preflight = MobileClawVpnRendezvousResponderPreflight::claw(store, rendezvous_token, claw)
        .map_err(MobileClawVpnRendezvousResponderWriteError::Authorization)?;
    let hello_bytes = preflight.into_hello_bytes();
    writer
        .write_all(&hello_bytes)
        .await
        .map_err(|_error| MobileClawVpnRendezvousResponderWriteError::HelloWriteFailed)?;
    writer
        .flush()
        .await
        .map_err(|_error| MobileClawVpnRendezvousResponderWriteError::HelloWriteFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use household_rs::claw_share_rendezvous_hello::RendezvousRole;
    use household_rs::claw_vpn_mobile_state::{
        ClawVpnMobileAclGrant, ClawVpnMobileDeviceId, ClawVpnMobileMemberId, ClawVpnMobileMeshError,
    };
    use tokio::io::AsyncReadExt;

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

    #[tokio::test]
    async fn mobile_claw_vpn_responder_preflight_writes_claw_hello_to_stream() {
        let (_td, store, rendezvous_token) = ready_store();
        let (mut writer, mut reader) = tokio::io::duplex(1024);

        mobile_claw_vpn_write_rendezvous_responder_hello(
            &mut writer,
            &store,
            &rendezvous_token,
            &claw_alpha(),
        )
        .await
        .unwrap();
        drop(writer);

        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        let decoded = RendezvousHello::decode(&bytes).unwrap();

        assert_eq!(decoded.role, RendezvousRole::Claw);
        assert_eq!(decoded.token, rendezvous_token.relay_token().unwrap());
    }

    #[tokio::test]
    async fn mobile_claw_vpn_responder_preflight_denies_before_writer() {
        struct PanicOnWrite;

        impl AsyncWrite for PanicOnWrite {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                panic!("writer must not be used when Claw authorization fails");
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                panic!("writer must not be flushed when Claw authorization fails");
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let (_td, store, rendezvous_token) = ready_store();
        assert!(store.set_claw_available(claw_beta()).unwrap());
        let mut writer = PanicOnWrite;

        let error = mobile_claw_vpn_write_rendezvous_responder_hello(
            &mut writer,
            &store,
            &rendezvous_token,
            &claw_beta(),
        )
        .await
        .unwrap_err();

        assert_eq!(error.kind(), "authorization_failed");
        let auth_error = error.authorization_error().unwrap();
        assert_eq!(
            auth_error.operation(),
            "authorize_rendezvous_token_for_claw"
        );
        assert_eq!(
            auth_error.model_error(),
            Some(ClawVpnMobileMeshError::SelectedClawMismatch)
        );
        assert!(!format!("{error:?}").contains("claw-beta"));
        assert!(!error.to_string().contains("claw-beta"));
    }

    #[tokio::test]
    async fn mobile_claw_vpn_responder_preflight_write_error_is_static() {
        struct FailingWriter;

        impl AsyncWrite for FailingWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Poll::Ready(Err(std::io::Error::other(
                    "relay write failed for 203.0.113.10:49152",
                )))
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let (_td, store, rendezvous_token) = ready_store();
        let mut writer = FailingWriter;

        let error = mobile_claw_vpn_write_rendezvous_responder_hello(
            &mut writer,
            &store,
            &rendezvous_token,
            &claw_alpha(),
        )
        .await
        .unwrap_err();

        assert_eq!(error.kind(), "hello_write_failed");
        assert!(error.authorization_error().is_none());
        assert!(!format!("{error:?}").contains("203.0.113.10"));
        assert!(!error.to_string().contains("203.0.113.10"));
    }
}
