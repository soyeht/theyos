//! Engine-side trust gate for the Product A `relay_stream` Noise handshake.
//!
//! C7c-2c-2b moved the trust-free Noise transport primitives (initiator,
//! responder, session, framed stream, async stream, frame codec, consts, error)
//! into household-rs so the guest (friend-cli) can dial. This module re-exports
//! them at the original path and adds the ENGINE-SIDE TRUST GATE.
//!
//! The household responder is prologue-driven and does ZERO trust work — it is a
//! pure transport primitive. The authorization boundary lives here:
//! [`responder_handshake_with_trust`] derives the Noise prologue from a
//! machine-issuer-verified offer (via [`RelayStreamIssuerTrust::to_noise_prologue`],
//! which runs `verify_with_trust(record, cert, projection, now)`) BEFORE running
//! the prologue-driven handshake, and fails closed if verification fails. Every
//! responder entry point (the responder server and the relay listener) MUST go
//! through this gate — never the bare household responder. The prologue bytes
//! are byte-identical to the guest's audience-verified prologue; only which side
//! computes them changed.

use tokio::io::{AsyncRead, AsyncWrite};

pub use household_rs::claw_share_relay_stream_noise::*;

use crate::claw_share_relay_stream_contract::RelayStreamOfferContract;
use crate::claw_share_relay_stream_issuer_trust::RelayStreamIssuerTrust;

/// Runs the responder handshake after verifying the offer against household
/// machine-issuer trust.
///
/// This is the only sanctioned responder entry point on the engine. It gates on
/// `trust.to_noise_prologue` — machine-issuer `verify_with_trust` plus offer
/// freshness — and only then drives the prologue-driven household responder. A
/// rejected offer (unauthorized/wrong signer, revoked machine, expired) fails
/// closed here, before any handshake bytes are exchanged and before the data
/// tunnel ever opens.
pub async fn responder_handshake_with_trust<T>(
    stream: T,
    offer: &RelayStreamOfferContract,
    trust: &RelayStreamIssuerTrust,
    now_unix: u64,
    static_private_key: &RelayStreamNoiseStaticPrivateKey,
) -> Result<RelayStreamNoiseFramed<T>, RelayStreamNoiseError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let prologue = trust.to_noise_prologue(offer, now_unix)?;
    RelayStreamNoiseFramed::responder_handshake_with_prologue(stream, &prologue, static_private_key)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    use household_rs::household_mesh_log::{MeshLogStore, emit_directory_device_removed};
    use household_rs::keys::IdentityKey;

    use crate::claw_share_relay_stream_contract::{
        RelayStreamContractError, RelayStreamExpectedPath, RelayStreamOfferPayload,
        RelayStreamResource,
    };
    use crate::claw_share_relay_stream_issuer_trust::RelayStreamTrustContext;
    use crate::claw_share_relay_stream_test_support::{
        DATA_TUNNEL_SLOT, RELAY_STREAM_CLAW_ID, RELAY_STREAM_ENDPOINT, attacker_signer, guest_pub,
        household_root_signer, now_unix, owner_pub, owner_signer, relay_stream_household_record,
        relay_stream_issuer_trust, relay_stream_machine_cert, relay_stream_offer,
        relay_stream_offer_signed_by, rendezvous_token,
    };

    // Happy path: the gate passes a valid, machine-issuer-authorized offer and
    // the prologue-driven handshake completes against a real guest initiator —
    // proving the trust gate produces a byte-identical prologue (the handshake
    // would fail otherwise).
    #[tokio::test]
    async fn responder_handshake_with_trust_completes_with_valid_offer() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = relay_stream_offer(rendezvous_token(0x42), &keypair);
        let trust = relay_stream_issuer_trust();
        let now = now_unix();
        let (initiator_io, responder_io) = duplex(1_000_000);
        let owner = owner_pub();
        let guest = guest_pub();

        let result = tokio::try_join!(
            RelayStreamNoiseFramed::initiator_handshake(initiator_io, &offer, &owner, &guest, now),
            responder_handshake_with_trust(
                responder_io,
                &offer,
                &trust,
                now,
                keypair.private_key(),
            ),
        );

        assert!(result.is_ok());
    }

    // Gate rejects an attacker-signed offer BEFORE the handshake: the prologue
    // derivation fails on machine-issuer trust, so no frame is ever read.
    #[tokio::test]
    async fn responder_handshake_with_trust_rejects_attacker_before_handshake() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer =
            relay_stream_offer_signed_by(rendezvous_token(0x42), &keypair, &attacker_signer());
        let trust = relay_stream_issuer_trust();
        let now = now_unix();
        let (responder_io, _peer) = duplex(1024);

        let result = responder_handshake_with_trust(
            responder_io,
            &offer,
            &trust,
            now,
            keypair.private_key(),
        )
        .await;

        assert!(matches!(
            result,
            Err(RelayStreamNoiseError::Contract(
                RelayStreamContractError::IssuerUnauthorized(_)
            ))
        ));
    }

    // Gate rejects an offer whose (authorized) signer machine has since been
    // revoked via DirectoryDeviceRemoved — kill switch fires before handshake.
    #[tokio::test]
    async fn responder_handshake_with_trust_rejects_revoked_signer_before_handshake() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = relay_stream_offer(rendezvous_token(0x42), &keypair);
        let now = now_unix();

        let mesh = MeshLogStore::new();
        let root = household_root_signer();
        emit_directory_device_removed(
            &mesh,
            &root as &dyn IdentityKey,
            &root.public(),
            &owner_signer().public(),
            now,
        )
        .unwrap();
        let projection = mesh.project();
        let trust = RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
            record: relay_stream_household_record(),
            cert: relay_stream_machine_cert(),
            projection: projection.clone(),
        });
        let (responder_io, _peer) = duplex(1024);

        let result = responder_handshake_with_trust(
            responder_io,
            &offer,
            &trust,
            now,
            keypair.private_key(),
        )
        .await;

        assert!(matches!(
            result,
            Err(RelayStreamNoiseError::Contract(
                RelayStreamContractError::IssuerUnauthorized(_)
            ))
        ));
    }

    // Gate rejects an expired offer before the handshake.
    #[tokio::test]
    async fn responder_handshake_with_trust_rejects_expired_before_handshake() {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let now = now_unix();
        let payload = RelayStreamOfferPayload::new(
            rendezvous_token(0x42),
            RELAY_STREAM_CLAW_ID.to_string(),
            DATA_TUNNEL_SLOT,
            guest_pub(),
            RelayStreamResource::Pty,
            RelayStreamExpectedPath::RelayStream,
            RELAY_STREAM_ENDPOINT.to_string(),
            keypair.public_key().clone(),
            now,
        );
        let expired_offer = RelayStreamOfferContract::sign(payload, &owner_signer()).unwrap();
        let trust = relay_stream_issuer_trust();
        let (responder_io, _peer) = duplex(1024);

        let result = responder_handshake_with_trust(
            responder_io,
            &expired_offer,
            &trust,
            now,
            keypair.private_key(),
        )
        .await;

        assert!(matches!(
            result,
            Err(RelayStreamNoiseError::Contract(
                RelayStreamContractError::Expired
            ))
        ));
    }
}
