#![cfg(test)]

use super::*;
use crate::claw_share::SlotId;
use crate::claw_share::relay_stream_contract::{
    RelayStreamExpectedPath, RelayStreamOfferPayload, RelayStreamResource,
};
use crate::claw_share::rendezvous_token::RendezvousToken;
use crate::keys::{IdentityKey, P256Keypair};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

/// Builds the responder prologue trust-free for these transport tests:
/// owner-verified instead of machine-issuer-trust verified (the trust seam
/// is server-rs). It is byte-identical to the initiator's audience prologue
/// for the same offer, so the handshake still succeeds.
fn responder_prologue(offer: &RelayStreamOfferContract) -> RelayStreamNoisePrologue {
    offer
        .to_noise_prologue_owner_verified(&owner_pub(), NOW)
        .unwrap()
}

const NOW: u64 = 1_800_000_000;
const NOT_AFTER: u64 = NOW + 60;

fn signer() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
}

fn attacker() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap()
}

fn owner_pub() -> P256PublicKey {
    signer().public()
}

fn guest_pub() -> P256PublicKey {
    P256Keypair::from_secret_scalar(&[0x33; 32])
        .unwrap()
        .public()
}

fn other_guest_pub() -> P256PublicKey {
    P256Keypair::from_secret_scalar(&[0x44; 32])
        .unwrap()
        .public()
}

fn token(label: u8) -> RendezvousToken {
    RendezvousToken::try_new(vec![label; 16]).unwrap()
}

fn payload_with(
    claw_static_pub: RelayStreamClawStaticPublicKey,
    edit: impl FnOnce(&mut RelayStreamOfferPayload),
) -> RelayStreamOfferPayload {
    let mut payload = RelayStreamOfferPayload::new(
        token(0x42),
        "claw_alpha".to_string(),
        SlotId([0x22; 16]),
        guest_pub(),
        RelayStreamResource::Pty,
        RelayStreamExpectedPath::RelayStream,
        "relay-stream://127.0.0.1:49152".to_string(),
        claw_static_pub,
        NOT_AFTER,
    );
    edit(&mut payload);
    payload
}

fn signed_offer_with(
    keypair: &RelayStreamNoiseStaticKeypair,
    edit: impl FnOnce(&mut RelayStreamOfferPayload),
) -> RelayStreamOfferContract {
    RelayStreamOfferContract::sign(payload_with(keypair.public_key().clone(), edit), &signer())
        .unwrap()
}

fn signed_offer(keypair: &RelayStreamNoiseStaticKeypair) -> RelayStreamOfferContract {
    signed_offer_with(keypair, |_| {})
}

fn handshake_pair(
    offer: &RelayStreamOfferContract,
    keypair: &RelayStreamNoiseStaticKeypair,
) -> (RelayStreamNoiseSession, RelayStreamNoiseSession) {
    let mut initiator =
        RelayStreamNoiseInitiator::new(offer, &owner_pub(), &guest_pub(), NOW).unwrap();
    let mut responder =
        RelayStreamNoiseResponder::new(&responder_prologue(offer), keypair.private_key()).unwrap();
    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let (msg2, responder_session) = responder.write_message_2().unwrap();
    let initiator_session = initiator.read_message_2(&msg2).unwrap();
    (initiator_session, responder_session)
}

async fn framed_pair(
    offer: &RelayStreamOfferContract,
    keypair: &RelayStreamNoiseStaticKeypair,
) -> (
    RelayStreamNoiseFramed<DuplexStream>,
    RelayStreamNoiseFramed<DuplexStream>,
) {
    let (initiator_io, responder_io) = duplex(1_000_000);
    let owner = owner_pub();
    let guest = guest_pub();
    let prologue = responder_prologue(offer);
    tokio::try_join!(
        RelayStreamNoiseFramed::initiator_handshake(initiator_io, offer, &owner, &guest, NOW,),
        RelayStreamNoiseFramed::responder_handshake_with_prologue(
            responder_io,
            &prologue,
            keypair.private_key(),
        )
    )
    .unwrap()
}

async fn async_stream_pair(
    offer: &RelayStreamOfferContract,
    keypair: &RelayStreamNoiseStaticKeypair,
) -> (
    RelayStreamNoiseAsyncStream<DuplexStream>,
    RelayStreamNoiseAsyncStream<DuplexStream>,
) {
    let (initiator, responder) = framed_pair(offer, keypair).await;
    (initiator.into_async_stream(), responder.into_async_stream())
}

#[test]
fn relay_contract_noise_handshake_nk_succeeds_with_same_offer_prologue_and_key() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&keypair);

    let (_initiator_session, _responder_session) = handshake_pair(&offer, &keypair);
}

#[test]
fn relay_contract_noise_encrypt_decrypt_roundtrip_after_handshake() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&keypair);
    let (mut initiator_session, mut responder_session) = handshake_pair(&offer, &keypair);

    let secret_plaintext = b"relay stream plaintext stays inside transport state";
    let ciphertext = initiator_session.encrypt(secret_plaintext).unwrap();
    assert_ne!(ciphertext, secret_plaintext);
    let decrypted = responder_session.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, secret_plaintext);

    let reply = b"reply plaintext stays inside transport state";
    let reply_ciphertext = responder_session.encrypt(reply).unwrap();
    let reply_decrypted = initiator_session.decrypt(&reply_ciphertext).unwrap();
    assert_eq!(reply_decrypted, reply);
}

#[test]
fn relay_contract_noise_divergent_token_prologue_fails_handshake() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let initiator_offer =
        signed_offer_with(&keypair, |payload| payload.rendezvous_token = token(0x43));
    let responder_offer = signed_offer(&keypair);

    let mut initiator =
        RelayStreamNoiseInitiator::new(&initiator_offer, &owner_pub(), &guest_pub(), NOW).unwrap();
    let mut responder = RelayStreamNoiseResponder::new(
        &responder_prologue(&responder_offer),
        keypair.private_key(),
    )
    .unwrap();
    let msg1 = initiator.write_message_1().unwrap();

    assert!(matches!(
        responder.read_message_1(&msg1),
        Err(RelayStreamNoiseError::Snow(_))
    ));
}

#[test]
fn relay_contract_noise_wrong_responder_static_key_fails_handshake() {
    let expected_keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let wrong_keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&expected_keypair);

    let mut initiator =
        RelayStreamNoiseInitiator::new(&offer, &owner_pub(), &guest_pub(), NOW).unwrap();
    let mut responder =
        RelayStreamNoiseResponder::new(&responder_prologue(&offer), wrong_keypair.private_key())
            .unwrap();
    let msg1 = initiator.write_message_1().unwrap();

    assert!(matches!(
        responder.read_message_1(&msg1),
        Err(RelayStreamNoiseError::Snow(_))
    ));
}

#[test]
fn relay_contract_noise_attacker_signed_offer_does_not_start_handshake() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = RelayStreamOfferContract::sign(
        payload_with(keypair.public_key().clone(), |_| {}),
        &attacker(),
    )
    .unwrap();

    assert!(matches!(
        RelayStreamNoiseInitiator::new(&offer, &owner_pub(), &guest_pub(), NOW),
        Err(RelayStreamNoiseError::Contract(
            RelayStreamContractError::SignerMismatch
        ))
    ));
    // Trust-free responder prologue derivation rejects the attacker signer
    // (owner-verify). The machine-issuer-trust IssuerUnauthorized path is
    // covered engine-side in server-rs claw_share_relay_stream_noise.
    assert!(matches!(
        offer.to_noise_prologue_owner_verified(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignerMismatch)
    ));
}

#[test]
fn relay_contract_noise_expired_offer_does_not_start_handshake() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer_with(&keypair, |payload| payload.not_after = NOW);

    assert!(matches!(
        RelayStreamNoiseInitiator::new(&offer, &owner_pub(), &guest_pub(), NOW),
        Err(RelayStreamNoiseError::Contract(
            RelayStreamContractError::Expired
        ))
    ));
    assert!(matches!(
        offer.to_noise_prologue_owner_verified(&owner_pub(), NOW),
        Err(RelayStreamContractError::Expired)
    ));
}

#[test]
fn relay_contract_noise_wrong_guest_audience_does_not_start_initiator() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&keypair);

    assert!(matches!(
        RelayStreamNoiseInitiator::new(&offer, &owner_pub(), &other_guest_pub(), NOW),
        Err(RelayStreamNoiseError::Contract(
            RelayStreamContractError::AudienceMismatch
        ))
    ));
    // The responder prologue does not bind the guest audience — that check is
    // the initiator/guest's job — so it builds for any audience.
    assert!(
        RelayStreamNoiseResponder::new(&responder_prologue(&offer), keypair.private_key()).is_ok()
    );
}

#[test]
fn relay_contract_noise_debug_does_not_leak_private_key_token_or_plaintext() {
    let private =
        RelayStreamNoiseStaticPrivateKey::try_new([0x41; RELAY_STREAM_NOISE_KEY_LEN]).unwrap();
    let private_debug = format!("{private:?}");
    assert!(!private_debug.contains("414141"));
    assert!(!private_debug.contains("AAAA"));
    assert!(private_debug.contains("redacted"));

    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer_with(&keypair, |payload| {
        payload.rendezvous_token = RendezvousToken::try_new(b"0123456789abcdef").unwrap();
    });
    let mut initiator =
        RelayStreamNoiseInitiator::new(&offer, &owner_pub(), &guest_pub(), NOW).unwrap();
    let mut responder =
        RelayStreamNoiseResponder::new(&responder_prologue(&offer), keypair.private_key()).unwrap();
    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let (msg2, responder_session) = responder.write_message_2().unwrap();
    let initiator_session = initiator.read_message_2(&msg2).unwrap();

    let debug = format!("{initiator_session:?} {responder_session:?}");
    assert!(!debug.contains("0123456789abcdef"));
    assert!(!debug.contains("30313233343536373839616263646566"));
    assert!(!debug.contains("relay stream plaintext stays inside transport state"));
    assert!(debug.contains("redacted"));
}

#[tokio::test]
async fn relay_contract_noise_framed_handshake_and_bidirectional_plaintext() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&keypair);
    let (mut initiator, mut responder) = framed_pair(&offer, &keypair).await;

    let to_responder = b"guest-to-claw framed plaintext";
    let to_initiator = b"claw-to-guest framed plaintext";
    let initiator_task = async {
        initiator.write_all_encrypted(to_responder).await?;
        initiator.read_exact_encrypted(to_initiator.len()).await
    };
    let responder_task = async {
        let received = responder.read_exact_encrypted(to_responder.len()).await?;
        responder.write_all_encrypted(to_initiator).await?;
        Ok::<_, RelayStreamNoiseError>(received)
    };

    let (reply, request) = tokio::try_join!(initiator_task, responder_task).unwrap();
    assert_eq!(request, to_responder);
    assert_eq!(reply, to_initiator);
}

#[tokio::test]
async fn relay_contract_noise_framed_chunks_large_plaintext_and_reconstructs() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&keypair);
    let (mut initiator, mut responder) = framed_pair(&offer, &keypair).await;
    let plaintext_len = RELAY_STREAM_NOISE_MAX_PLAINTEXT_RECORD_LEN * 2 + 123;
    let plaintext = (0..plaintext_len)
        .map(|idx| u8::try_from(idx % 251).unwrap())
        .collect::<Vec<_>>();

    let writer = async { initiator.write_all_encrypted(&plaintext).await };
    let reader = async { responder.read_exact_encrypted(plaintext.len()).await };

    let ((), received) = tokio::try_join!(writer, reader).unwrap();
    assert_eq!(received, plaintext);
}

#[tokio::test]
async fn relay_contract_noise_framed_oversized_and_empty_frames_are_rejected() {
    let (mut writer, mut reader) = duplex(8);
    let oversized = u32::try_from(RELAY_STREAM_NOISE_MAX_FRAME_LEN + 1).unwrap();
    writer.write_all(&oversized.to_be_bytes()).await.unwrap();

    assert!(matches!(
        read_noise_frame(&mut reader).await,
        Err(RelayStreamNoiseError::FrameTooLarge { actual, max })
            if actual == u64::from(oversized) && max == RELAY_STREAM_NOISE_MAX_FRAME_LEN
    ));

    let (mut writer, mut reader) = duplex(8);
    writer.write_all(&0u32.to_be_bytes()).await.unwrap();

    assert!(matches!(
        read_noise_frame(&mut reader).await,
        Err(RelayStreamNoiseError::EmptyFrame)
    ));
}

#[tokio::test]
async fn relay_contract_noise_framed_unexpected_handshake_payload_is_rejected() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&keypair);
    let prologue = offer.to_noise_prologue(&owner_pub(), NOW).unwrap();
    let mut malicious_initiator = noise_builder()
        .unwrap()
        .prologue(prologue.as_bytes())
        .unwrap()
        .remote_public_key(offer.payload.claw_static_pub.as_bytes())
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut message = vec![0u8; RELAY_STREAM_NOISE_MAX_FRAME_LEN];
    let len = malicious_initiator
        .write_message(b"unexpected-handshake-payload", &mut message)
        .unwrap();
    message.truncate(len);

    let (mut initiator_io, responder_io) = duplex(4096);
    let writer = async { write_noise_frame(&mut initiator_io, &message).await };
    let prologue = responder_prologue(&offer);
    let responder = RelayStreamNoiseFramed::responder_handshake_with_prologue(
        responder_io,
        &prologue,
        keypair.private_key(),
    );

    let (write_result, responder_result) = tokio::join!(writer, responder);
    write_result.unwrap();
    assert!(matches!(
        responder_result,
        Err(RelayStreamNoiseError::UnexpectedHandshakePayload)
    ));
}

#[tokio::test]
async fn relay_contract_noise_framed_divergent_prologue_and_wrong_key_fail() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let initiator_offer =
        signed_offer_with(&keypair, |payload| payload.rendezvous_token = token(0x43));
    let responder_offer = signed_offer(&keypair);
    let (initiator_io, responder_io) = duplex(4096);
    let owner = owner_pub();
    let guest = guest_pub();
    let prologue = responder_prologue(&responder_offer);
    let result = tokio::try_join!(
        RelayStreamNoiseFramed::initiator_handshake(
            initiator_io,
            &initiator_offer,
            &owner,
            &guest,
            NOW,
        ),
        RelayStreamNoiseFramed::responder_handshake_with_prologue(
            responder_io,
            &prologue,
            keypair.private_key(),
        )
    );

    assert!(matches!(result, Err(RelayStreamNoiseError::Snow(_))));

    let expected_keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let wrong_keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&expected_keypair);
    let (initiator_io, responder_io) = duplex(4096);
    let owner = owner_pub();
    let guest = guest_pub();
    let prologue = responder_prologue(&offer);
    let result = tokio::try_join!(
        RelayStreamNoiseFramed::initiator_handshake(initiator_io, &offer, &owner, &guest, NOW,),
        RelayStreamNoiseFramed::responder_handshake_with_prologue(
            responder_io,
            &prologue,
            wrong_keypair.private_key(),
        )
    );

    assert!(matches!(result, Err(RelayStreamNoiseError::Snow(_))));
}

#[tokio::test]
async fn relay_contract_noise_framed_attacker_and_expired_contracts_do_not_start() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let attacker_offer = RelayStreamOfferContract::sign(
        payload_with(keypair.public_key().clone(), |_| {}),
        &attacker(),
    )
    .unwrap();
    let (stream, _peer) = duplex(1024);
    let owner = owner_pub();
    let guest = guest_pub();

    assert!(matches!(
        RelayStreamNoiseFramed::initiator_handshake(stream, &attacker_offer, &owner, &guest, NOW,)
            .await,
        Err(RelayStreamNoiseError::Contract(
            RelayStreamContractError::SignerMismatch
        ))
    ));

    let expired_offer = signed_offer_with(&keypair, |payload| payload.not_after = NOW);

    assert!(matches!(
        expired_offer.to_noise_prologue_owner_verified(&owner_pub(), NOW),
        Err(RelayStreamContractError::Expired)
    ));
}

#[tokio::test]
async fn relay_contract_noise_framed_debug_does_not_leak_secret_material() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer_with(&keypair, |payload| {
        payload.rendezvous_token = RendezvousToken::try_new(b"0123456789abcdef").unwrap();
    });
    let (initiator, responder) = framed_pair(&offer, &keypair).await;
    let debug = format!("{initiator:?} {responder:?}");

    assert!(!debug.contains("0123456789abcdef"));
    assert!(!debug.contains("30313233343536373839616263646566"));
    assert!(!debug.contains("guest-to-claw framed plaintext"));
    assert!(debug.contains("redacted"));
}

#[tokio::test]
async fn relay_contract_noise_async_stream_bidirectional_async_read_write() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&keypair);
    let (mut initiator, mut responder) = async_stream_pair(&offer, &keypair).await;

    let to_responder = b"guest-to-claw async stream plaintext";
    let to_initiator = b"claw-to-guest async stream plaintext";
    let initiator_task = async {
        initiator.write_all(to_responder).await?;
        initiator.flush().await?;
        let mut reply = vec![0u8; to_initiator.len()];
        initiator.read_exact(&mut reply).await?;
        Ok::<_, io::Error>(reply)
    };
    let responder_task = async {
        let mut request = vec![0u8; to_responder.len()];
        responder.read_exact(&mut request).await?;
        responder.write_all(to_initiator).await?;
        responder.flush().await?;
        Ok::<_, io::Error>(request)
    };

    let (reply, request) = tokio::try_join!(initiator_task, responder_task).unwrap();
    assert_eq!(request, to_responder);
    assert_eq!(reply, to_initiator);
}

#[tokio::test]
async fn relay_contract_noise_async_stream_hides_record_boundaries() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&keypair);
    let (mut initiator, mut responder) = async_stream_pair(&offer, &keypair).await;
    let large = (0..(RELAY_STREAM_NOISE_MAX_PLAINTEXT_RECORD_LEN + 777))
        .map(|idx| u8::try_from(idx % 251).unwrap())
        .collect::<Vec<_>>();
    let mut expected = b"a".to_vec();
    expected.extend_from_slice(b"bc");
    expected.extend_from_slice(&large);
    let expected_for_reader = expected.clone();

    let writer = async move {
        initiator.write_all(b"a").await?;
        initiator.write_all(b"bc").await?;
        initiator.write_all(&large).await?;
        initiator.flush().await
    };
    let reader = async move {
        let mut received = vec![0u8; expected_for_reader.len()];
        responder.read_exact(&mut received).await?;
        Ok::<_, io::Error>(received)
    };

    let ((), received) = tokio::try_join!(writer, reader).unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn relay_contract_noise_async_stream_partial_reads_work() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&keypair);
    let (mut initiator, mut responder) = async_stream_pair(&offer, &keypair).await;
    let plaintext = b"partial reads see a continuous stream";

    let writer = async {
        initiator.write_all(plaintext).await?;
        initiator.flush().await
    };
    let reader = async {
        let mut received = Vec::with_capacity(plaintext.len());
        for _ in 0..plaintext.len() {
            let mut one = [0u8; 1];
            responder.read_exact(&mut one).await?;
            received.push(one[0]);
        }
        Ok::<_, io::Error>(received)
    };

    let ((), received) = tokio::try_join!(writer, reader).unwrap();
    assert_eq!(received, plaintext);
}

#[tokio::test]
async fn relay_contract_noise_async_stream_rejects_empty_plaintext_record() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&keypair);
    let (mut initiator, responder) = framed_pair(&offer, &keypair).await;
    let mut responder = responder.into_async_stream();

    initiator.write_frame_plaintext(&[]).await.unwrap();
    let mut one = [0u8; 1];
    let err = responder.read(&mut one).await.unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("plaintext record is empty"));
}

#[tokio::test]
async fn relay_contract_noise_async_stream_shutdown_eof_does_not_hang() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&keypair);
    let (mut initiator, mut responder) = async_stream_pair(&offer, &keypair).await;

    let writer = async {
        initiator.write_all(b"bye").await?;
        initiator.shutdown().await
    };
    let reader = async {
        let mut received = [0u8; 3];
        responder.read_exact(&mut received).await?;
        let mut extra = [0u8; 1];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            responder.read(&mut extra),
        )
        .await
        .expect("EOF read should not hang")?;
        Ok::<_, io::Error>((received, read))
    };

    let ((), (received, read)) = tokio::try_join!(writer, reader).unwrap();
    assert_eq!(&received, b"bye");
    assert_eq!(read, 0);
}

#[tokio::test]
async fn relay_contract_noise_async_stream_wrong_key_fails_before_adapter() {
    let expected_keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let wrong_keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer(&expected_keypair);
    let (initiator_io, responder_io) = duplex(4096);
    let owner = owner_pub();
    let guest = guest_pub();
    let prologue = responder_prologue(&offer);

    let result = tokio::try_join!(
        RelayStreamNoiseFramed::initiator_handshake(initiator_io, &offer, &owner, &guest, NOW,),
        RelayStreamNoiseFramed::responder_handshake_with_prologue(
            responder_io,
            &prologue,
            wrong_keypair.private_key(),
        )
    );

    assert!(matches!(result, Err(RelayStreamNoiseError::Snow(_))));
}

#[tokio::test]
async fn relay_contract_noise_async_stream_debug_does_not_leak_secret_material() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = signed_offer_with(&keypair, |payload| {
        payload.rendezvous_token = RendezvousToken::try_new(b"0123456789abcdef").unwrap();
    });
    let (mut initiator, mut responder) = async_stream_pair(&offer, &keypair).await;
    let secret_plaintext = b"async stream buffered plaintext secret";

    let writer = async {
        initiator.write_all(secret_plaintext).await?;
        initiator.flush().await
    };
    let reader = async {
        let mut one = [0u8; 1];
        responder.read_exact(&mut one).await?;
        Ok::<_, io::Error>(responder)
    };
    let ((), responder) = tokio::try_join!(writer, reader).unwrap();
    let debug = format!("{responder:?}");

    assert!(!debug.contains("0123456789abcdef"));
    assert!(!debug.contains("30313233343536373839616263646566"));
    assert!(!debug.contains("async stream buffered plaintext secret"));
    assert!(debug.contains("redacted"));
}
