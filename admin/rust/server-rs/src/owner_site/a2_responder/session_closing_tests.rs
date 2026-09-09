#![cfg(test)]

//! THE CLOSER RED (the test that closes S2): full M1→M2→M3 sessions.
//! Attack: proof signed over a device_static that is NOT the one the live
//! handshake learned — refused, and the challenge is NOT consumed (the
//! effect). Honest: proof over the real session transcript — accepted,
//! and the challenge is consumed exactly once (non-vacuity).

use super::*;
use crate::owner_site::authority::{
    OwnerSiteActionPopKey, OwnerSiteBindingDigest, OwnerSiteChannelAuthKey,
    OwnerSiteResolvedBinding,
};
use household_rs::keys::{IdentityKey, P256Keypair};

fn fixture() -> (
    OwnerSiteA2Responder,
    OwnerSitePreAuthIntent,
    OwnerSiteAuthorityObservation,
) {
    let responder = OwnerSiteA2Responder::new(
        vec![0x11; 64],
        "engine-test.v1".into(),
        Arc::new(P256Keypair::generate()),
    );
    let request = crate::owner_site::capability::OwnerSiteCanonicalRequest::new(
        crate::owner_site::capability::OwnerSiteRequestMethod::Get,
        "/api/v1/household/claws/claw-a/owner-site/ake",
        [7u8; 32],
    )
    .unwrap();
    let intent = OwnerSitePreAuthIntent::new(
        "hh-a",
        "owner-site-mesh",
        OwnerSiteResource::from_route_claw("claw-a").unwrap(),
        request,
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let observation = OwnerSiteAuthorityObservation::from_roster_adapter(
        "hh-a".to_string(),
        1,
        [7u8; 32],
        1,
        0,
        [3u8; 33],
        now,
        now + 86_400,
    )
    .unwrap();
    (responder, intent, observation)
}

fn resolved_binding() -> (P256Keypair, OwnerSiteResolvedBinding) {
    let device_key = P256Keypair::generate();
    let binding = OwnerSiteResolvedBinding::injected_for_harness(
        OwnerSiteBindingId::injected_for_harness([0x01; 32]).unwrap(),
        OwnerSiteBindingDigest::injected_for_harness([0x51; 32]).unwrap(),
        "npub1a",
        OwnerSiteChannelAuthKey::injected_for_harness("ch-a", device_key.public()).unwrap(),
        OwnerSiteActionPopKey::injected_for_harness("pop-a", device_key.public()).unwrap(),
    )
    .unwrap();
    (device_key, binding)
}

fn begin_honest_session(
    responder: &OwnerSiteA2Responder,
    intent: &OwnerSitePreAuthIntent,
    resource: &OwnerSiteResource,
    observation: &OwnerSiteAuthorityObservation,
) -> (snow::HandshakeState, [u8; 32], OwnerSiteA2ResponderSession) {
    let (client_hs, client_static) = a2_noise::new_noise_initiator().expect("initiator");
    let core = ClientHelloCore {
        domain: crate::owner_site::binding_glue::A2_DOMAIN.to_string(),
        version: A2_VERSION,
        household_id: "hh-a".into(),
        network_id: "owner-site-mesh".into(),
        route: "/api/v1/household/claws/claw-a/owner-site/ake".into(),
        resource: "claw-a".into(),
        intent: crate::owner_site::a2_wire::CanonicalIntent {
            method: "GET".into(),
            target: "/api/v1/household/claws/claw-a/owner-site/ake".into(),
            body_hash: vec![7u8; 32],
        },
        claimed_binding_id: vec![0x01; 32],
    };
    let payload = encode_canonical(&core).unwrap();
    let mut client_hs = client_hs;
    let mut m1_noise = vec![0u8; MAX_A2_FRAME_BYTES];
    let m1_len = client_hs.write_message(&payload, &mut m1_noise).unwrap();
    m1_noise.truncate(m1_len);
    let m1_frame = encode_canonical(&AkeFrame {
        version: A2_VERSION,
        kind: AkeMessageKind::M1 as u8,
        noise: m1_noise,
    })
    .unwrap();
    let (session, m2_frame) = responder
        .begin_m1(intent, resource, observation, &m1_frame)
        .expect("honest begin_m1 must succeed");
    let m2: AkeFrame = decode_canonical(&m2_frame).unwrap();
    let mut m2_plain = vec![0u8; MAX_A2_FRAME_BYTES];
    let _ = client_hs.read_message(&m2.noise, &mut m2_plain).unwrap();
    (client_hs, client_static, session)
}

fn m3_frame_for(
    client_hs: &mut snow::HandshakeState,
    session: &OwnerSiteA2ResponderSession,
    binding: &OwnerSiteResolvedBinding,
    device_key: &P256Keypair,
    t1: [u8; 32],
    device_static: [u8; 32],
) -> Vec<u8> {
    let pre = crate::owner_site::binding_glue::pop_binding_pre(t1, device_static).unwrap();
    let d_auth = crate::owner_site::binding_glue::device_auth_hash(
        &pre,
        &binding.binding_id(),
        &binding.binding_digest(),
        binding.participant_npub(),
        binding.channel_auth_key().key_id(),
    )
    .unwrap();
    let intent_wire = encode_canonical(&session.c1.core.intent).unwrap();
    let action = crate::owner_site::binding_glue::owner_action_hash(
        &pre,
        &session.m2,
        &session.c1.core,
        &binding.binding_id(),
        &binding.binding_digest(),
        binding.participant_npub(),
        &intent_wire,
    )
    .unwrap();
    let proof = crate::owner_site::a2_wire::ClientProof {
        binding_id: binding.binding_id().as_bytes().to_vec(),
        binding_digest: binding.binding_digest().as_bytes().to_vec(),
        participant_npub: binding.participant_npub().to_string(),
        channel_auth_key_id: binding.channel_auth_key().key_id().as_str().to_string(),
        action_pop_key_id: binding.action_pop_key().key_id().as_str().to_string(),
        device_signature: device_key
            .sign(d_auth.as_bytes())
            .unwrap()
            .as_bytes()
            .to_vec(),
        action_pop: device_key
            .sign(action.as_bytes())
            .unwrap()
            .as_bytes()
            .to_vec(),
    };
    let proof_payload = encode_canonical(&proof).unwrap();
    let mut m3_noise = vec![0u8; MAX_A2_FRAME_BYTES];
    let m3_len = client_hs
        .write_message(&proof_payload, &mut m3_noise)
        .unwrap();
    m3_noise.truncate(m3_len);
    encode_canonical(&AkeFrame {
        version: A2_VERSION,
        kind: AkeMessageKind::M3 as u8,
        noise: m3_noise,
    })
    .unwrap()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn m3_signed_over_a_foreign_device_static_is_refused_and_the_challenge_survives() {
    let (responder, intent, observation) = fixture();
    let resource = OwnerSiteResource::from_route_claw("claw-a").unwrap();
    let (mut client_hs, client_static, mut session) =
        begin_honest_session(&responder, &intent, &resource, &observation);
    // ONE key — the same pair the binding holds. The ONLY thing wrong
    // is the device_static the proof is signed over.
    let (device_key, binding) = resolved_binding();
    let foreign_static = [0xEE; 32];
    // PRECONDITION: the foreign static really IS foreign to this session.
    assert_ne!(
        client_static, foreign_static,
        "precondition: the foreign static must differ from the live session's"
    );
    let m3_frame = m3_frame_for(
        &mut client_hs,
        &session,
        &binding,
        &device_key,
        session.t1,
        foreign_static,
    );

    let intent_for_claim = crate::owner_site::capability::OwnerSiteIntent::from_pre_auth(
        intent.clone(),
        "member-a".to_string(),
    );
    let outstanding_before = responder.challenges.outstanding(now_secs()).unwrap();
    assert_eq!(
        outstanding_before, 1,
        "precondition: exactly one challenge outstanding before accept_m3"
    );
    let result = session.accept_m3(
        &responder.challenges,
        &binding,
        &intent_for_claim,
        &m3_frame,
    );
    assert!(
        result.is_err(),
        "a proof over a foreign device_static must be refused"
    );
    let outstanding_after = responder.challenges.outstanding(now_secs()).unwrap();
    assert_eq!(
        outstanding_before, outstanding_after,
        "THE EFFECT: the one-shot challenge must NOT be consumed by a refused proof"
    );
}

#[test]
fn m3_signed_over_the_real_session_transcript_is_accepted_and_consumes() {
    let (responder, intent, observation) = fixture();
    let resource = OwnerSiteResource::from_route_claw("claw-a").unwrap();
    let (mut client_hs, client_static, mut session) =
        begin_honest_session(&responder, &intent, &resource, &observation);
    let (device_key, binding) = resolved_binding();
    let m3_frame = m3_frame_for(
        &mut client_hs,
        &session,
        &binding,
        &device_key,
        session.t1,
        client_static, // the REAL static the handshake learned
    );

    let intent_for_claim = crate::owner_site::capability::OwnerSiteIntent::from_pre_auth(
        intent.clone(),
        "member-a".to_string(),
    );
    let outstanding_before = responder.challenges.outstanding(now_secs()).unwrap();
    assert_eq!(
        outstanding_before, 1,
        "precondition: exactly one challenge outstanding before accept_m3"
    );
    session
        .accept_m3(
            &responder.challenges,
            &binding,
            &intent_for_claim,
            &m3_frame,
        )
        .expect("the honest proof must be accepted");
    let outstanding_after = responder.challenges.outstanding(now_secs()).unwrap();
    assert_eq!(
        outstanding_before - 1,
        outstanding_after,
        "THE EFFECT: the one-shot challenge is consumed exactly once"
    );
}

/// TYPED-API OPACITY: two failures with DIFFERENT causes that reach
/// DIFFERENT code paths in `accept_m3` must return the SAME opaque type
/// `OwnerSiteA2Rejection` and the SAME public `Debug` form — the caller
/// cannot discriminate which check failed from the return value alone.
///
/// WIRE-LEVEL OPACITY (same CBOR bytes on the WebSocket for every cause)
/// is PENDING the WS handler wiring — it does not exist yet and is not
/// claimed here. When the handler lands, a wire-level test must be added.
///
/// Cause A (proof_verify path): proof signed over a foreign device_static.
/// Cause B (challenge_claim path): valid proof, but the challenge was
/// already purged from the table.
#[test]
fn two_distinct_causes_return_the_same_opaque_rejection_and_debug_form() {
    let (responder, intent, observation) = fixture();
    let resource = OwnerSiteResource::from_route_claw("claw-a").unwrap();
    let intent_for_claim = crate::owner_site::capability::OwnerSiteIntent::from_pre_auth(
        intent.clone(),
        "member-a".to_string(),
    );

    // ── Cause A: proof_verify path (foreign device_static) ──────────
    let (mut client_hs_a, _client_static_a, mut session_a) =
        begin_honest_session(&responder, &intent, &resource, &observation);
    let (device_key_a, binding_a) = resolved_binding();
    let frame_a = m3_frame_for(
        &mut client_hs_a,
        &session_a,
        &binding_a,
        &device_key_a,
        session_a.t1,
        [0xEE; 32], // foreign static
    );
    let err_a = session_a
        .accept_m3(
            &responder.challenges,
            &binding_a,
            &intent_for_claim,
            &frame_a,
        )
        .expect_err("cause A must reject");

    // ── Cause B: challenge_claim path (valid proof, challenge purged) ─
    let (mut client_hs_b, client_static_b, mut session_b) =
        begin_honest_session(&responder, &intent, &resource, &observation);
    let (device_key_b, binding_b) = resolved_binding();
    let frame_b = m3_frame_for(
        &mut client_hs_b,
        &session_b,
        &binding_b,
        &device_key_b,
        session_b.t1,
        client_static_b, // the REAL static — proof is valid
    );
    let future = now_secs() + 120;
    let _ = responder.challenges.outstanding(future).unwrap();
    let err_b = session_b
        .accept_m3(
            &responder.challenges,
            &binding_b,
            &intent_for_claim,
            &frame_b,
        )
        .expect_err("cause B must reject");

    // ── Both return the same opaque type and identical Debug ────────
    assert_eq!(
        err_a, err_b,
        "two different causes must produce the same opaque rejection value"
    );
    assert_eq!(
        format!("{err_a:?}"),
        format!("{err_b:?}"),
        "the Debug form must not name the cause"
    );
    assert_eq!(format!("{err_a:?}"), "OwnerSiteA2Rejection");
}
