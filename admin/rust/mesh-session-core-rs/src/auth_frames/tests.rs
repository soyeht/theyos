#![cfg(test)]

use super::*;
use crate::delegation::test_support::sample_delegation;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use rand_core::OsRng;
use std::time::{Duration, Instant};

fn far_future_deadline() -> CeremonyDeadline {
    CeremonyDeadline::for_test(Instant::now(), Duration::from_secs(3600))
}

struct TestKMesh(SigningKey);
impl MeshSessionFrameSigner for TestKMesh {
    fn sign_mesh_session_frame(
        &self,
        preimage: &MeshSessionFramePreimage,
        _deadline: &CeremonyDeadline,
    ) -> Result<[u8; 64], AuthFrameError> {
        let sig: Signature = self.0.sign(preimage.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().into())
    }
    fn public_key(&self) -> VerifyingKey {
        *self.0.verifying_key()
    }
    fn sign_intent(
        &self,
        preimage: &crate::intent::IntentSigningPreimage,
    ) -> Result<[u8; 64], AuthFrameError> {
        let sig: Signature = self.0.sign(preimage.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().into())
    }
}

/// Stands in for a buggy/malicious K_mesh that signs a DIFFERENT
/// message than the one it was asked for, but otherwise correctly
/// (low-S, matching its own key) — proves `sign_frame`'s new
/// mathematical self-check catches a wrong-preimage signature that
/// shape-and-low-S parsing alone would have let straight onto the
/// wire.
struct WrongMessageKMesh(SigningKey);
impl MeshSessionFrameSigner for WrongMessageKMesh {
    fn sign_mesh_session_frame(
        &self,
        _preimage: &MeshSessionFramePreimage,
        _deadline: &CeremonyDeadline,
    ) -> Result<[u8; 64], AuthFrameError> {
        let sig: Signature = self.0.sign(b"not the preimage sign_frame asked for");
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().into())
    }
    fn public_key(&self) -> VerifyingKey {
        *self.0.verifying_key()
    }
    fn sign_intent(
        &self,
        _preimage: &crate::intent::IntentSigningPreimage,
    ) -> Result<[u8; 64], AuthFrameError> {
        let sig: Signature = self
            .0
            .sign(b"not the preimage sign_intent_record asked for");
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().into())
    }
}

/// Stands in for a K_mesh that signs correctly but whose reported
/// `public_key()` does not match the key it actually signed with —
/// used to prove `sign_frame`'s self-check (and, separately,
/// `auth_state_machine`'s delegation binding check) catch a
/// key/signature mismatch rather than trusting either side alone.
struct MismatchedPublicKeyKMesh {
    signs_with: SigningKey,
    claims_to_be: SigningKey,
}
impl MeshSessionFrameSigner for MismatchedPublicKeyKMesh {
    fn sign_mesh_session_frame(
        &self,
        preimage: &MeshSessionFramePreimage,
        _deadline: &CeremonyDeadline,
    ) -> Result<[u8; 64], AuthFrameError> {
        let sig: Signature = self.signs_with.sign(preimage.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().into())
    }
    fn public_key(&self) -> VerifyingKey {
        *self.claims_to_be.verifying_key()
    }
    fn sign_intent(
        &self,
        preimage: &crate::intent::IntentSigningPreimage,
    ) -> Result<[u8; 64], AuthFrameError> {
        let sig: Signature = self.signs_with.sign(preimage.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().into())
    }
}

/// Stands in for a real K_mesh whose backend refuses to sign — e.g.
/// revoked, stale epoch, expired delegation. `sign_frame` must
/// propagate this, never fabricate a signature.
struct AlwaysFailingKMesh(SigningKey);
impl MeshSessionFrameSigner for AlwaysFailingKMesh {
    fn sign_mesh_session_frame(
        &self,
        _preimage: &MeshSessionFramePreimage,
        _deadline: &CeremonyDeadline,
    ) -> Result<[u8; 64], AuthFrameError> {
        Err(AuthFrameError::SignerFailed)
    }
    fn public_key(&self) -> VerifyingKey {
        *self.0.verifying_key()
    }
    fn sign_intent(
        &self,
        _preimage: &crate::intent::IntentSigningPreimage,
    ) -> Result<[u8; 64], AuthFrameError> {
        Err(AuthFrameError::SignerFailed)
    }
}

/// Stands in for a buggy/non-compliant K_mesh that returns a high-S
/// signature — `sign_frame` must catch this itself, not rely on the
/// receiving peer's inbound check. RFC6979 signing is deterministic
/// per (key, message), so probe a small salt range for a message that
/// happens to sign high-S (roughly half do) rather than trying to
/// construct one directly — the `ecdsa` crate exposes no public
/// "denormalize" operation.
struct AlwaysHighSKMesh(SigningKey);
impl MeshSessionFrameSigner for AlwaysHighSKMesh {
    fn sign_mesh_session_frame(
        &self,
        preimage: &MeshSessionFramePreimage,
        _deadline: &CeremonyDeadline,
    ) -> Result<[u8; 64], AuthFrameError> {
        for salt in 0u8..255 {
            let mut salted = preimage.as_bytes().to_vec();
            salted.push(salt);
            let sig: Signature = self.0.sign(&salted);
            if sig.normalize_s().is_some() {
                return Ok(sig.to_bytes().into());
            }
        }
        panic!("expected at least one high-S signature among 255 probes");
    }
    fn public_key(&self) -> VerifyingKey {
        *self.0.verifying_key()
    }
    fn sign_intent(
        &self,
        preimage: &crate::intent::IntentSigningPreimage,
    ) -> Result<[u8; 64], AuthFrameError> {
        for salt in 0u8..255 {
            let mut salted = preimage.as_bytes().to_vec();
            salted.push(salt);
            let sig: Signature = self.0.sign(&salted);
            if sig.normalize_s().is_some() {
                return Ok(sig.to_bytes().into());
            }
        }
        panic!("expected at least one high-S signature among 255 probes");
    }
}

fn sample_proof_r() -> ProofR {
    ProofR::new(
        vec![0u8; 32],
        "hh-1".to_string(),
        "responder-1".to_string(),
        vec![0xCC; 32],
        vec![0xDD; 32],
        1,
        vec![0xEE; 32],
        1_000_000,
        sample_delegation(100, 200),
        vec![0u8; 64],
    )
    .unwrap()
}

#[test]
fn auth_frame_round_trip_through_wire_encode_decode() {
    let frame = AuthFrame::ProofR(sample_proof_r());
    let bytes = encode_auth_frame(&frame).unwrap();
    assert_eq!(bytes[0], TYPE_PROOF_R);
    let decoded = decode_auth_frame(&bytes).unwrap();
    assert_eq!(decoded, frame);
}

#[test]
fn red_unknown_type_byte_rejected() {
    let mut bytes = encode_auth_frame(&AuthFrame::ProofR(sample_proof_r())).unwrap();
    bytes[0] = 0x99;
    assert!(matches!(
        decode_auth_frame(&bytes),
        Err(AuthFrameError::Wire(
            crate::error::WireError::UnknownTypeByte(0x99)
        ))
    ));
}

#[test]
fn red_wrong_role_for_proof_r_rejected_at_construction() {
    let bad = ProofRWire {
        protocol_version: PROTOCOL_VERSION,
        domain: DOMAIN.to_string(),
        role: ROLE_INITIATOR.to_string(), // wrong — ProofR must be "responder"
        h_final: vec![0u8; 32],
        hh_id: "hh-1".to_string(),
        self_m_id: "x".to_string(),
        self_cert_fingerprint: vec![0xCC; 32],
        checkpoint_hash: vec![0xDD; 32],
        checkpoint_sequence: 1,
        checkpoint_event_head: vec![0xEE; 32],
        checkpoint_not_after: 1,
        delegation: sample_delegation(100, 200),
        sig: vec![0u8; 64],
    };
    assert!(matches!(
        ProofR::try_from(bad),
        Err(AuthFrameError::RoleOrKindMismatch)
    ));
}

#[test]
fn red_wrong_h_final_length_rejected_at_construction() {
    let bad = ProofRWire {
        protocol_version: PROTOCOL_VERSION,
        domain: DOMAIN.to_string(),
        role: ROLE_RESPONDER.to_string(),
        h_final: vec![0u8; 31], // one byte short
        hh_id: "hh-1".to_string(),
        self_m_id: "x".to_string(),
        self_cert_fingerprint: vec![0xCC; 32],
        checkpoint_hash: vec![0xDD; 32],
        checkpoint_sequence: 1,
        checkpoint_event_head: vec![0xEE; 32],
        checkpoint_not_after: 1,
        delegation: sample_delegation(100, 200),
        sig: vec![0u8; 64],
    };
    assert!(matches!(
        ProofR::try_from(bad),
        Err(AuthFrameError::ShapeMismatch)
    ));
}

#[test]
fn red_wrong_domain_literal_rejected_at_construction() {
    let bad = ProofRWire {
        protocol_version: PROTOCOL_VERSION,
        domain: "soyeht/mesh-connection-intent/v1".to_string(),
        role: ROLE_RESPONDER.to_string(),
        h_final: vec![0u8; 32],
        hh_id: "hh-1".to_string(),
        self_m_id: "x".to_string(),
        self_cert_fingerprint: vec![0xCC; 32],
        checkpoint_hash: vec![0xDD; 32],
        checkpoint_sequence: 1,
        checkpoint_event_head: vec![0xEE; 32],
        checkpoint_not_after: 1,
        delegation: sample_delegation(100, 200),
        sig: vec![0u8; 64],
    };
    assert!(matches!(
        ProofR::try_from(bad),
        Err(AuthFrameError::VersionOrDomainMismatch)
    ));
}

#[test]
fn embedding_still_validates_after_decode_not_just_at_construction() {
    // Regression for the audit finding: fields used to be pub with no
    // post-decode validation. Hand-build wire bytes with a bad role
    // (bypassing ProofR::new's own validation entirely) and confirm
    // the closed decode entrypoint still rejects them.
    let w = ProofRWire {
        protocol_version: PROTOCOL_VERSION,
        domain: DOMAIN.to_string(),
        role: "not-a-real-role".to_string(),
        h_final: vec![0u8; 32],
        hh_id: "hh-1".to_string(),
        self_m_id: "x".to_string(),
        self_cert_fingerprint: vec![0xCC; 32],
        checkpoint_hash: vec![0xDD; 32],
        checkpoint_sequence: 1,
        checkpoint_event_head: vec![0xEE; 32],
        checkpoint_not_after: 1,
        delegation: sample_delegation(100, 200),
        sig: vec![0u8; 64],
    };
    let body_cbor = cbor::to_canonical_vec(&w).unwrap();
    let frame_bytes = crate::wire::encode_typed_frame(TYPE_PROOF_R, &body_cbor).unwrap();
    assert!(decode_auth_frame(&frame_bytes).is_err());
}

#[test]
fn red_wrong_frame_type_for_the_type_byte_rejected() {
    // A ProofI-shaped body framed under ProofR's type byte — the field
    // sets differ (ProofI has expected_peer_m_id etc.), so
    // deny_unknown_fields on ProofR must reject it.
    let proof_i = ProofI::new(
        vec![0u8; 32],
        "hh-1".to_string(),
        "initiator-1".to_string(),
        "responder-1".to_string(),
        vec![0xAA; 32],
        vec![0xCC; 32],
        vec![0xDD; 32],
        1,
        vec![0xEE; 32],
        1_000_000,
        sample_delegation(100, 200),
        ConnectionIntentDigest::from_bytes([0x11; 32]),
        vec![0u8; 64],
    )
    .unwrap();
    let body_cbor = cbor::to_canonical_vec(&proof_i).unwrap();
    let frame_bytes = crate::wire::encode_typed_frame(TYPE_PROOF_R, &body_cbor).unwrap();
    assert!(decode_auth_frame(&frame_bytes).is_err());
}

#[test]
fn connection_intent_digest_round_trips_and_rejects_wrong_length() {
    let digest = ConnectionIntentDigest::from_bytes([0x42; 32]);
    let bytes = cbor::to_canonical_vec(&digest).unwrap();
    let back: ConnectionIntentDigest = cbor::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(digest, back);

    let short = serde_bytes::ByteBuf::from(vec![0u8; 31]);
    let short_bytes = cbor::to_canonical_vec(&short).unwrap();
    assert!(cbor::from_canonical_bytes::<ConnectionIntentDigest>(&short_bytes).is_err());
}

#[test]
fn red_missing_connection_intent_digest_rejected_by_deny_unknown_fields_shape() {
    use ciborium::Value;
    let raw = Value::Map(vec![
        (
            Value::Text("protocol_version".into()),
            Value::Integer(1.into()),
        ),
        (Value::Text("domain".into()), Value::Text(DOMAIN.into())),
        (
            Value::Text("role".into()),
            Value::Text(ROLE_INITIATOR.into()),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&raw, &mut bytes).unwrap();
    assert!(cbor::from_canonical_bytes::<ProofI>(&bytes).is_err());
}

#[test]
fn signed_preimage_excludes_sig_frame_digest_includes_it() {
    let frame = sample_proof_r();
    let preimage = MeshSessionFramePreimage::for_frame(&frame).unwrap();
    assert_eq!(preimage.as_bytes()[0], TYPE_PROOF_R);
    assert!(!crate::cbor::map_has_top_level_key(&preimage.as_bytes()[1..], "sig").unwrap());

    let digest_a = frame_digest(&frame).unwrap();
    let tampered = frame.clone().with_sig(vec![0xFFu8; 64]);
    let digest_b = frame_digest(&tampered).unwrap();
    assert_ne!(
        digest_a, digest_b,
        "frame_digest must include sig — two different sigs must digest differently"
    );
}

#[test]
fn sign_then_verify_round_trip_with_a_real_p256_pair() {
    let signing_key = SigningKey::random(&mut OsRng);
    let k_mesh = TestKMesh(signing_key.clone());
    let verifier = RawP256FrameVerifier(VerifyingKey::from(&signing_key));

    let frame = sample_proof_r();
    let signed = sign_frame(frame, &k_mesh, &far_future_deadline()).unwrap();
    let sig: [u8; 64] = signed.sig().to_vec().try_into().unwrap();
    verify_frame(&signed, &sig, &verifier).unwrap();
}

/// Reads `deadline` itself and fails if already expired — proves the
/// SAME token `sign_frame` receives genuinely reaches a real signer's
/// own check (2026-08-04, @kiana, WIP audit, E3 seam: "todo hook
/// potencialmente I/O deve receber o mesmo token"), the signing-side
/// counterpart of `DeadlineAwareVerifier` in
/// `auth_state_machine::tests`.
struct DeadlineAwareSigner(SigningKey);
impl MeshSessionFrameSigner for DeadlineAwareSigner {
    fn sign_mesh_session_frame(
        &self,
        preimage: &MeshSessionFramePreimage,
        deadline: &CeremonyDeadline,
    ) -> Result<[u8; 64], AuthFrameError> {
        if deadline.is_expired() {
            return Err(AuthFrameError::SignerFailed);
        }
        let sig: Signature = self.0.sign(preimage.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().into())
    }
    fn public_key(&self) -> VerifyingKey {
        *self.0.verifying_key()
    }
    fn sign_intent(
        &self,
        preimage: &crate::intent::IntentSigningPreimage,
    ) -> Result<[u8; 64], AuthFrameError> {
        let sig: Signature = self.0.sign(preimage.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().into())
    }
}

#[test]
fn red_sign_frame_propagates_the_official_ceremony_deadline_to_the_signer() {
    let k_mesh = DeadlineAwareSigner(SigningKey::random(&mut OsRng));
    let expired = CeremonyDeadline::already_expired_for_test();
    let err = sign_frame(sample_proof_r(), &k_mesh, &expired).unwrap_err();
    assert!(matches!(err, AuthFrameError::SignerFailed));
}

#[test]
fn red_signer_failure_propagates_never_fabricates_a_signature() {
    let k_mesh = AlwaysFailingKMesh(SigningKey::random(&mut OsRng));
    let err = sign_frame(sample_proof_r(), &k_mesh, &far_future_deadline()).unwrap_err();
    assert!(matches!(err, AuthFrameError::SignerFailed));
}

#[test]
fn red_signer_returning_high_s_is_caught_before_the_wire() {
    let signing_key = SigningKey::random(&mut OsRng);
    let k_mesh = AlwaysHighSKMesh(signing_key);
    let err = sign_frame(sample_proof_r(), &k_mesh, &far_future_deadline()).unwrap_err();
    assert!(matches!(err, AuthFrameError::HighSRejected));
}

#[test]
fn red_signer_returning_a_valid_low_s_signature_for_a_different_message_is_rejected() {
    // The core finding this closes: shape-and-low-S parsing alone
    // does not prove the signature is OVER THIS PREIMAGE. A signer
    // that returns a perfectly well-formed, low-S, key-consistent
    // signature — just over the wrong message — must still be caught
    // locally, before the frame is ever written.
    let k_mesh = WrongMessageKMesh(SigningKey::random(&mut OsRng));
    let err = sign_frame(sample_proof_r(), &k_mesh, &far_future_deadline()).unwrap_err();
    assert!(matches!(
        err,
        AuthFrameError::SignerProducedInvalidSignature
    ));
}

#[test]
fn red_signer_public_key_not_matching_its_own_signing_key_is_rejected() {
    // A signer whose sign_mesh_session_frame and public_key report
    // two DIFFERENT keys — the signature is real and over the right
    // preimage, but does not verify against what the signer itself
    // claims to be. Must fail the same way as a wrong-message
    // signature: locally, before any write.
    let k_mesh = MismatchedPublicKeyKMesh {
        signs_with: SigningKey::random(&mut OsRng),
        claims_to_be: SigningKey::random(&mut OsRng),
    };
    let err = sign_frame(sample_proof_r(), &k_mesh, &far_future_deadline()).unwrap_err();
    assert!(matches!(
        err,
        AuthFrameError::SignerProducedInvalidSignature
    ));
}

#[test]
fn tampered_frame_fails_verification() {
    let signing_key = SigningKey::random(&mut OsRng);
    let k_mesh = TestKMesh(signing_key.clone());
    let verifier = RawP256FrameVerifier(VerifyingKey::from(&signing_key));

    let frame = sample_proof_r();
    let signed = sign_frame(frame, &k_mesh, &far_future_deadline()).unwrap();
    let sig: [u8; 64] = signed.sig().to_vec().try_into().unwrap();

    let tampered = ProofR::new(
        signed.h_final().to_vec(),
        signed.hh_id().to_string(),
        "attacker".to_string(),
        signed.self_cert_fingerprint().to_vec(),
        signed.checkpoint_hash().to_vec(),
        1,
        vec![0xEE; 32],
        1_000_000,
        sample_delegation(100, 200),
        signed.sig().to_vec(),
    )
    .unwrap();
    assert!(verify_frame(&tampered, &sig, &verifier).is_err());
}

#[test]
fn red_high_s_signature_rejected_low_s_accepted() {
    // RFC6979 signing is deterministic per (key, message), so a fixed
    // preimage always yields the same s. Vary the frame across a
    // small probe set to find at least one naturally-high-S signature
    // (P-256 ECDSA signatures land high-S roughly half the time before
    // normalization) — this is deterministic given a fixed key and a
    // fixed sequence of probe frames, not flaky.
    let signing_key = SigningKey::random(&mut OsRng);
    let verifier = RawP256FrameVerifier(VerifyingKey::from(&signing_key));

    let mut found_high_s = false;
    let mut found_low_s = false;
    for i in 0u64..64 {
        let probe = ProofR::new(
            vec![0u8; 32],
            "hh-1".to_string(),
            "responder-1".to_string(),
            vec![0xCC; 32],
            vec![0xDD; 32],
            i,
            vec![0xEE; 32],
            1_000_000,
            sample_delegation(100, 200),
            vec![0u8; 64],
        )
        .unwrap();
        let preimage = MeshSessionFramePreimage::for_frame(&probe).unwrap();
        let sig: Signature = signing_key.sign(preimage.as_bytes());
        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        if sig.normalize_s().is_some() {
            assert!(matches!(
                verifier.verify_mesh_session_frame(&preimage, &sig_bytes),
                Err(AuthFrameError::HighSRejected)
            ));
            found_high_s = true;
        } else {
            verifier
                .verify_mesh_session_frame(&preimage, &sig_bytes)
                .unwrap();
            found_low_s = true;
        }
        if found_high_s && found_low_s {
            break;
        }
    }
    assert!(
        found_high_s,
        "expected at least one high-S signature among 64 probes"
    );
    assert!(
        found_low_s,
        "expected at least one low-S signature among 64 probes"
    );
}
