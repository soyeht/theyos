use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::pair_device::PairNonce;
use household_rs::pop::{PairingProofContext, RequestSigningContext};
use household_rs::{P256Signature, derive_household_id};

#[test]
fn pairing_proof_context_canonical_bytes_verify() {
    let hh_key = P256Keypair::generate();
    let person_key = P256Keypair::generate();
    let nonce = PairNonce::random();
    let ctx = PairingProofContext::new(
        derive_household_id(&hh_key.public()),
        nonce.0,
        person_key.public(),
    );

    let canonical = ctx.canonical_bytes().unwrap();
    let sig = person_key.sign(&canonical).unwrap();
    ctx.verify(&sig).unwrap();

    let other_sig = P256Keypair::generate().sign(&canonical).unwrap();
    ctx.verify(&other_sig).unwrap_err();
}

#[test]
fn request_signing_context_binds_method_path_timestamp_and_body() {
    let key = P256Keypair::generate();
    let ctx = RequestSigningContext::new("get", "/api/v1/household/snapshot?x=y", 123, b"body");
    let sig = key.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    ctx.verify(&key.public(), &sig).unwrap();

    let changed_body =
        RequestSigningContext::new("GET", "/api/v1/household/snapshot?x=y", 123, b"other");
    changed_body.verify(&key.public(), &sig).unwrap_err();

    let changed_path =
        RequestSigningContext::new("GET", "/api/v1/household/snapshot?z=y", 123, b"body");
    changed_path.verify(&key.public(), &sig).unwrap_err();
}

#[test]
fn malformed_signature_is_rejected() {
    let key = P256Keypair::generate();
    let ctx = RequestSigningContext::new("GET", "/api/v1/household/snapshot", 123, b"");
    let sig = P256Signature::from_bytes(&[1_u8; 63]);
    assert!(sig.is_err());
    let sig = key.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    let mut tampered = sig.clone();
    tampered.0[0] ^= 1;
    ctx.verify(&key.public(), &tampered).unwrap_err();
}
