use household_rs::keys::verify_signature;
use household_rs::{IdentityKey, P256Keypair, P256PublicKey, P256Signature};

#[test]
fn keypair_signs_and_verifies() {
    let kp = P256Keypair::generate();
    let msg = b"hello household";
    let sig = kp.sign(msg).expect("sign");
    verify_signature(&kp.public(), msg, &sig).expect("verify");
}

#[test]
fn tamper_breaks_verify() {
    let kp = P256Keypair::generate();
    let msg = b"hello household";
    let mut sig = kp.sign(msg).expect("sign");
    sig.0[0] ^= 0x01;
    verify_signature(&kp.public(), msg, &sig).expect_err("must fail");
}

#[test]
fn from_bytes_rejects_der_encoded_signature() {
    // FR-013 mandates raw 64-byte `r || s`. A DER blob (SEQUENCE 0x30 + len)
    // is typically 70-72 bytes for P-256 and must be rejected on length alone.
    let der: [u8; 71] = {
        let mut buf = [0u8; 71];
        buf[0] = 0x30;
        buf[1] = 69;
        buf
    };
    assert!(P256Signature::from_bytes(&der).is_err());
}

#[test]
fn pubkey_round_trip() {
    let kp = P256Keypair::generate();
    let pk = kp.public();
    let pk2 = P256PublicKey::from_bytes(pk.as_bytes()).expect("round trip");
    assert_eq!(pk.as_bytes(), pk2.as_bytes());
}

#[test]
fn pubkey_rejects_bad_length() {
    assert!(P256PublicKey::from_bytes(&[0x02; 10]).is_err());
    assert!(P256PublicKey::from_bytes(&[0u8; 33]).is_err());
    assert!(P256PublicKey::from_bytes(&[0x04; 33]).is_err());
    assert!(P256PublicKey::from_bytes(&[0xff; 33]).is_err());
}

#[test]
fn signature_round_trip() {
    let kp = P256Keypair::generate();
    let sig = kp.sign(b"x").unwrap();
    let bytes = *sig.as_bytes();
    let sig2 = P256Signature::from_bytes(&bytes).unwrap();
    assert_eq!(sig.as_bytes(), sig2.as_bytes());
}

#[test]
fn from_secret_scalar_roundtrip() {
    let kp = P256Keypair::generate();
    let scalar = *kp.as_software_secret().expect("software-backed scalar");
    let kp2 = P256Keypair::from_secret_scalar(&scalar).unwrap();
    assert_eq!(kp.public().as_bytes(), kp2.public().as_bytes());
}
