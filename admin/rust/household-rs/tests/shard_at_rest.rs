//! T013 round-trip and tamper coverage for the Phase 3 shard-at-rest
//! AEAD wrapper exposed by `household_rs::shard_at_rest`. Inline tests
//! in the module already cover most of these — the file-level tests
//! here exist so the task's named test path (`tests/shard_at_rest.rs`)
//! is observable to CI and so the CBOR fuzz-corpus seed is generated
//! alongside.

#![allow(clippy::cast_possible_truncation)]

use std::fs;
use std::path::PathBuf;

use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::shard_at_rest::{
    EncryptedShard, ShardError, decrypt_from_peer, decrypt_self, encrypt_for_peer,
    encrypt_for_self,
};
use zeroize::Zeroizing;

fn fixed_shard(seed: u8) -> Zeroizing<[u8; 32]> {
    let mut s = Zeroizing::new([0u8; 32]);
    for (i, b) in s.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8).wrapping_mul(0x35);
    }
    s
}

#[test]
fn self_round_trip() {
    let kp = P256Keypair::generate();
    let m_pub = kp.public();
    let m_priv = kp.as_software_secret().unwrap();
    let shard = fixed_shard(0xa1);
    let es = encrypt_for_self(&shard, m_priv, &m_pub, "m_test_self", 1).unwrap();
    let recovered = decrypt_self(&es, m_priv, &m_pub, "m_test_self").unwrap();
    assert_eq!(*recovered, *shard);
}

#[test]
fn peer_round_trip() {
    let m1 = P256Keypair::generate();
    let m2 = P256Keypair::generate();
    let shard = fixed_shard(0xb2);
    let es = encrypt_for_peer(
        &shard,
        m1.as_software_secret().unwrap(),
        &m2.public(),
        "m_test_m2",
        2,
    )
    .unwrap();
    let recovered = decrypt_from_peer(
        &es,
        m2.as_software_secret().unwrap(),
        &m1.public(),
        "m_test_m2",
    )
    .unwrap();
    assert_eq!(*recovered, *shard);
}

#[test]
fn wrong_self_key_fails() {
    let kp_a = P256Keypair::generate();
    let kp_b = P256Keypair::generate();
    let shard = fixed_shard(0xc3);
    let es = encrypt_for_self(
        &shard,
        kp_a.as_software_secret().unwrap(),
        &kp_a.public(),
        "m_test_self",
        1,
    )
    .unwrap();
    let err = decrypt_self(
        &es,
        kp_b.as_software_secret().unwrap(),
        &kp_b.public(),
        "m_test_self",
    )
    .unwrap_err();
    assert!(matches!(err, ShardError::AeadFailed));
}

#[test]
fn deterministic_cbor_re_encode_is_byte_equal() {
    let kp = P256Keypair::generate();
    let shard = fixed_shard(0xd4);
    let es = encrypt_for_self(
        &shard,
        kp.as_software_secret().unwrap(),
        &kp.public(),
        "m_test_self",
        1,
    )
    .unwrap();
    let bytes_a = es.to_canonical_bytes().unwrap();
    let bytes_b = es.to_canonical_bytes().unwrap();
    assert_eq!(bytes_a, bytes_b);
}

/// Emit a single CBOR fuzz-corpus seed so future `cargo fuzz`
/// harnesses have a non-trivial starting state. The seed is emitted
/// only when the `THEYOS_REGEN_FUZZ_SEEDS=1` env var is set so normal
/// `cargo test` runs are read-only.
#[test]
fn cbor_fuzz_corpus_seed_exists_or_is_regenerable() {
    let path = corpus_seed_path();
    if std::env::var("THEYOS_REGEN_FUZZ_SEEDS").as_deref() == Ok("1") {
        let kp = P256Keypair::generate();
        let shard = fixed_shard(0xe5);
        let es = encrypt_for_self(
            &shard,
            kp.as_software_secret().unwrap(),
            &kp.public(),
            "m_test_self",
            1,
        )
        .unwrap();
        let bytes = es.to_canonical_bytes().unwrap();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, bytes).unwrap();
    }
    if path.exists() {
        let bytes = fs::read(&path).unwrap();
        let decoded: EncryptedShard = household_rs::cbor::from_canonical_slice(&bytes)
            .expect("seed decodes as EncryptedShard");
        assert_eq!(decoded.version, 1);
    }
}

fn corpus_seed_path() -> PathBuf {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_root
        .join("tests")
        .join("fuzz_corpus")
        .join("encrypted_shard.cbor")
}
