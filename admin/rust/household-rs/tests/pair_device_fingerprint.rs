//! Pair-device code determinism vectors — the six BIP-39 words the Mac
//! shows next to its pairing QR and the iPhone types back into
//! `POST /bootstrap/pair-device-uri/by-code`.
//!
//! 16 fixed `(hh_pub_sec1, nonce)` pairs → 16 expected index sextets and
//! word sextets. The code is the first 66 bits of
//! `BLAKE3-256(hh_pub_sec1 ‖ nonce)` read MSB-first as 6 × 11-bit indices
//! into the pinned BIP-39 English wordlist. Any deviation in the
//! derivation (hash input order, bit extraction, wordlist, lookup) MUST
//! surface as a test failure here.
//!
//! Cross-repo sync: the canonical vectors file lives at
//! `admin/rust/household-rs/tests/data/pair_device_fingerprint_vectors.json`.
//! The iSoyehtTerm Swift test target derives the same pairs through
//! `OperatorFingerprint.derive(machinePublicKey:pairingNonce:wordlist:)`
//! and asserts byte-equal output, in
//! `Packages/SoyehtCore/Tests/SoyehtCoreTests/PairDeviceFingerprintVectorsTests.swift`.
//! That sentence was aspirational when this file was written — no Swift
//! test read these vectors, so the contract was locked on one side only.
//! It is named here so the claim stays checkable. Each entry exposes BOTH the `indices`
//! array and the `words` array so each side of the cross-repo gate can
//! pick the shape that matches its existing assertion conventions
//! without re-deriving anything.
//!
//! The vectors are produced by the Rust code under test, never typed by
//! hand — regenerate with
//! `cargo test -p household-rs --test pair_device_fingerprint -- --ignored regenerate_pair_device_fingerprint_vectors_json`.

#![allow(clippy::cast_possible_truncation)]

use household_rs::bip39_wordlist::WORDLIST;
use household_rs::fingerprint::{
    pair_device_fingerprint_indices, pair_device_fingerprint_words, word_index,
};
use household_rs::keys::{IdentityKey, P256Keypair};
use std::fs;
use std::path::Path;

const VECTOR_COUNT: u64 = 16;

/// 32 deterministic bytes from a small `SplitMix64` so test output stays
/// stable across platforms and Rust versions. `stream` separates the
/// secret-scalar bytes from the nonce bytes of the same seed.
fn seeded_bytes(seed: u64, stream: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut s = seed
        .wrapping_mul(0x2545_F491_4F6C_DD1D)
        .wrapping_add(stream.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    for chunk in out.chunks_mut(8) {
        s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte = (z >> (i * 8)) as u8;
        }
    }
    out
}

/// A genuine SEC1-compressed P-256 household public key for `seed`, so the
/// fixture stays valid for a consumer that parses the point before hashing.
fn seeded_hh_pub(seed: u64) -> [u8; 33] {
    let scalar = seeded_bytes(seed, 1);
    let keypair = P256Keypair::from_secret_scalar(&scalar)
        .unwrap_or_else(|e| panic!("seed {seed} yields an invalid P-256 scalar: {e}"));
    *keypair.public().as_bytes()
}

fn seeded_nonce(seed: u64) -> [u8; 32] {
    seeded_bytes(seed, 2)
}

struct Vector {
    hh_pub: [u8; 33],
    nonce: [u8; 32],
    indices: [u16; 6],
    words: [&'static str; 6],
}

fn vectors() -> Vec<Vector> {
    (0..VECTOR_COUNT)
        .map(|seed| {
            let hh_pub = seeded_hh_pub(seed);
            let nonce = seeded_nonce(seed);
            Vector {
                hh_pub,
                nonce,
                indices: pair_device_fingerprint_indices(&hh_pub, &nonce),
                words: pair_device_fingerprint_words(&hh_pub, &nonce),
            }
        })
        .collect()
}

#[test]
fn pair_device_vectors_are_deterministic_across_runs() {
    let a = vectors();
    let b = vectors();
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.hh_pub, y.hh_pub);
        assert_eq!(x.nonce, y.nonce);
        assert_eq!(x.indices, y.indices);
        assert_eq!(x.words, y.words);
    }
}

#[test]
fn pair_device_vectors_are_distinct_and_in_range() {
    let all = vectors();
    for (i, v) in all.iter().enumerate() {
        assert!(matches!(v.hh_pub[0], 0x02 | 0x03), "vector {i}: SEC1 tag");
        for idx in v.indices {
            assert!(idx < 2048, "vector {i}: index {idx} out of range");
        }
        for w in v.words {
            assert!(!w.is_empty(), "vector {i}: empty word");
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "vector {i}: non-lower-ASCII word {w:?}"
            );
        }
        for other in &all[i + 1..] {
            assert_ne!(v.hh_pub, other.hh_pub, "vector {i}: duplicate hh_pub");
            assert_ne!(v.nonce, other.nonce, "vector {i}: duplicate nonce");
        }
    }
}

#[test]
fn pair_device_words_round_trip_through_word_index() {
    for (i, v) in vectors().iter().enumerate() {
        for (j, (idx, word)) in v.indices.iter().zip(v.words.iter()).enumerate() {
            assert_eq!(WORDLIST[*idx as usize], *word, "vector {i} word {j}");
            assert_eq!(word_index(word), Some(*idx), "vector {i} word {j}");
        }
    }
}

#[test]
fn pair_device_fingerprint_vectors_json_exists_and_is_consistent() {
    let path = vectors_json_path();
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing {} ({e}); regenerate via `cargo test -p household-rs --test pair_device_fingerprint -- --ignored regenerate_pair_device_fingerprint_vectors_json`",
            path.display()
        )
    });
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("vectors JSON is valid");
    let arr = parsed.as_array().expect("vectors JSON is an array");
    let actual = vectors();
    assert_eq!(
        arr.len(),
        actual.len(),
        "vectors length drift: file has {} entries, in-process has {}",
        arr.len(),
        actual.len()
    );
    for (i, v) in actual.iter().enumerate() {
        let entry = &arr[i];
        let hh_pub_hex = entry["hh_pub_hex"]
            .as_str()
            .expect("hh_pub_hex is a string");
        let nonce_hex = entry["nonce_hex"].as_str().expect("nonce_hex is a string");
        assert_eq!(hh_pub_hex, hex::encode(v.hh_pub), "vector {i}: hh_pub_hex");
        assert_eq!(nonce_hex, hex::encode(v.nonce), "vector {i}: nonce_hex");

        // Round trip from the file's own bytes, independent of the seeded
        // generator: decode → derive → must equal what the file claims.
        let hh_pub: [u8; 33] = hex::decode(hh_pub_hex)
            .expect("hh_pub_hex decodes")
            .try_into()
            .expect("hh_pub is 33 bytes");
        let nonce: [u8; 32] = hex::decode(nonce_hex)
            .expect("nonce_hex decodes")
            .try_into()
            .expect("nonce is 32 bytes");
        let file_indices: Vec<u16> = entry["indices"]
            .as_array()
            .expect("indices is an array")
            .iter()
            .map(|x| u16::try_from(x.as_u64().expect("index is an integer")).expect("fits u16"))
            .collect();
        let file_words: Vec<&str> = entry["words"]
            .as_array()
            .expect("words is an array")
            .iter()
            .map(|x| x.as_str().expect("each word is a string"))
            .collect();
        assert_eq!(
            file_indices,
            pair_device_fingerprint_indices(&hh_pub, &nonce),
            "vector {i}: indices"
        );
        assert_eq!(
            file_words,
            pair_device_fingerprint_words(&hh_pub, &nonce),
            "vector {i}: words"
        );
        for (j, (idx, word)) in file_indices.iter().zip(file_words.iter()).enumerate() {
            assert_eq!(WORDLIST[*idx as usize], *word, "vector {i} word {j}");
            assert_eq!(word_index(word), Some(*idx), "vector {i} word {j}");
        }
    }
}

#[test]
#[ignore = "manual regeneration only — writes the canonical cross-repo vectors file"]
fn regenerate_pair_device_fingerprint_vectors_json() {
    let path = vectors_json_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create vectors dir");
    }
    let json_arr: Vec<serde_json::Value> = vectors()
        .iter()
        .map(|v| {
            serde_json::json!({
                "hh_pub_hex": hex::encode(v.hh_pub),
                "nonce_hex": hex::encode(v.nonce),
                "indices": v.indices,
                "words": v.words,
            })
        })
        .collect();
    let payload = serde_json::to_string_pretty(&json_arr).unwrap();
    fs::write(&path, format!("{payload}\n")).expect("write pair_device_fingerprint_vectors.json");
}

fn vectors_json_path() -> std::path::PathBuf {
    // Anchored at the crate root, next to `fingerprint_vectors.json`, so the
    // path survives any cross-repo sandbox (Nix, devcontainer, etc.).
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_root
        .join("tests")
        .join("data")
        .join("pair_device_fingerprint_vectors.json")
}
