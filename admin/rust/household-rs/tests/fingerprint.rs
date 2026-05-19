//! T008 / `contracts/fingerprint-derivation.md` determinism vectors.
//!
//! 16 fixed `m_pub_sec1` byte vectors → 16 expected fingerprint strings.
//! The vectors are computed once and locked in this file. Any deviation
//! in the derivation algorithm (BLAKE3, bit-extraction, BIP-39 lookup,
//! join character) MUST surface as a test failure here.
//!
//! Cross-repo sync: the canonical vectors file lives at
//! `admin/rust/household-rs/tests/data/fingerprint_vectors.json`. The
//! iSoyehtTerm Swift test target vendors the same file via a
//! repo-relative path (still stable — anchored at the Rust crate root
//! rather than the retired `specs/` dir). Each entry exposes BOTH a
//! space-separated `fingerprint` string AND a `fingerprint_words`
//! array of six lowercase ASCII strings so each side of the cross-
//! repo gate can pick the shape that matches its existing assertion
//! conventions without re-deriving anything.

#![allow(clippy::cast_possible_truncation)]

use household_rs::fingerprint::fingerprint;
use std::fs;
use std::path::Path;

/// 16 deterministic seeds yielding 16 distinct 33-byte machine public-key
/// values. The seeds drive a small `SplitMix64` so test output stays
/// stable across platforms and Rust versions.
fn seeded_m_pub(seed: u64) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = if seed & 1 == 0 { 0x02 } else { 0x03 };
    let mut s = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    for chunk in out[1..].chunks_mut(8) {
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

fn vectors() -> Vec<([u8; 33], String)> {
    (0..16u64)
        .map(|seed| {
            let m_pub = seeded_m_pub(seed);
            let fp = fingerprint(&m_pub);
            (m_pub, fp)
        })
        .collect()
}

#[test]
fn fingerprint_is_deterministic_across_runs() {
    // Compute twice and assert byte-equality on every entry. If the
    // algorithm drifted between calls (e.g., a future refactor accidentally
    // introduced timing-dependent state), this fails.
    let a = vectors();
    let b = vectors();
    assert_eq!(a, b);
}

#[test]
fn fingerprints_are_six_lowercase_ascii_words() {
    for (m_pub, fp) in vectors() {
        let words: Vec<&str> = fp.split(' ').collect();
        assert_eq!(
            words.len(),
            6,
            "fp {fp:?} for m_pub {} not six words",
            hex(&m_pub)
        );
        for w in &words {
            assert!(!w.is_empty(), "empty word in {fp:?}");
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "non-lower-ASCII in {fp:?}: {w:?}"
            );
        }
    }
}

#[test]
fn fingerprint_vectors_json_exists_and_is_consistent() {
    // T008 / T094: theyos publishes a JSON list at tests/fingerprint_vectors.json
    // for the iSoyehtTerm Swift test target to consume. We assert the
    // file exists, parses, and matches the in-process vectors. The file
    // is checked into git; failing this test means a regenerate run is
    // needed.
    let path = vectors_json_path();
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing {} ({e}); regenerate via `cargo test -p household-rs --test fingerprint -- --ignored regenerate_fingerprint_vectors_json`",
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
    for (i, (m_pub, fp)) in actual.iter().enumerate() {
        let entry = &arr[i];
        assert_eq!(entry["index"].as_u64(), Some(i as u64));
        assert_eq!(entry["m_pub_sec1_hex"].as_str(), Some(hex(m_pub).as_str()));
        assert_eq!(entry["fingerprint"].as_str(), Some(fp.as_str()));
        let words: Vec<&str> = fp.split(' ').collect();
        let arr_words: Vec<String> = entry["fingerprint_words"]
            .as_array()
            .expect("fingerprint_words must be an array")
            .iter()
            .map(|v| v.as_str().expect("each word is a string").to_string())
            .collect();
        assert_eq!(
            arr_words.len(),
            6,
            "fingerprint_words must have six entries"
        );
        for (j, w) in words.iter().enumerate() {
            assert_eq!(
                arr_words[j].as_str(),
                *w,
                "word {j} disagrees with fingerprint string"
            );
        }
    }
}

#[test]
#[ignore = "manual regeneration only — writes the canonical cross-repo vectors file"]
fn regenerate_fingerprint_vectors_json() {
    let path = vectors_json_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create vectors dir");
    }
    let actual = vectors();
    let json_arr: Vec<serde_json::Value> = actual
        .iter()
        .enumerate()
        .map(|(i, (m_pub, fp))| {
            let words: Vec<&str> = fp.split(' ').collect();
            serde_json::json!({
                "index": i,
                "m_pub_sec1_hex": hex(m_pub),
                "fingerprint": fp,
                "fingerprint_words": words,
            })
        })
        .collect();
    let payload = serde_json::to_string_pretty(&json_arr).unwrap();
    fs::write(&path, format!("{payload}\n")).expect("write fingerprint_vectors.json");
}

fn vectors_json_path() -> std::path::PathBuf {
    // Anchored at the crate root so the path survives any cross-repo
    // sandbox (Nix, devcontainer, etc.). Used to live under
    // `specs/003-machine-join/tests/` when the spec-kit flow was active;
    // moved into the crate alongside the other fixture data after the
    // spec-kit retire (see `docs/followup-llm-proxy-protecthome.md`-era
    // cleanup commits).
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_root
        .join("tests")
        .join("data")
        .join("fingerprint_vectors.json")
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}
