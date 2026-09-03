//! Golden vectors for `derive_emoji_code`.
//!
//! The emoji security code is a second cross-language contract: the Mac shows
//! six emoji, the phone derives the same six, and a person compares them. It
//! shares `fingerprint::extract_indices` with the six-word pair-device code
//! since that helper was hoisted out of this module — which means an edit made
//! "for BIP-39 reasons" silently changes the emoji code too.
//!
//! Before this file the only pinned output in the whole emoji path was
//! "six non-empty strings, all indices < 2048". Nothing compared
//! `derive_emoji_code` to a fixed answer, so that edit would have shipped
//! green. These vectors are the fixed answer.
//!
//! Unlike the pair-device vectors, the hostname is folded into the hash, so a
//! vector is `(m_pub, nonce, hostname) -> six emoji`.

use household_rs::emoji_code::derive_emoji_code;

/// `(m_pub seed, nonce seed, hostname)`. Seeds are expanded deterministically
/// below so the file stays readable.
const CASES: [(u8, u8, &str); 8] = [
    (0x02, 0x00, ""),
    (0x02, 0x01, "a"),
    (0x03, 0x02, "mac-alpha"),
    (0x02, 0x03, "mac-alpha.local"),
    (0x03, 0x04, "MAC-ALPHA"),
    (
        0x02,
        0x05,
        "a-very-long-host-name-that-keeps-going-and-going",
    ),
    (0x03, 0x06, "café"),
    (0x02, 0xff, "mac-beta"),
];

fn m_pub(tag: u8, seed: u8) -> [u8; 33] {
    let mut key = [0u8; 33];
    key[0] = tag;
    for (i, byte) in key.iter_mut().enumerate().skip(1) {
        *byte = seed
            .wrapping_mul(31)
            .wrapping_add(u8::try_from(i).unwrap_or(0));
    }
    key
}

fn nonce(seed: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    for (i, byte) in n.iter_mut().enumerate() {
        *byte = seed
            .wrapping_mul(17)
            .wrapping_add(u8::try_from(i).unwrap_or(0));
    }
    n
}

fn vectors_json_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("emoji_code_vectors.json")
}

fn derive_case(case: (u8, u8, &str)) -> [String; 6] {
    let (tag, seed, hostname) = case;
    derive_emoji_code(&m_pub(tag, seed), &nonce(seed), hostname)
}

#[test]
fn emoji_code_matches_the_committed_vectors() {
    let raw = std::fs::read_to_string(vectors_json_path())
        .expect("emoji_code_vectors.json must be committed next to the other vector files");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    let rows = parsed["vectors"].as_array().expect("vectors array");
    assert_eq!(rows.len(), CASES.len(), "vector count drifted from CASES");

    for (i, (case, row)) in CASES.iter().zip(rows).enumerate() {
        assert_eq!(
            row["hostname"].as_str(),
            Some(case.2),
            "vector {i}: hostname drifted"
        );
        let expected: Vec<&str> = row["emoji"]
            .as_array()
            .expect("emoji array")
            .iter()
            .map(|v| v.as_str().expect("emoji string"))
            .collect();
        let actual = derive_case(*case);
        assert_eq!(
            actual.iter().map(String::as_str).collect::<Vec<_>>(),
            expected,
            "vector {i} ({}): derive_emoji_code changed. If this is deliberate, \
             regenerate the file and say so — but check whether you also changed \
             the six-word pair-device code, which shares extract_indices.",
            case.2
        );
    }
}

#[test]
fn emoji_code_depends_on_the_hostname() {
    // The hostname is folded into the hash on purpose: it binds the code to
    // the machine showing it. If that ever stops being true, these vectors
    // would still pass while the property was gone.
    let a = derive_emoji_code(&m_pub(0x02, 9), &nonce(9), "mac-alpha");
    let b = derive_emoji_code(&m_pub(0x02, 9), &nonce(9), "mac-beta");
    assert_ne!(a, b, "the hostname must change the code");
}

/// `EMOJI_VECTORS=regenerate cargo test -p household-rs --test emoji_code_vectors`
#[test]
fn regenerate_emoji_code_vectors_when_asked() {
    if std::env::var("EMOJI_VECTORS").as_deref() != Ok("regenerate") {
        return;
    }
    let rows: Vec<serde_json::Value> = CASES
        .iter()
        .map(|case| {
            serde_json::json!({
                "hostname": case.2,
                "emoji": derive_case(*case).to_vec(),
            })
        })
        .collect();
    let doc = serde_json::json!({
        "_comment": "Golden vectors for derive_emoji_code. Regenerate only \
                     deliberately: this code is compared by a person across two \
                     devices, and it shares extract_indices with the six-word \
                     pair-device code.",
        "vectors": rows,
    });
    std::fs::write(
        vectors_json_path(),
        serde_json::to_string_pretty(&doc).expect("serialise") + "\n",
    )
    .expect("write vectors");
}
