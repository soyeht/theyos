//! P7-B (PR1, theyos side) — `PoP` / CBOR cross-language golden vectors.
//!
//! Pins, byte-for-byte, the canonical CBOR of the two Soyeht proof-of-possession
//! signed contexts — `RequestSigningContext` (with its BLAKE3 body hash and a
//! fixed P-256 verify-vector) and `PairingProofContext` — against a neutral
//! public fixture (`data/pop_vectors.json`). The soyeht-ios half (PR2) asserts
//! the Swift encoder reproduces the same `canonical_cbor_hex` (and verifies the
//! same signature), proving the two implementations agree.
//!
//! IMPORTANT — scope:
//! * Test-only. It asserts the EXISTING behaviour of `pop.rs` / `cbor.rs`; it
//!   changes no runtime/wire/auth code and no canonicalization. If a future
//!   change to the signing context or canonicalization breaks these vectors,
//!   that is a deliberate cross-language wire change and must be handled as such
//!   (re-mint the vectors on BOTH sides), not by quietly editing this test.
//! * `Operation` / caveat is NOT part of the signed request context — it is
//!   enforced separately by the cert caveats (see the P7-A gate-completeness
//!   guard, `server-rs/tests/household_pop_gate_completeness.rs`). These vectors
//!   intentionally do not include it.
//! * The fixture holds only a PUBLIC key + a fixed signature; no secret/private
//!   key. ECDSA signing is not byte-reproducible across languages, so only the
//!   deterministic `verify` is pinned.

use household_rs::ids::HouseholdId;
use household_rs::keys::{P256PublicKey, P256Signature};
use household_rs::pop::{PairingProofContext, RequestSigningContext};
use serde::Deserialize;
use std::fmt::Write as _;

#[derive(Deserialize)]
struct Vectors {
    request_signing_context: Vec<RscCase>,
    pairing_proof_context: Vec<PpcCase>,
}

#[derive(Deserialize, Clone)]
struct RscCase {
    id: String,
    input: RscInput,
    body_hash_blake3_hex: String,
    canonical_cbor_hex: String,
    #[serde(default)]
    verify_vector: Option<VerifyVector>,
}

#[derive(Deserialize, Clone)]
struct RscInput {
    method: String,
    path_and_query: String,
    timestamp: u64,
    body_utf8: String,
}

#[derive(Deserialize, Clone)]
struct VerifyVector {
    public_key_sec1_compressed_hex: String,
    signature_p256_raw_hex: String,
}

#[derive(Deserialize, Clone)]
struct PpcCase {
    id: String,
    input: PpcInput,
    canonical_cbor_hex: String,
}

#[derive(Deserialize, Clone)]
struct PpcInput {
    purpose: String,
    household_id: String,
    nonce_hex: String,
    p_pub_sec1_compressed_hex: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("data/pop_vectors.json"))
        .expect("pop_vectors.json must be valid JSON")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn context_for(case: &RscCase) -> RequestSigningContext {
    RequestSigningContext::new(
        case.input.method.as_str(),
        case.input.path_and_query.as_str(),
        case.input.timestamp,
        case.input.body_utf8.as_bytes(),
    )
}

#[test]
fn canonical_bytes_and_body_hash_match_fixture() {
    for case in vectors().request_signing_context {
        let ctx = context_for(&case);
        assert_eq!(
            hex(&ctx.body_hash.0),
            case.body_hash_blake3_hex,
            "{}: BLAKE3 body hash drifted",
            case.id
        );
        assert_eq!(
            hex(&ctx.canonical_bytes().expect("canonical bytes")),
            case.canonical_cbor_hex,
            "{}: canonical CBOR drifted — if this is an intended wire change, re-mint the cross-language vectors on BOTH sides",
            case.id
        );
    }
}

#[test]
fn verify_vector_accepts_the_fixed_signature() {
    let mut checked = 0;
    for case in vectors().request_signing_context {
        let Some(vv) = case.verify_vector.clone() else {
            continue;
        };
        let ctx = context_for(&case);
        let pk = P256PublicKey::from_bytes(&unhex(&vv.public_key_sec1_compressed_hex))
            .expect("valid SEC1 compressed public key");
        let sig = P256Signature::from_bytes(&unhex(&vv.signature_p256_raw_hex))
            .expect("valid raw P-256 signature");
        ctx.verify(&pk, &sig)
            .unwrap_or_else(|e| panic!("{}: fixed verify-vector must verify: {e:?}", case.id));
        checked += 1;
    }
    assert!(
        checked > 0,
        "expected at least one verify-vector in the fixture"
    );
}

#[test]
fn tampering_changes_canonical_bytes_and_breaks_verify() {
    let case = vectors()
        .request_signing_context
        .into_iter()
        .find(|c| c.verify_vector.is_some())
        .expect("a case with a verify-vector");
    let vv = case.verify_vector.clone().unwrap();
    let pk = P256PublicKey::from_bytes(&unhex(&vv.public_key_sec1_compressed_hex)).unwrap();
    let sig = P256Signature::from_bytes(&unhex(&vv.signature_p256_raw_hex)).unwrap();
    let base = &case.input;

    // (method, path_and_query, timestamp, body) — each mutation in isolation.
    let mutations = [
        (
            "method",
            "PUT",
            base.path_and_query.as_str(),
            base.timestamp,
            base.body_utf8.as_bytes(),
        ),
        (
            "path",
            base.method.as_str(),
            "/api/v1/household/claws/other",
            base.timestamp,
            base.body_utf8.as_bytes(),
        ),
        (
            "timestamp",
            base.method.as_str(),
            base.path_and_query.as_str(),
            base.timestamp + 1,
            base.body_utf8.as_bytes(),
        ),
        (
            "body",
            base.method.as_str(),
            base.path_and_query.as_str(),
            base.timestamp,
            b"tampered".as_slice(),
        ),
    ];

    for (label, method, path, timestamp, body) in mutations {
        let tampered = RequestSigningContext::new(method, path, timestamp, body);
        assert_ne!(
            hex(&tampered.canonical_bytes().unwrap()),
            case.canonical_cbor_hex,
            "tampering {label} must change the canonical signing material"
        );
        assert!(
            tampered.verify(&pk, &sig).is_err(),
            "the fixed signature must NOT verify against a context with tampered {label}"
        );
    }
}

fn pairing_context(case: &PpcCase) -> PairingProofContext {
    let nonce_vec = unhex(&case.input.nonce_hex);
    assert_eq!(nonce_vec.len(), 32, "{}: nonce must be 32 bytes", case.id);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_vec);
    let p_pub = P256PublicKey::from_bytes(&unhex(&case.input.p_pub_sec1_compressed_hex))
        .expect("valid SEC1 compressed public key");
    let hh_id = HouseholdId::parse(case.input.household_id.clone())
        .expect("fixture household_id must be a well-formed HouseholdId");
    PairingProofContext::new(hh_id, nonce, p_pub)
}

#[test]
fn pairing_proof_context_canonical_bytes_match_fixture() {
    let mut checked = 0;
    for case in vectors().pairing_proof_context {
        assert_eq!(
            case.input.purpose,
            PairingProofContext::PURPOSE,
            "{}: pairing purpose constant drifted",
            case.id
        );
        let ctx = pairing_context(&case);
        assert_eq!(
            hex(&ctx.canonical_bytes().expect("canonical bytes")),
            case.canonical_cbor_hex,
            "{}: PairingProofContext canonical CBOR drifted — if intended, re-mint the cross-language vectors on BOTH sides",
            case.id
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "expected at least one pairing_proof_context case"
    );
}

#[test]
fn pairing_proof_context_mutations_and_invalid_fields() {
    let case = vectors()
        .pairing_proof_context
        .into_iter()
        .next()
        .expect("a pairing_proof_context case");

    // Changing the nonce changes the canonical bytes.
    let mut m = pairing_context(&case);
    m.nonce[0] ^= 0xff;
    assert_ne!(
        hex(&m.canonical_bytes().unwrap()),
        case.canonical_cbor_hex,
        "changing the nonce must alter the canonical bytes"
    );

    // Changing the household id changes the canonical bytes. The replacement is
    // itself a well-formed, distinct HouseholdId (no validation bypass).
    let mut m = pairing_context(&case);
    m.hh_id = HouseholdId::parse("hh_xvkthvh2atzntqhpivyucglovyrx4wr63xtdncxlsoqckpaff54q")
        .expect("valid household id");
    assert_ne!(
        hex(&m.canonical_bytes().unwrap()),
        case.canonical_cbor_hex,
        "changing hh_id must alter the canonical bytes"
    );

    // Invalid version / nonce length are rejected by the existing guard
    // (struct-literal mutation only — no production code is touched).
    let mut bad = pairing_context(&case);
    bad.version = 2;
    assert!(
        bad.canonical_bytes().is_err(),
        "version != 1 must be rejected"
    );

    let mut bad = pairing_context(&case);
    bad.nonce = vec![0x2a; 31];
    assert!(
        bad.canonical_bytes().is_err(),
        "nonce length != 32 must be rejected"
    );
}
