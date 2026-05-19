//! Generator for `tests/fixtures/owner_cert_auth.cbor`.
//!
//! Produces 5 deterministic `TeardownRequest` CBOR variants for the owner-auth
//! contract cross-language fixture (T080a). Uses BLAKE3 to derive P-256 key
//! scalars from a fixed seed so the fixture is reproducible.
//!
//! Run:
//!   cargo run --manifest-path admin/rust/Cargo.toml -p server-rs \
//!     --bin gen-owner-cert-fixture -- \
//!     admin/rust/server-rs/tests/fixtures/owner_cert_auth.cbor
//!
//! Regenerate when the `TeardownRequest` wire format changes
//! (contracts/bootstrap-teardown.md).

use std::path::PathBuf;

use household_rs::cbor::to_canonical_vec;
use household_rs::ids::{HouseholdId, MachineId, derive_household_id, derive_machine_id};
use household_rs::{IdentityKey, P256Keypair};
use serde::Serialize;
use serde_bytes::ByteBuf;

const SEED: &[u8] = b"soyeht-onboarding-owner-cert-fixture-2026";
const BASE_TS: u64 = 1_746_921_600; // 2025-05-11 00:00:00 UTC

// ── Wire types (mirror of handlers_bootstrap private types) ───────────────────

#[derive(Serialize)]
struct TeardownPayload {
    #[serde(rename = "v")]
    version: u8,
    op: String,
    hh_id: String,
    m_id: String,
    nonce: ByteBuf,
    ts: u64,
    signed_by: ByteBuf,
}

#[derive(Serialize)]
struct TeardownRequest {
    #[serde(rename = "v")]
    version: u8,
    op: String,
    hh_id: String,
    m_id: String,
    nonce: ByteBuf,
    ts: u64,
    signed_by: ByteBuf,
    signature: ByteBuf,
}

// ── Output types ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct Fixture {
    seed: String,
    hh_pub: ByteBuf,
    owner_pub: ByteBuf,
    hh_id: String,
    m_id: String,
    base_ts: u64,
    variants: Variants,
}

#[derive(Serialize)]
struct Variants {
    valid: ByteBuf,
    sig_mismatch: ByteBuf,
    ts_skew: ByteBuf,
    nonce_replay: ByteBuf,
    unknown_signer: ByteBuf,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn derive_scalar(domain: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SEED);
    h.update(domain);
    *h.finalize().as_bytes()
}

fn derive_keypair(domain: &[u8]) -> P256Keypair {
    let scalar = derive_scalar(domain);
    P256Keypair::from_secret_scalar(&scalar).unwrap_or_else(|_| {
        // Extremely unlikely: scalar == 0 or >= n. Retry with a suffix.
        let mut h = blake3::Hasher::new();
        h.update(SEED);
        h.update(domain);
        h.update(b"-retry");
        let scalar2: [u8; 32] = *h.finalize().as_bytes();
        P256Keypair::from_secret_scalar(&scalar2).expect("second scalar derivation failed")
    })
}

fn fixed_nonce(domain: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SEED);
    h.update(b"nonce:");
    h.update(domain);
    *h.finalize().as_bytes()
}

fn build_request(
    hh_id: &HouseholdId,
    m_id: &MachineId,
    ts: u64,
    nonce: [u8; 32],
    signer: &P256Keypair,
) -> Vec<u8> {
    let signed_by = ByteBuf::from(signer.public().as_bytes().to_vec());
    let payload = TeardownPayload {
        version: 1,
        op: "teardown".into(),
        hh_id: hh_id.to_string(),
        m_id: m_id.to_string(),
        nonce: ByteBuf::from(nonce.to_vec()),
        ts,
        signed_by: signed_by.clone(),
    };
    let msg = to_canonical_vec(&payload).expect("encode payload");
    let sig = signer.sign(&msg).expect("sign");
    let req = TeardownRequest {
        version: 1,
        op: "teardown".into(),
        hh_id: hh_id.to_string(),
        m_id: m_id.to_string(),
        nonce: ByteBuf::from(nonce.to_vec()),
        ts,
        signed_by,
        signature: ByteBuf::from(sig.as_bytes().to_vec()),
    };
    to_canonical_vec(&req).expect("encode request")
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn main() {
    let owner_key = derive_keypair(b"owner");
    let m_key = derive_keypair(b"machine");
    let unknown_key = derive_keypair(b"unknown"); // key NOT in the household owner set

    let hh_key = derive_keypair(b"household");
    let hh_pub = hh_key.public();
    let m_pub = m_key.public();
    let owner_pub = owner_key.public();

    let hh_id = derive_household_id(&hh_pub);
    let m_id = derive_machine_id(&m_pub);

    let nonce = fixed_nonce(b"fixture-v1");

    // (a) Valid: well-formed, correct signature, ts within skew window.
    let valid = build_request(&hh_id, &m_id, BASE_TS, nonce, &owner_key);

    // (b) Signature mismatch: structurally valid CBOR, wrong signature (all-zero r=0).
    let sig_mismatch = {
        let signed_by = ByteBuf::from(owner_key.public().as_bytes().to_vec());
        let req = TeardownRequest {
            version: 1,
            op: "teardown".into(),
            hh_id: hh_id.to_string(),
            m_id: m_id.to_string(),
            nonce: ByteBuf::from(nonce.to_vec()),
            ts: BASE_TS,
            signed_by,
            signature: ByteBuf::from(vec![0u8; 64]),
        };
        to_canonical_vec(&req).expect("encode sig_mismatch")
    };

    // (c) ts skew: ts is 400 seconds behind BASE_TS (> 300-second gate).
    let ts_skew = build_request(
        &hh_id,
        &m_id,
        BASE_TS.saturating_sub(400),
        nonce,
        &owner_key,
    );

    // (d) Nonce replay: identical CBOR to `valid`. Server accepts the first use
    // and rejects the second (nonce already consumed). Fixture consumers should
    // send `valid` first, then `nonce_replay` to see the 401.
    let nonce_replay = valid.clone();

    // (e) Unknown signer: structurally valid, signature correct for the key,
    // but `signed_by` is a key not in the household's owner-cert set.
    let unknown_signer = build_request(&hh_id, &m_id, BASE_TS, nonce, &unknown_key);

    let fixture = Fixture {
        seed: String::from_utf8(SEED.to_vec()).expect("seed utf8"),
        hh_pub: ByteBuf::from(hh_pub.as_bytes().to_vec()),
        owner_pub: ByteBuf::from(owner_pub.as_bytes().to_vec()),
        hh_id: hh_id.to_string(),
        m_id: m_id.to_string(),
        base_ts: BASE_TS,
        variants: Variants {
            valid: ByteBuf::from(valid),
            sig_mismatch: ByteBuf::from(sig_mismatch),
            ts_skew: ByteBuf::from(ts_skew),
            nonce_replay: ByteBuf::from(nonce_replay),
            unknown_signer: ByteBuf::from(unknown_signer),
        },
    };

    let cbor_bytes = to_canonical_vec(&fixture).expect("encode fixture");

    let output_path = std::env::args().nth(1).map_or_else(
        || PathBuf::from("admin/rust/server-rs/tests/fixtures/owner_cert_auth.cbor"),
        PathBuf::from,
    );

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).expect("create output dir");
    }
    std::fs::write(&output_path, &cbor_bytes).expect("write fixture");
    eprintln!(
        "gen-owner-cert-fixture: wrote {} bytes → {}",
        cbor_bytes.len(),
        output_path.display()
    );
}
