#![allow(dead_code)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
use household_rs::pair_device::PairNonce;
use household_rs::pop::{PairingProofContext, RequestSigningContext};
use household_rs::{HouseholdId, P256Signature, derive_person_id};
use serde::Deserialize;
use serde_json::json;

pub struct TestPersonKey {
    pub key: P256Keypair,
    pub p_pub_b64: String,
    pub p_id: String,
}

impl TestPersonKey {
    pub fn generate() -> Self {
        let key = P256Keypair::generate();
        let public = key.public();
        Self {
            p_pub_b64: B64URL.encode(public.as_bytes()),
            p_id: derive_person_id(&public).0,
            key,
        }
    }
}

pub fn signed_pair_confirm_body(
    hh_id: &HouseholdId,
    nonce: &PairNonce,
    person: &TestPersonKey,
    display_name: &str,
) -> serde_json::Value {
    let p_pub = P256PublicKey::from_bytes(
        &B64URL
            .decode(&person.p_pub_b64)
            .expect("decode generated p_pub"),
    )
    .expect("valid generated p_pub");
    let ctx = PairingProofContext::new(hh_id.clone(), nonce.0, p_pub);
    let sig = person.key.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    json!({
        "v": 1,
        "nonce": nonce.as_b64(),
        "p_pub": person.p_pub_b64,
        "display_name": display_name,
        "proof_sig": B64URL.encode(sig.as_bytes()),
    })
}

pub fn pop_header(
    person: &TestPersonKey,
    method: &str,
    path_and_query: &str,
    timestamp: u64,
    body: &[u8],
) -> String {
    let ctx = RequestSigningContext::new(method, path_and_query, timestamp, body);
    let sig = person.key.sign(&ctx.canonical_bytes().unwrap()).unwrap();
    format!(
        "Soyeht-PoP v1:{}:{}:{}",
        person.p_id,
        timestamp,
        B64URL.encode(sig.as_bytes())
    )
}

#[derive(Debug, Deserialize)]
pub struct PairConfirmBody {
    pub v: u8,
    pub hh_id: String,
    pub p_id: String,
    pub person_cert_cbor: String,
    pub capabilities: Vec<String>,
    pub consumed: Option<bool>,
}

pub fn decode_signature_b64url(value: &str) -> P256Signature {
    let bytes = B64URL.decode(value).expect("decode signature");
    P256Signature::from_bytes(&bytes).expect("signature length")
}
