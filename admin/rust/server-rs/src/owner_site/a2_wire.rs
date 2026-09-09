//! A2 wire types (M1/M2/M3), promoted from the test harness to production
//! for the S2 glue (increment 3a-4). The harness delegates to these — ONE
//! definition of the wire, used by both sides.
//!
//! Fields are `pub(crate)` so the transcript hashing in
//! `owner_site_binding_glue` can read them; serde shape is load-bearing
//! (canonical CBOR on the wire and inside transcript preimages).

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct CanonicalIntent {
    pub(crate) method: String,
    pub(crate) target: String,
    #[serde(with = "serde_bytes")]
    pub(crate) body_hash: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct ClientHelloCore {
    pub(crate) domain: String,
    pub(crate) version: u8,
    pub(crate) household_id: String,
    pub(crate) network_id: String,
    pub(crate) route: String,
    pub(crate) resource: String,
    pub(crate) intent: CanonicalIntent,
    #[serde(with = "serde_bytes")]
    pub(crate) claimed_binding_id: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
#[allow(dead_code)] // consumed by the M3 flows (harness today, production 3a-5)
pub(crate) struct ClientHello {
    pub(crate) core: ClientHelloCore,
    #[serde(with = "serde_bytes")]
    pub(crate) device_ephemeral: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct ServerHello {
    #[serde(with = "serde_bytes")]
    pub(crate) engine_machine_certificate: Vec<u8>,
    pub(crate) engine_key_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) channel_id: Vec<u8>,
    pub(crate) channel_epoch: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) challenge_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) challenge_secret: Vec<u8>,
    pub(crate) authz_epoch: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) roster_digest: Vec<u8>,
    pub(crate) fresh_until: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) engine_signature: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
#[allow(dead_code)] // consumed by the M3 flows (harness today, production 3a-5)
pub(crate) struct ClientProof {
    #[serde(with = "serde_bytes")]
    pub(crate) binding_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) binding_digest: Vec<u8>,
    pub(crate) participant_npub: String,
    pub(crate) channel_auth_key_id: String,
    pub(crate) action_pop_key_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) device_signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) action_pop: Vec<u8>,
}

/// A2 frame kinds on the wire.
#[allow(dead_code)] // consumed by the responder (next increment)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AkeMessageKind {
    M1 = 1,
    M2 = 2,
    M3 = 3,
}

#[allow(dead_code)]
impl AkeMessageKind {
    pub(crate) fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::M1),
            2 => Some(Self::M2),
            3 => Some(Self::M3),
            _ => None,
        }
    }
}

#[allow(dead_code)] // consumed by the responder (next increment)
#[derive(Deserialize, Serialize)]
pub(crate) struct AkeFrame {
    pub(crate) version: u8,
    pub(crate) kind: u8,
    #[serde(with = "serde_bytes")]
    pub(crate) noise: Vec<u8>,
}

/// A2-R1 post-M3 WebSocket envelope. Deliberately a tuple, so canonical CBOR
/// encodes exactly `[1, ciphertext]`; no plaintext record kind, direction,
/// nonce, or authorization is visible outside Noise.
#[allow(dead_code)] // consumed by the S2/C3 record flow (next increment)
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct A2RecordEnvelope(
    pub(crate) u8,
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
);
