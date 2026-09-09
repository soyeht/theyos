//! B0b — roster evidence primitives: domains, snapshot body, the two digests,
//! the signing preimage, and the outcome vocabulary.
//!
//! The wire is **frozen by the iOS client** (`RosterEvidenceClient` /
//! `RosterEvidenceVerifier`). Everything here exists to reproduce those bytes
//! exactly; nothing here may be "improved" without re-freezing the client.
//!
//! Three things in this module break *silently* if got wrong — each produces a
//! server that is internally consistent and that the client rejects, so the
//! inline negative controls below are not optional:
//!
//! 1. **The trailing NUL in each domain.** Dropping it still hashes, still
//!    verifies against itself, and never matches the client.
//! 2. **The floor asymmetry.** `state_evidence_digest` is taken over the body
//!    *without* `floor_secs`; `full_snapshot_digest` over the body *with* it.
//!    Swapping them yields two coherent digests of the wrong preimages.
//! 3. **The unsigned map.** When the outcome is `available` the signature must
//!    cover `snapshot_body` and both digests. Omitting them signs a strictly
//!    weaker statement while still verifying.
//! 4. **The body type inside the unsigned map.** `snapshot_body` is a nested
//!    CBOR map, not a byte string containing CBOR. The latter still verifies
//!    against itself but is a different preimage from the one frozen by iOS.
//!
//! The outcome vocabulary is deliberately **not** shared with
//! `machine_roster_store::PublicCurrencyOutcome`. That enum has nine literals
//! and this one has four, and they partition the same store states
//! incompatibly: no-genesis and both fork states are `unavailable_*` for
//! currency but **`available`** here, carried as `state_kind` 0/2/3. A shared
//! enum or a shared `wire_str` would leak one vocabulary into the other.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::HouseholdError;
use crate::ids::HouseholdId;
use crate::keys::{IdentityKey, P256Signature};
use crate::machine_cert::MachineCert;
use crate::machine_roster_authority::{bstr_var, bstr32, machine_cert_fingerprint};

/// Public serde adapter for the evidence request nonce.
///
/// The authoritative bstr[32] implementation remains the existing roster
/// adapter; this module only makes it reachable by the server crate.
pub mod request_bstr32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        super::bstr32::serialize(value, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        super::bstr32::deserialize(deserializer)
    }
}

/// Domain separators. The trailing NUL is part of the domain, not a typo.
const EVIDENCE_DOMAIN: &[u8] = b"soyeht/roster-evidence/v1\x00";
const SNAPSHOT_DOMAIN: &[u8] = b"soyeht/roster-snapshot/v1\x00";

/// Wire version carried by both the request and every response.
pub const EVIDENCE_VERSION: u8 = 1;

/// The four literals this surface may serve. See the module note on why these
/// are not the currency literals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterEvidenceOutcome {
    Available,
    UnavailableClockState,
    UnavailableOwnerAuthority,
    UnavailableCheckpointStale,
}

impl RosterEvidenceOutcome {
    /// Kept beside the definition, exactly as the currency enum does, so the
    /// two vocabularies cannot drift into a shared helper.
    #[must_use]
    pub fn wire_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::UnavailableClockState => "unavailable_clock_state",
            Self::UnavailableOwnerAuthority => "unavailable_owner_authority",
            Self::UnavailableCheckpointStale => "unavailable_checkpoint_stale",
        }
    }

    #[must_use]
    pub fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// The immutable projection of the roster chain that the store hands out.
///
/// `state_kind` crosses the boundary as `u8` on purpose: the store's
/// `ChainStateKind` is an internal type and must not become part of this
/// surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterEvidenceSnapshot {
    pub hh_id: HouseholdId,
    pub state_kind: u8,
    pub floor_secs: u64,
    pub genesis_checkpoint: Option<Vec<u8>>,
    pub accepted_checkpoint: Option<Vec<u8>>,
    pub predecessor_checkpoint: Option<Vec<u8>>,
    pub conflicting_checkpoint: Option<Vec<u8>>,
}

/// The snapshot body as it appears on the wire.
///
/// `floor_secs` is an `Option` **only** so the same shape can be encoded twice
/// — once without it for `state_evidence_digest`, once with it for
/// `full_snapshot_digest` and for the served `snapshot_body`. It is never
/// absent on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RosterEvidenceSnapshotBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_checkpoint: Option<serde_bytes::ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conflicting_checkpoint: Option<serde_bytes::ByteBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    floor_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    genesis_checkpoint: Option<serde_bytes::ByteBuf>,
    hh_id: HouseholdId,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_checkpoint: Option<serde_bytes::ByteBuf>,
    state_kind: u8,
    v: u8,
}

impl RosterEvidenceSnapshot {
    fn wire(&self, include_floor: bool) -> RosterEvidenceSnapshotBody {
        fn opt(blob: Option<&[u8]>) -> Option<serde_bytes::ByteBuf> {
            blob.map(<[u8]>::to_vec).map(serde_bytes::ByteBuf::from)
        }
        RosterEvidenceSnapshotBody {
            accepted_checkpoint: opt(self.accepted_checkpoint.as_deref()),
            conflicting_checkpoint: opt(self.conflicting_checkpoint.as_deref()),
            floor_secs: include_floor.then_some(self.floor_secs),
            genesis_checkpoint: opt(self.genesis_checkpoint.as_deref()),
            hh_id: self.hh_id.clone(),
            predecessor_checkpoint: opt(self.predecessor_checkpoint.as_deref()),
            state_kind: self.state_kind,
            v: EVIDENCE_VERSION,
        }
    }

    /// Canonical CBOR of the body. `include_floor` selects which of the two
    /// preimages this is — see the module note on the asymmetry.
    pub fn body_cbor(&self, include_floor: bool) -> Result<Vec<u8>, HouseholdError> {
        crate::cbor::to_canonical_vec(&self.wire(include_floor))
    }

    /// The body exactly as served in `snapshot_body`: **with** `floor_secs`.
    pub fn served_body_cbor(&self) -> Result<Vec<u8>, HouseholdError> {
        self.body_cbor(true)
    }

    /// `SHA256(evidence_domain ‖ canonical_cbor(body WITHOUT floor_secs))`.
    pub fn state_evidence_digest(&self) -> Result<[u8; 32], HouseholdError> {
        Ok(domain_digest(EVIDENCE_DOMAIN, &self.body_cbor(false)?))
    }

    /// `SHA256(snapshot_domain ‖ canonical_cbor(body WITH floor_secs))`.
    pub fn full_snapshot_digest(&self) -> Result<[u8; 32], HouseholdError> {
        Ok(domain_digest(SNAPSHOT_DOMAIN, &self.body_cbor(true)?))
    }
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// The map the signature covers.
///
/// The three optional members are present **iff** the outcome is `available`.
/// An `unavailable` is therefore a signed, signer-anchored statement over the
/// six base fields alone — categorically not an unsigned error envelope.
#[derive(Serialize)]
struct EvidenceUnsigned<'a> {
    #[serde(with = "bstr32")]
    client_nonce: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    full_snapshot_digest: Option<&'a serde_bytes::Bytes>,
    outcome: &'a str,
    #[serde(with = "bstr_var")]
    signer_machine_cert: Vec<u8>,
    #[serde(with = "bstr32")]
    signer_machine_cert_fingerprint: [u8; 32],
    signer_m_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_body: Option<&'a RosterEvidenceSnapshotBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_evidence_digest: Option<&'a serde_bytes::Bytes>,
    v: u8,
}

/// Everything the handler needs to serve one evidence response.
///
/// Built in one place so the "an unavailable carries no body and no digests"
/// invariant is expressed once and can be tested without a server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRosterEvidence {
    pub outcome: RosterEvidenceOutcome,
    pub client_nonce: [u8; 32],
    pub signer_m_id: String,
    pub signer_machine_cert: Vec<u8>,
    pub signer_machine_cert_fingerprint: [u8; 32],
    pub signature: P256Signature,
    /// `Some` iff `outcome` is `available`. All three move together.
    pub snapshot_body: Option<RosterEvidenceSnapshotBody>,
    pub state_evidence_digest: Option<[u8; 32]>,
    pub full_snapshot_digest: Option<[u8; 32]>,
}

/// Assemble and sign one evidence response.
///
/// `snapshot` is `Some` only for `available`; passing one for an unavailable is
/// rejected rather than silently dropped, because that mismatch is exactly how
/// a body could leak into an unavailable response.
pub fn build_signed_evidence(
    outcome: RosterEvidenceOutcome,
    client_nonce: [u8; 32],
    signer_cert: &MachineCert,
    signer_key: &dyn IdentityKey,
    snapshot: Option<&RosterEvidenceSnapshot>,
) -> Result<SignedRosterEvidence, HouseholdError> {
    if outcome.is_available() != snapshot.is_some() {
        return Err(HouseholdError::InvalidRecord(
            "evidence snapshot presence must match the available outcome".into(),
        ));
    }

    let signer_machine_cert = crate::cbor::to_canonical_vec(signer_cert)?;
    let signer_machine_cert_fingerprint = machine_cert_fingerprint(signer_cert)
        .map_err(|_| HouseholdError::Cbor("signer cert fingerprint".into()))?;
    let signer_m_id = signer_cert.m_id.to_string();

    let (snapshot_body, state_digest, full_digest) = match snapshot {
        Some(snapshot) => (
            Some(snapshot.wire(true)),
            Some(snapshot.state_evidence_digest()?),
            Some(snapshot.full_snapshot_digest()?),
        ),
        None => (None, None, None),
    };

    let unsigned = EvidenceUnsigned {
        client_nonce,
        full_snapshot_digest: full_digest.as_ref().map(|d| serde_bytes::Bytes::new(d)),
        outcome: outcome.wire_str(),
        signer_machine_cert: signer_machine_cert.clone(),
        signer_machine_cert_fingerprint,
        signer_m_id: &signer_m_id,
        snapshot_body: snapshot_body.as_ref(),
        state_evidence_digest: state_digest.as_ref().map(|d| serde_bytes::Bytes::new(d)),
        v: EVIDENCE_VERSION,
    };

    let mut preimage = Vec::with_capacity(EVIDENCE_DOMAIN.len() + 512);
    preimage.extend_from_slice(EVIDENCE_DOMAIN);
    preimage.extend_from_slice(&crate::cbor::to_canonical_vec(&unsigned)?);
    let signature = signer_key
        .sign(&preimage)
        .map_err(|_| HouseholdError::InvalidRecord("evidence signing failed".into()))?;

    Ok(SignedRosterEvidence {
        outcome,
        client_nonce,
        signer_m_id,
        signer_machine_cert,
        signer_machine_cert_fingerprint,
        signature,
        snapshot_body,
        state_evidence_digest: state_digest,
        full_snapshot_digest: full_digest,
    })
}

/// Recompute the signing preimage for an assembled response.
///
/// Exposed so a verifier — the test/vector side, never the producer — can check
/// a signature without rebuilding the response.
pub fn signing_preimage(evidence: &SignedRosterEvidence) -> Result<Vec<u8>, HouseholdError> {
    let unsigned = EvidenceUnsigned {
        client_nonce: evidence.client_nonce,
        full_snapshot_digest: evidence
            .full_snapshot_digest
            .as_ref()
            .map(|d| serde_bytes::Bytes::new(d)),
        outcome: evidence.outcome.wire_str(),
        signer_machine_cert: evidence.signer_machine_cert.clone(),
        signer_machine_cert_fingerprint: evidence.signer_machine_cert_fingerprint,
        signer_m_id: &evidence.signer_m_id,
        snapshot_body: evidence.snapshot_body.as_ref(),
        state_evidence_digest: evidence
            .state_evidence_digest
            .as_ref()
            .map(|d| serde_bytes::Bytes::new(d)),
        v: EVIDENCE_VERSION,
    };
    let mut preimage = Vec::with_capacity(EVIDENCE_DOMAIN.len() + 512);
    preimage.extend_from_slice(EVIDENCE_DOMAIN);
    preimage.extend_from_slice(&crate::cbor::to_canonical_vec(&unsigned)?);
    Ok(preimage)
}

#[cfg(test)]
mod tests;
