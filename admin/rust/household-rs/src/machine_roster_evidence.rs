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
mod tests {
    use super::*;
    use crate::keys::P256Keypair;
    use crate::machine_cert::{MachineCert, Platform, SignOptions};
    use ciborium::value::Value;

    const NOW: u64 = 1_714_972_800;

    fn signer() -> (P256Keypair, MachineCert) {
        let hh = P256Keypair::generate();
        let machine = P256Keypair::generate();
        let hh_id = crate::ids::derive_household_id(&hh.public());
        let cert = MachineCert::sign(
            &hh,
            &machine.public(),
            &SignOptions {
                hh_id,
                hostname: "studio-mac".into(),
                platform: Platform::Macos,
                joined_at: NOW,
            },
        )
        .unwrap();
        (machine, cert)
    }

    fn snapshot(state_kind: u8) -> RosterEvidenceSnapshot {
        let hh = P256Keypair::generate();
        RosterEvidenceSnapshot {
            hh_id: crate::ids::derive_household_id(&hh.public()),
            state_kind,
            floor_secs: NOW,
            genesis_checkpoint: (state_kind != 0).then(|| vec![0xA1, 0x01]),
            accepted_checkpoint: (state_kind != 0).then(|| vec![0xA1, 0x02]),
            predecessor_checkpoint: None,
            conflicting_checkpoint: (state_kind >= 2).then(|| vec![0xA1, 0x03]),
        }
    }

    fn map_keys(bytes: &[u8]) -> Vec<String> {
        let value: Value = ciborium::de::from_reader(bytes).unwrap();
        let Value::Map(entries) = value else {
            panic!("expected a CBOR map");
        };
        let mut keys = entries
            .iter()
            .map(|(k, _)| match k {
                Value::Text(t) => t.clone(),
                other => panic!("non-text key {other:?}"),
            })
            .collect::<Vec<_>>();
        keys.sort();
        keys
    }

    // ── domains ────────────────────────────────────────────────────────────

    #[test]
    fn domains_carry_the_trailing_nul() {
        assert_eq!(EVIDENCE_DOMAIN.last(), Some(&0u8));
        assert_eq!(SNAPSHOT_DOMAIN.last(), Some(&0u8));
        assert_eq!(EVIDENCE_DOMAIN, b"soyeht/roster-evidence/v1\x00");
        assert_eq!(SNAPSHOT_DOMAIN, b"soyeht/roster-snapshot/v1\x00");
        assert_ne!(EVIDENCE_DOMAIN, SNAPSHOT_DOMAIN);
    }

    /// NEGATIVE CONTROL — dropping the NUL changes every digest. Without this a
    /// domain typo produces a self-consistent server the client rejects.
    #[test]
    fn dropping_the_domain_nul_changes_the_digest() {
        let snap = snapshot(1);
        let body = snap.body_cbor(false).unwrap();
        let with_nul = domain_digest(EVIDENCE_DOMAIN, &body);
        let without_nul = domain_digest(b"soyeht/roster-evidence/v1", &body);
        assert_ne!(with_nul, without_nul);
        assert_eq!(with_nul, snap.state_evidence_digest().unwrap());
    }

    #[test]
    fn the_two_domains_produce_different_digests_of_the_same_bytes() {
        let snap = snapshot(1);
        let body = snap.body_cbor(true).unwrap();
        assert_ne!(
            domain_digest(EVIDENCE_DOMAIN, &body),
            domain_digest(SNAPSHOT_DOMAIN, &body)
        );
    }

    // ── the floor asymmetry ────────────────────────────────────────────────

    #[test]
    fn state_digest_body_omits_floor_and_full_digest_body_includes_it() {
        let snap = snapshot(1);
        assert!(!map_keys(&snap.body_cbor(false).unwrap()).contains(&"floor_secs".to_string()));
        assert!(map_keys(&snap.body_cbor(true).unwrap()).contains(&"floor_secs".to_string()));
        // The served body is the with-floor one.
        assert_eq!(
            snap.served_body_cbor().unwrap(),
            snap.body_cbor(true).unwrap()
        );
    }

    /// NEGATIVE CONTROL — swapping the asymmetry yields two coherent digests of
    /// the wrong preimages, which only a cross-check like this catches.
    #[test]
    fn swapping_the_floor_asymmetry_changes_both_digests() {
        let snap = snapshot(1);
        let swapped_state = domain_digest(EVIDENCE_DOMAIN, &snap.body_cbor(true).unwrap());
        let swapped_full = domain_digest(SNAPSHOT_DOMAIN, &snap.body_cbor(false).unwrap());
        assert_ne!(swapped_state, snap.state_evidence_digest().unwrap());
        assert_ne!(swapped_full, snap.full_snapshot_digest().unwrap());
    }

    #[test]
    fn floor_participates_only_in_the_full_digest() {
        let mut a = snapshot(1);
        let mut b = a.clone();
        b.floor_secs = a.floor_secs + 1;
        assert_eq!(
            a.state_evidence_digest().unwrap(),
            b.state_evidence_digest().unwrap(),
            "the state digest must not observe the floor"
        );
        assert_ne!(
            a.full_snapshot_digest().unwrap(),
            b.full_snapshot_digest().unwrap(),
            "the full digest must observe the floor"
        );
        a.floor_secs = b.floor_secs;
        assert_eq!(a, b);
    }

    // ── body shape per state_kind ──────────────────────────────────────────

    #[test]
    fn state_kind_zero_carries_only_the_four_base_keys() {
        let keys = map_keys(&snapshot(0).served_body_cbor().unwrap());
        assert_eq!(keys, vec!["floor_secs", "hh_id", "state_kind", "v"]);
    }

    #[test]
    fn accepted_without_predecessor_omits_the_predecessor_key() {
        let keys = map_keys(&snapshot(1).served_body_cbor().unwrap());
        assert_eq!(
            keys,
            vec![
                "accepted_checkpoint",
                "floor_secs",
                "genesis_checkpoint",
                "hh_id",
                "state_kind",
                "v"
            ]
        );
        assert!(!keys.contains(&"predecessor_checkpoint".to_string()));
        assert!(!keys.contains(&"conflicting_checkpoint".to_string()));
    }

    #[test]
    fn accepted_with_predecessor_carries_it() {
        let mut snap = snapshot(1);
        snap.predecessor_checkpoint = Some(vec![0xA1, 0x04]);
        assert!(
            map_keys(&snap.served_body_cbor().unwrap())
                .contains(&"predecessor_checkpoint".to_string())
        );
    }

    #[test]
    fn fork_states_carry_the_conflicting_checkpoint() {
        for kind in [2u8, 3u8] {
            let keys = map_keys(&snapshot(kind).served_body_cbor().unwrap());
            assert!(
                keys.contains(&"conflicting_checkpoint".to_string()),
                "state_kind {kind} must carry conflicting_checkpoint"
            );
            assert!(keys.contains(&"genesis_checkpoint".to_string()));
            assert!(keys.contains(&"accepted_checkpoint".to_string()));
        }
    }

    #[test]
    fn body_round_trips_canonically() {
        for kind in [0u8, 1, 2, 3] {
            let bytes = snapshot(kind).served_body_cbor().unwrap();
            let decoded: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(crate::cbor::to_canonical_vec(&decoded).unwrap(), bytes);
        }
    }

    // ── outcome vocabulary ─────────────────────────────────────────────────

    #[test]
    fn the_four_literals_are_exact_and_distinct() {
        let all = [
            RosterEvidenceOutcome::Available,
            RosterEvidenceOutcome::UnavailableClockState,
            RosterEvidenceOutcome::UnavailableOwnerAuthority,
            RosterEvidenceOutcome::UnavailableCheckpointStale,
        ];
        let wires: Vec<&str> = all.iter().map(|o| o.wire_str()).collect();
        assert_eq!(
            wires,
            vec![
                "available",
                "unavailable_clock_state",
                "unavailable_owner_authority",
                "unavailable_checkpoint_stale"
            ]
        );
        let distinct: std::collections::BTreeSet<&str> = wires.iter().copied().collect();
        assert_eq!(distinct.len(), 4);
        assert!(RosterEvidenceOutcome::Available.is_available());
        assert!(!RosterEvidenceOutcome::UnavailableClockState.is_available());
    }

    // ── the unsigned map ───────────────────────────────────────────────────

    #[test]
    fn available_signs_over_body_and_both_digests() {
        let (key, cert) = signer();
        let snap = snapshot(1);
        let evidence = build_signed_evidence(
            RosterEvidenceOutcome::Available,
            [7u8; 32],
            &cert,
            &key,
            Some(&snap),
        )
        .unwrap();
        let preimage = signing_preimage(&evidence).unwrap();
        assert!(preimage.starts_with(EVIDENCE_DOMAIN));
        let keys = map_keys(&preimage[EVIDENCE_DOMAIN.len()..]);
        assert_eq!(
            keys,
            vec![
                "client_nonce",
                "full_snapshot_digest",
                "outcome",
                "signer_m_id",
                "signer_machine_cert",
                "signer_machine_cert_fingerprint",
                "snapshot_body",
                "state_evidence_digest",
                "v"
            ]
        );
    }

    #[test]
    fn unavailable_signs_over_exactly_the_six_base_fields() {
        let (key, cert) = signer();
        let evidence = build_signed_evidence(
            RosterEvidenceOutcome::UnavailableClockState,
            [9u8; 32],
            &cert,
            &key,
            None,
        )
        .unwrap();
        let preimage = signing_preimage(&evidence).unwrap();
        let keys = map_keys(&preimage[EVIDENCE_DOMAIN.len()..]);
        assert_eq!(
            keys,
            vec![
                "client_nonce",
                "outcome",
                "signer_m_id",
                "signer_machine_cert",
                "signer_machine_cert_fingerprint",
                "v"
            ]
        );
        assert!(evidence.snapshot_body.is_none());
        assert!(evidence.state_evidence_digest.is_none());
        assert!(evidence.full_snapshot_digest.is_none());
    }

    /// The client signs the snapshot body as a **nested CBOR map**
    /// (`unsigned["snapshot_body"] = .map(snapshotBodyMap(...))`), not as a
    /// byte string containing CBOR. Asserting mere presence cannot tell the two
    /// apart, so this asserts the CBOR *type*: a bstr here is a server that
    /// verifies against itself and that iOS rejects every time.
    #[test]
    fn the_signed_snapshot_body_is_a_nested_map_not_a_byte_string() {
        let (key, cert) = signer();
        let snap = snapshot(1);
        let evidence = build_signed_evidence(
            RosterEvidenceOutcome::Available,
            [7u8; 32],
            &cert,
            &key,
            Some(&snap),
        )
        .unwrap();
        let preimage = signing_preimage(&evidence).unwrap();
        let value: Value = ciborium::de::from_reader(&preimage[EVIDENCE_DOMAIN.len()..]).unwrap();
        let Value::Map(entries) = value else {
            panic!("the unsigned preimage is a CBOR map");
        };
        let body = entries
            .iter()
            .find(|(k, _)| k == &Value::Text("snapshot_body".into()))
            .map(|(_, v)| v.clone())
            .expect("snapshot_body must be present when available");
        assert!(
            matches!(body, Value::Map(_)),
            "snapshot_body must be signed as a nested CBOR map, not a byte string"
        );
        // And its contents must be the with-floor body, key for key.
        let Value::Map(body_entries) = body else {
            unreachable!()
        };
        let mut keys = body_entries
            .iter()
            .map(|(k, _)| match k {
                Value::Text(t) => t.clone(),
                other => panic!("non-text key {other:?}"),
            })
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, map_keys(&snap.served_body_cbor().unwrap()));
    }

    /// NEGATIVE CONTROL — an unsigned map missing `snapshot_body` signs a
    /// strictly weaker statement and still verifies against itself.
    #[test]
    fn dropping_snapshot_body_from_the_unsigned_map_changes_the_preimage() {
        let (key, cert) = signer();
        let snap = snapshot(1);
        let available = build_signed_evidence(
            RosterEvidenceOutcome::Available,
            [7u8; 32],
            &cert,
            &key,
            Some(&snap),
        )
        .unwrap();
        let mut stripped = available.clone();
        stripped.snapshot_body = None;
        stripped.state_evidence_digest = None;
        stripped.full_snapshot_digest = None;
        assert_ne!(
            signing_preimage(&available).unwrap(),
            signing_preimage(&stripped).unwrap()
        );
    }

    /// NEGATIVE CONTROL — the historical bstr form is internally coherent:
    /// a signature made over those wrong bytes verifies against those same
    /// bytes. It must not verify against the frozen map-form preimage.
    #[test]
    fn a_bstr_body_signature_does_not_verify_against_the_map_body_preimage() {
        #[derive(Serialize)]
        struct EvidenceUnsignedBstr<'a> {
            #[serde(with = "bstr32")]
            client_nonce: [u8; 32],
            full_snapshot_digest: &'a serde_bytes::Bytes,
            outcome: &'a str,
            #[serde(with = "bstr_var")]
            signer_machine_cert: Vec<u8>,
            #[serde(with = "bstr32")]
            signer_machine_cert_fingerprint: [u8; 32],
            signer_m_id: &'a str,
            snapshot_body: &'a serde_bytes::Bytes,
            state_evidence_digest: &'a serde_bytes::Bytes,
            v: u8,
        }

        let (key, cert) = signer();
        let snap = snapshot(1);
        let evidence = build_signed_evidence(
            RosterEvidenceOutcome::Available,
            [7u8; 32],
            &cert,
            &key,
            Some(&snap),
        )
        .unwrap();
        let wrong_snapshot_body =
            crate::cbor::to_canonical_vec(evidence.snapshot_body.as_ref().unwrap()).unwrap();
        let wrong_unsigned = EvidenceUnsignedBstr {
            client_nonce: evidence.client_nonce,
            full_snapshot_digest: serde_bytes::Bytes::new(
                evidence.full_snapshot_digest.as_ref().unwrap(),
            ),
            outcome: evidence.outcome.wire_str(),
            signer_machine_cert: evidence.signer_machine_cert.clone(),
            signer_machine_cert_fingerprint: evidence.signer_machine_cert_fingerprint,
            signer_m_id: &evidence.signer_m_id,
            snapshot_body: serde_bytes::Bytes::new(&wrong_snapshot_body),
            state_evidence_digest: serde_bytes::Bytes::new(
                evidence.state_evidence_digest.as_ref().unwrap(),
            ),
            v: EVIDENCE_VERSION,
        };
        let mut wrong_preimage = EVIDENCE_DOMAIN.to_vec();
        wrong_preimage.extend_from_slice(&crate::cbor::to_canonical_vec(&wrong_unsigned).unwrap());
        let wrong_signature = key.sign(&wrong_preimage).unwrap();

        crate::keys::verify_signature(&cert.m_pub, &wrong_preimage, &wrong_signature).unwrap();
        let correct_preimage = signing_preimage(&evidence).unwrap();
        assert_ne!(wrong_preimage, correct_preimage);
        assert!(
            crate::keys::verify_signature(&cert.m_pub, &correct_preimage, &wrong_signature)
                .is_err()
        );
    }

    #[test]
    fn presence_mismatch_between_outcome_and_snapshot_is_refused() {
        let (key, cert) = signer();
        let snap = snapshot(1);
        assert!(
            build_signed_evidence(
                RosterEvidenceOutcome::UnavailableClockState,
                [1u8; 32],
                &cert,
                &key,
                Some(&snap)
            )
            .is_err(),
            "an unavailable must never carry a body"
        );
        assert!(
            build_signed_evidence(
                RosterEvidenceOutcome::Available,
                [1u8; 32],
                &cert,
                &key,
                None
            )
            .is_err(),
            "an available must never be served without a body"
        );
    }

    // ── signature ──────────────────────────────────────────────────────────

    #[test]
    fn the_signature_verifies_under_the_signer_key() {
        let (key, cert) = signer();
        let snap = snapshot(2);
        let evidence = build_signed_evidence(
            RosterEvidenceOutcome::Available,
            [3u8; 32],
            &cert,
            &key,
            Some(&snap),
        )
        .unwrap();
        let preimage = signing_preimage(&evidence).unwrap();
        crate::keys::verify_signature(&cert.m_pub, &preimage, &evidence.signature).unwrap();
        assert_eq!(evidence.signer_m_id, cert.m_id.to_string());
        assert_eq!(
            evidence.signer_machine_cert_fingerprint,
            machine_cert_fingerprint(&cert).unwrap()
        );
    }

    /// NEGATIVE CONTROL — exercises the VERIFIER, never the producer. The
    /// standalone keypair never reaches a signing path; it exists so
    /// "the signature verified" cannot be a vacuous assertion.
    #[test]
    fn a_signature_from_another_key_does_not_verify() {
        let (key, cert) = signer();
        let evidence = build_signed_evidence(
            RosterEvidenceOutcome::UnavailableOwnerAuthority,
            [5u8; 32],
            &cert,
            &key,
            None,
        )
        .unwrap();
        let preimage = signing_preimage(&evidence).unwrap();
        let stranger = P256Keypair::generate();
        let forged = stranger.sign(&preimage).unwrap();
        assert!(crate::keys::verify_signature(&cert.m_pub, &preimage, &forged).is_err());
        // ...and the genuine one still verifies, so the negative is not passing
        // because verification is broken outright.
        crate::keys::verify_signature(&cert.m_pub, &preimage, &evidence.signature).unwrap();
    }

    #[test]
    fn the_client_nonce_is_echoed_into_the_signed_map() {
        let (key, cert) = signer();
        let nonce = [0xAB; 32];
        let evidence = build_signed_evidence(
            RosterEvidenceOutcome::UnavailableCheckpointStale,
            nonce,
            &cert,
            &key,
            None,
        )
        .unwrap();
        assert_eq!(evidence.client_nonce, nonce);
        let preimage = signing_preimage(&evidence).unwrap();
        assert!(
            preimage.windows(nonce.len()).any(|window| window == nonce),
            "the nonce must be inside the signed preimage"
        );
    }
}
