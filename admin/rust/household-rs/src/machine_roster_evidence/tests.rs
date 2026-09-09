#![cfg(test)]

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
        map_keys(&snap.served_body_cbor().unwrap()).contains(&"predecessor_checkpoint".to_string())
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
        crate::keys::verify_signature(&cert.m_pub, &correct_preimage, &wrong_signature).is_err()
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
