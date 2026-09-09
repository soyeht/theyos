#![cfg(test)]

use super::*;

// ─── Lane R (@ilia): membership-key projection REDs ─────────────────

#[cfg(feature = "mesh-session-runtime")]
#[allow(clippy::too_many_arguments)]
fn membership_test_snapshot(
    hh_id: &str,
    m_id: &str,
    fingerprint: [u8; 32],
    checkpoint_hash: [u8; 32],
    checkpoint_sequence: u64,
    revoked: bool,
) -> RosterSnapshotView {
    let hh_id = HouseholdId(hh_id.to_string());
    let machine_id = MachineId(m_id.to_string());
    let active = if revoked {
        Vec::new()
    } else {
        vec![MachineRosterMemberV1 {
            m_id: machine_id.clone(),
            m_pub: crate::keys::P256PublicKey([0x02; 33]),
            machine_cert: Vec::new(),
            machine_cert_fingerprint: fingerprint,
        }]
    };
    let tombstones = if revoked {
        vec![MachineRosterRevocationV1 {
            v: 1,
            kind: "machine_roster_revocation_v1".to_string(),
            hh_id: hh_id.clone(),
            epoch: [1u8; 32],
            sequence: 1,
            prev_event_hash: [0u8; 32],
            m_id: machine_id.clone(),
            m_pub: crate::keys::P256PublicKey([0x02; 33]),
            machine_cert_fingerprint: fingerprint,
            revoked_at: 1,
            reason: RevocationReason::OwnerAction,
            cascade: RevocationCascade::MachineOnly,
            owner_p_id: crate::machine_cert::PersonId("owner".to_string()),
            owner_cert_fingerprint: [4u8; 32],
            owner_person_cert: Vec::new(),
            signature: crate::keys::P256Signature([7u8; 64]),
        }]
    } else {
        Vec::new()
    };
    let data = AcceptedRosterData {
        epoch: [1u8; 32],
        checkpoint_sequence,
        checkpoint_hash,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 1,
        event_head_hash: [3u8; 32],
        predecessor_event_sequence: 0,
        predecessor_event_head_hash: [0u8; 32],
        issued_at: 1,
        not_after: u64::MAX,
        owner_cert_fingerprint: [4u8; 32],
        genesis_basis: VerifiedGenesisRoster {
            epoch: [1u8; 32],
            members: Vec::new(),
        },
        active,
        tombstones,
    };
    RosterSnapshotView::project(&hh_id, &data)
}

/// Real `D1MembershipKey`, via the `test-support`-gated escape hatch
/// — every field-mismatch RED below drives the REAL public
/// `SealedBinding::from_membership_key` wrapper, not the private
/// `validate_membership_fields` helper alone. A test that only
/// exercises a helper parallel to the caller cannot catch the caller
/// itself (@ilia) — if the wrapper ever mis-ordered its own field
/// extraction or passed the wrong accessor to the helper, these REDs
/// would still catch it; the earlier helper-only version could not.
/// `session_id` is a fixed, arbitrary fixture value — it is read by
/// nothing on either side of this call chain (see this section's own
/// module doc for why).
#[cfg(feature = "mesh-session-runtime")]
fn membership_key_for_test(
    hh_id: &str,
    peer_m_id: &str,
    peer_cert_fingerprint: [u8; 32],
    checkpoint_hash: [u8; 32],
    checkpoint_sequence: u64,
) -> mesh_session_core_rs::intent::D1MembershipKey {
    mesh_session_core_rs::intent::D1MembershipKey::new_for_test(
        b"fixture-session-id".to_vec(),
        hh_id.to_string(),
        peer_m_id.to_string(),
        peer_cert_fingerprint.to_vec(),
        checkpoint_hash.to_vec(),
        checkpoint_sequence,
    )
}

#[cfg(feature = "mesh-session-runtime")]
#[test]
fn membership_key_all_fields_match_produces_sealed_binding() {
    let snapshot =
        membership_test_snapshot("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7, false);
    let key = membership_key_for_test("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7);
    let bound = SealedBinding::from_membership_key(&key, &snapshot).unwrap();
    assert_eq!(bound.hh_id().0, "hh-runtime-1");
    assert_eq!(bound.m_id().0, "m-1");
    assert_eq!(bound.machine_cert_fingerprint(), [0xAAu8; 32]);
    assert_eq!(bound.checkpoint_hash(), [0xCCu8; 32]);
    assert_eq!(bound.checkpoint_sequence(), 7);
}

#[cfg(feature = "mesh-session-runtime")]
#[test]
fn red_membership_key_hh_id_mismatch_rejected() {
    let snapshot =
        membership_test_snapshot("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7, false);
    let key = membership_key_for_test("hh-DIFFERENT", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7);
    let err = SealedBinding::from_membership_key(&key, &snapshot).unwrap_err();
    assert_eq!(err, MembershipKeyRejected);
}

#[cfg(feature = "mesh-session-runtime")]
#[test]
fn red_membership_key_unknown_peer_m_id_rejected() {
    let snapshot =
        membership_test_snapshot("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7, false);
    let key = membership_key_for_test(
        "hh-runtime-1",
        "m-DOES-NOT-EXIST",
        [0xAAu8; 32],
        [0xCCu8; 32],
        7,
    );
    let err = SealedBinding::from_membership_key(&key, &snapshot).unwrap_err();
    assert_eq!(err, MembershipKeyRejected);
}

#[cfg(feature = "mesh-session-runtime")]
#[test]
fn red_membership_key_fingerprint_mismatch_rejected() {
    let snapshot =
        membership_test_snapshot("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7, false);
    let key = membership_key_for_test("hh-runtime-1", "m-1", [0xFFu8; 32], [0xCCu8; 32], 7);
    let err = SealedBinding::from_membership_key(&key, &snapshot).unwrap_err();
    assert_eq!(err, MembershipKeyRejected);
}

#[cfg(feature = "mesh-session-runtime")]
#[test]
fn red_membership_key_checkpoint_hash_mismatch_rejected() {
    let snapshot =
        membership_test_snapshot("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7, false);
    let key = membership_key_for_test("hh-runtime-1", "m-1", [0xAAu8; 32], [0xEEu8; 32], 7);
    let err = SealedBinding::from_membership_key(&key, &snapshot).unwrap_err();
    assert_eq!(err, MembershipKeyRejected);
}

#[cfg(feature = "mesh-session-runtime")]
#[test]
fn red_membership_key_checkpoint_sequence_mismatch_rejected() {
    let snapshot =
        membership_test_snapshot("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7, false);
    let key = membership_key_for_test("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 999);
    let err = SealedBinding::from_membership_key(&key, &snapshot).unwrap_err();
    assert_eq!(err, MembershipKeyRejected);
}

#[cfg(feature = "mesh-session-runtime")]
#[test]
fn red_membership_key_revoked_rejected() {
    let snapshot =
        membership_test_snapshot("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7, true);
    let key = membership_key_for_test("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7);
    let err = SealedBinding::from_membership_key(&key, &snapshot).unwrap_err();
    assert_eq!(err, MembershipKeyRejected);
}

/// Key minted against an OLDER checkpoint (seq 7) is rejected once the
/// roster has genuinely advanced (seq 8) — even though it would have
/// been accepted against the exact snapshot it was minted for. Proves
/// temporal correctness, not just flat field equality.
#[cfg(feature = "mesh-session-runtime")]
#[test]
fn red_membership_key_stale_against_advanced_roster_rejected() {
    let old_snapshot =
        membership_test_snapshot("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7, false);
    let key = membership_key_for_test("hh-runtime-1", "m-1", [0xAAu8; 32], [0xCCu8; 32], 7);
    SealedBinding::from_membership_key(&key, &old_snapshot).unwrap();

    let advanced_snapshot =
        membership_test_snapshot("hh-runtime-1", "m-1", [0xAAu8; 32], [0xDDu8; 32], 8, false);
    let err = SealedBinding::from_membership_key(&key, &advanced_snapshot).unwrap_err();
    assert_eq!(err, MembershipKeyRejected);
}

/// Pins the ONE half of the declared partition (@ilia audit of
/// `29dc6139`, narrowed by @zain's structural analysis) that actually
/// needs pinning — `is_revoked`'s position relative to the 4
/// unconditional field comparisons.
///
/// **The `lookup_active` → `fingerprint_matches` order is NOT pinned
/// here, deliberately: it needs no pin at all.** `fingerprint_matches`
/// reads `member.machine_cert_fingerprint()`, and `member` is exactly
/// `lookup_active`'s own return value — this is a DATA dependency the
/// compiler enforces; `lookup_active` cannot be moved after that
/// comparison because the value it produces would not exist yet.
/// Pinning something the type system already guarantees would
/// wrongly imply this test is what secures it.
///
/// **`is_revoked` has no such dependency** — nothing downstream reads
/// its result besides the early return itself, so it could freely
/// move to after the 4 comparisons and the code would still compile.
/// Moving it is also BEHAVIORALLY UNOBSERVABLE: the error stays the
/// same fieldless `MembershipKeyRejected` either way, so no black-box
/// call sequence can distinguish the two orderings by return value —
/// which is exactly why a source-position pin is the only proof
/// available for this half, not a weaker substitute for something
/// free elsewhere.
///
/// **`include_str!` limitation, stated plainly:** this reads the
/// current SOURCE FILE at compile time — it proves what the source
/// says, not what the compiled binary does. Accepted here only
/// because this test lives in the same crate and recompiles whenever
/// the source it reads changes; a copy or a stale build would not be
/// covered.
#[cfg(feature = "mesh-session-runtime")]
#[test]
fn membership_key_is_revoked_check_precedes_field_comparisons() {
    let source = include_str!("../machine_roster_authority.rs");
    let fn_start = source
        .find("fn validate_membership_fields(")
        .expect("validate_membership_fields must exist");
    let fn_body = &source[fn_start..];
    let fn_end = fn_body
        .find("\n}\n")
        .expect("validate_membership_fields must have a closing brace");
    let fn_body = &fn_body[..fn_end];

    let revoked_check = fn_body
        .find("snapshot.is_revoked(")
        .expect("revoked check must exist in validate_membership_fields");

    // @khai's cross-audit (2026-08-05): anchoring on `hh_id_matches`
    // alone only proved `is_revoked` precedes ONE of the four
    // comparisons, not all of them, despite the assertion's own name
    // claiming "field comparisons" plural. A mutant that reorders the
    // four so `hh_id_matches` sits last (with `is_revoked` moved to
    // after the other three but still before `hh_id_matches`) left
    // this pin green while `is_revoked` had already stopped preceding
    // 3 of the 4. Anchoring on the MINIMUM of all four indices closes
    // that gap — `is_revoked` must precede every one of them, not just
    // whichever one this pin happened to name.
    let earliest_field_comparison = [
        "let hh_id_matches",
        "let fingerprint_matches",
        "let checkpoint_hash_matches",
        "let checkpoint_sequence_matches",
    ]
    .into_iter()
    .map(|needle| {
        fn_body.find(needle).unwrap_or_else(|| {
            panic!("{needle} comparison must exist in validate_membership_fields")
        })
    })
    .min()
    .expect("four comparisons are listed above, so a minimum always exists");

    assert!(
        revoked_check < earliest_field_comparison,
        "is_revoked has no data dependency forcing this order — unlike lookup_active, whose \
             result the field comparisons directly consume — so this position is not \
             compiler-guaranteed and needs this explicit pin. It must precede ALL FOUR field \
             comparisons, not just one of them. If this genuinely changed, update it deliberately, \
             not by accident."
    );
}

// Local wrappers preserving old call signatures for tests
fn sign_revocation(
    r: &mut MachineRosterRevocationV1,
    owner_key: &dyn crate::keys::IdentityKey,
    cert_bytes: &[u8],
    hh: &HouseholdId,
    hh_pub: &P256PublicKey,
    p_id: &PersonId,
    p_pub: &P256PublicKey,
    now: u64,
) -> Result<(), RosterCryptoError> {
    let ctx = RosterAuthorityContext {
        hh_pub,
        expected_hh_id: hh,
        expected_p_id: p_id,
        expected_p_pub: p_pub,
        effective_now: now,
    };
    super::sign_revocation(r, owner_key, cert_bytes, &ctx)
}

fn sign_checkpoint(
    c: &mut MachineRosterCheckpointV1,
    owner_key: &dyn crate::keys::IdentityKey,
    cert_bytes: &[u8],
    hh: &HouseholdId,
    hh_pub: &P256PublicKey,
    p_id: &PersonId,
    p_pub: &P256PublicKey,
    now: u64,
) -> Result<(), RosterCryptoError> {
    let ctx = RosterAuthorityContext {
        hh_pub,
        expected_hh_id: hh,
        expected_p_id: p_id,
        expected_p_pub: p_pub,
        effective_now: now,
    };
    super::sign_checkpoint(c, owner_key, cert_bytes, &ctx)
}

fn verify_revocation_authority(
    r: &MachineRosterRevocationV1,
    hh: &HouseholdId,
    hh_pub: &P256PublicKey,
    p_id: &PersonId,
    p_pub: &P256PublicKey,
    now: u64,
) -> Result<(), RosterCryptoError> {
    let ctx = RosterAuthorityContext {
        hh_pub,
        expected_hh_id: hh,
        expected_p_id: p_id,
        expected_p_pub: p_pub,
        effective_now: now,
    };
    super::verify_revocation_authority(r, &ctx)
}

fn verify_checkpoint_authority(
    c: &MachineRosterCheckpointV1,
    hh: &HouseholdId,
    hh_pub: &P256PublicKey,
    p_id: &PersonId,
    p_pub: &P256PublicKey,
    now: u64,
) -> Result<(), RosterCryptoError> {
    let ctx = RosterAuthorityContext {
        hh_pub,
        expected_hh_id: hh,
        expected_p_id: p_id,
        expected_p_pub: p_pub,
        effective_now: now,
    };
    super::verify_checkpoint_authority(c, &ctx)
}
use crate::cbor;
use crate::keys::IdentityKey as _;

const SCALAR_A: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const SCALAR_B: [u8; 32] = [
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn det_pub(s: &[u8; 32]) -> P256PublicKey {
    crate::keys::P256Keypair::from_secret_scalar(s)
        .unwrap()
        .public()
}

fn test_member() -> MachineRosterMemberV1 {
    let pk = det_pub(&SCALAR_A);
    MachineRosterMemberV1 {
        m_id: crate::ids::derive_machine_id(&pk),
        m_pub: pk,
        machine_cert: vec![1, 2, 3],
        machine_cert_fingerprint: [0xAB; 32],
    }
}

fn test_revocation() -> MachineRosterRevocationV1 {
    let rp = det_pub(&SCALAR_A);
    let mp = det_pub(&SCALAR_B);
    MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: crate::ids::derive_household_id(&rp),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id: crate::ids::derive_machine_id(&mp),
        m_pub: mp,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: PersonId("p_owner".into()),
        owner_cert_fingerprint: [0xCC; 32],
        owner_person_cert: vec![4, 5, 6],
        signature: P256Signature([0u8; 64]),
    }
}

fn test_checkpoint() -> MachineRosterCheckpointV1 {
    let rp = det_pub(&SCALAR_A);
    MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: crate::ids::derive_household_id(&rp),
        epoch: [0xAA; 32],
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0xDD; 32],
        issued_at: 1000,
        not_after: 1300,
        owner_p_id: PersonId("p_owner".into()),
        owner_cert_fingerprint: [0xCC; 32],
        active: vec![test_member()],
        revocations: vec![],
        owner_person_cert: vec![7, 8, 9],
        signature: P256Signature([0u8; 64]),
    }
}

fn inject_extra_and_assert_reject<T: for<'de> Deserialize<'de> + Serialize>(val: &T) {
    let bytes = cbor::to_canonical_vec(val).unwrap();
    let mut v: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut e) = v {
        e.push((
            ciborium::value::Value::Text("extra".into()),
            ciborium::value::Value::Null,
        ));
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf).unwrap();
    assert!(cbor::from_canonical_slice::<T>(&buf).is_err());
}

fn remove_field_and_assert_reject<T: for<'de> Deserialize<'de> + Serialize>(val: &T, field: &str) {
    let bytes = cbor::to_canonical_vec(val).unwrap();
    let mut v: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut e) = v {
        e.retain(|(k, _)| *k != ciborium::value::Value::Text(field.into()));
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf).unwrap();
    assert!(cbor::from_canonical_slice::<T>(&buf).is_err());
}

fn set_field_null_and_assert_reject<T: for<'de> Deserialize<'de> + Serialize>(
    val: &T,
    field: &str,
) {
    let bytes = cbor::to_canonical_vec(val).unwrap();
    let mut v: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut e) = v {
        for (k, fv) in e.iter_mut() {
            if *k == ciborium::value::Value::Text(field.into()) {
                *fv = ciborium::value::Value::Null;
            }
        }
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf).unwrap();
    assert!(cbor::from_canonical_slice::<T>(&buf).is_err());
}

fn set_field_array_and_assert_reject<T: for<'de> Deserialize<'de> + Serialize>(
    val: &T,
    field: &str,
    len: usize,
) {
    let bytes = cbor::to_canonical_vec(val).unwrap();
    let mut v: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut e) = v {
        for (k, fv) in e.iter_mut() {
            if *k == ciborium::value::Value::Text(field.into()) {
                *fv = ciborium::value::Value::Array(vec![
                    ciborium::value::Value::Integer(0.into());
                    len
                ]);
            }
        }
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf).unwrap();
    assert!(cbor::from_canonical_slice::<T>(&buf).is_err());
}

fn set_field_wrong_len_and_assert_reject<T: for<'de> Deserialize<'de> + Serialize>(
    val: &T,
    field: &str,
    len: usize,
) {
    let bytes = cbor::to_canonical_vec(val).unwrap();
    let mut v: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut e) = v {
        for (k, fv) in e.iter_mut() {
            if *k == ciborium::value::Value::Text(field.into()) {
                *fv = ciborium::value::Value::Bytes(vec![0u8; len]);
            }
        }
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf).unwrap();
    assert!(cbor::from_canonical_slice::<T>(&buf).is_err());
}

// ─── Enum tests ─────────────────────────────────────────────────────────

#[test]
fn reason_roundtrip_exact_uint() {
    for (v, e) in [
        (0, RevocationReason::Compromised),
        (1, RevocationReason::Lost),
        (2, RevocationReason::Retired),
        (3, RevocationReason::Replaced),
        (4, RevocationReason::OwnerAction),
    ] {
        let b = cbor::to_canonical_vec(&e).unwrap();
        assert_eq!(b, vec![v]);
        assert_eq!(
            cbor::from_canonical_slice::<RevocationReason>(&b).unwrap(),
            e
        );
    }
    for bad in [5u8, 100, 255] {
        assert!(
            cbor::from_canonical_slice::<RevocationReason>(&cbor::to_canonical_vec(&bad).unwrap())
                .is_err()
        );
    }
}

#[test]
fn cascade_roundtrip_exact_uint() {
    assert_eq!(
        cbor::to_canonical_vec(&RevocationCascade::MachineOnly).unwrap(),
        vec![0u8]
    );
    assert_eq!(
        cbor::to_canonical_vec(&RevocationCascade::MachineAndDependents).unwrap(),
        vec![1u8]
    );
    assert!(
        cbor::from_canonical_slice::<RevocationCascade>(&cbor::to_canonical_vec(&2u8).unwrap())
            .is_err()
    );
}

// ─── Roundtrip ──────────────────────────────────────────────────────────

#[test]
fn member_roundtrip() {
    let m = test_member();
    assert_eq!(
        cbor::from_canonical_slice::<MachineRosterMemberV1>(&cbor::to_canonical_vec(&m).unwrap())
            .unwrap(),
        m
    );
}
#[test]
fn revocation_roundtrip() {
    let r = test_revocation();
    assert_eq!(
        cbor::from_canonical_slice::<MachineRosterRevocationV1>(
            &cbor::to_canonical_vec(&r).unwrap()
        )
        .unwrap(),
        r
    );
}
#[test]
fn checkpoint_roundtrip() {
    let c = test_checkpoint();
    assert_eq!(
        cbor::from_canonical_slice::<MachineRosterCheckpointV1>(
            &cbor::to_canonical_vec(&c).unwrap()
        )
        .unwrap(),
        c
    );
}

// ─── Exact key sets ─────────────────────────────────────────────────────

fn map_key_names<T: Serialize>(val: &T) -> Vec<String> {
    let bytes = cbor::to_canonical_vec(val).unwrap();
    let v: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    match v {
        ciborium::value::Value::Map(e) => e
            .iter()
            .map(|(k, _)| match k {
                ciborium::value::Value::Text(s) => s.clone(),
                _ => panic!(),
            })
            .collect(),
        _ => panic!(),
    }
}

#[test]
fn member_exact_4_key_names() {
    let mut keys = map_key_names(&test_member());
    keys.sort();
    assert_eq!(
        keys,
        vec!["m_id", "m_pub", "machine_cert", "machine_cert_fingerprint"]
    );
}
#[test]
fn revocation_exact_16_key_names() {
    let mut keys = map_key_names(&test_revocation());
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "cascade",
            "epoch",
            "hh_id",
            "kind",
            "m_id",
            "m_pub",
            "machine_cert_fingerprint",
            "owner_cert_fingerprint",
            "owner_p_id",
            "owner_person_cert",
            "prev_event_hash",
            "reason",
            "revoked_at",
            "sequence",
            "signature",
            "v"
        ]
    );
}
#[test]
fn checkpoint_exact_17_key_names() {
    let mut keys = map_key_names(&test_checkpoint());
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "active",
            "checkpoint_sequence",
            "epoch",
            "event_head_hash",
            "event_sequence",
            "hh_id",
            "issued_at",
            "kind",
            "mesh_log_digest",
            "not_after",
            "owner_cert_fingerprint",
            "owner_p_id",
            "owner_person_cert",
            "prev_checkpoint_hash",
            "revocations",
            "signature",
            "v"
        ]
    );
}

// ─── Deny unknown (from valid map) ──────────────────────────────────────

#[test]
fn member_deny_unknown() {
    inject_extra_and_assert_reject(&test_member());
}
#[test]
fn revocation_deny_unknown() {
    inject_extra_and_assert_reject(&test_revocation());
}
#[test]
fn checkpoint_deny_unknown() {
    inject_extra_and_assert_reject(&test_checkpoint());
}

// ─── Missing field ──────────────────────────────────────────────────────

#[test]
fn member_missing_fingerprint() {
    remove_field_and_assert_reject(&test_member(), "machine_cert_fingerprint");
}
#[test]
fn revocation_missing_epoch() {
    remove_field_and_assert_reject(&test_revocation(), "epoch");
}
#[test]
fn checkpoint_missing_not_after() {
    remove_field_and_assert_reject(&test_checkpoint(), "not_after");
}

// ─── Null reject ────────────────────────────────────────────────────────

#[test]
fn member_null_fingerprint() {
    set_field_null_and_assert_reject(&test_member(), "machine_cert_fingerprint");
}
#[test]
fn revocation_null_epoch() {
    set_field_null_and_assert_reject(&test_revocation(), "epoch");
}
#[test]
fn checkpoint_null_epoch() {
    set_field_null_and_assert_reject(&test_checkpoint(), "epoch");
}
#[test]
fn member_null_m_pub() {
    set_field_null_and_assert_reject(&test_member(), "m_pub");
}
#[test]
fn revocation_null_signature() {
    set_field_null_and_assert_reject(&test_revocation(), "signature");
}

// ─── Array-vs-bstr reject ───────────────────────────────────────────────

#[test]
fn member_array_fingerprint() {
    set_field_array_and_assert_reject(&test_member(), "machine_cert_fingerprint", 32);
}
#[test]
fn member_array_m_pub() {
    set_field_array_and_assert_reject(&test_member(), "m_pub", 33);
}
#[test]
fn member_array_machine_cert() {
    set_field_array_and_assert_reject(&test_member(), "machine_cert", 3);
}
#[test]
fn revocation_array_epoch() {
    set_field_array_and_assert_reject(&test_revocation(), "epoch", 32);
}
#[test]
fn revocation_array_signature() {
    set_field_array_and_assert_reject(&test_revocation(), "signature", 64);
}
#[test]
fn checkpoint_array_owner_cert() {
    set_field_array_and_assert_reject(&test_checkpoint(), "owner_person_cert", 3);
}

// ─── Wrong bstr length (fixed only) ─────────────────────────────────────

#[test]
fn member_wrong_len_fingerprint_31() {
    set_field_wrong_len_and_assert_reject(&test_member(), "machine_cert_fingerprint", 31);
}
#[test]
fn member_wrong_len_fingerprint_33() {
    set_field_wrong_len_and_assert_reject(&test_member(), "machine_cert_fingerprint", 33);
}
#[test]
fn member_wrong_len_m_pub_32() {
    set_field_wrong_len_and_assert_reject(&test_member(), "m_pub", 32);
}
#[test]
fn member_wrong_len_m_pub_34() {
    set_field_wrong_len_and_assert_reject(&test_member(), "m_pub", 34);
}
#[test]
fn revocation_wrong_len_epoch_31() {
    set_field_wrong_len_and_assert_reject(&test_revocation(), "epoch", 31);
}
#[test]
fn revocation_wrong_len_signature_63() {
    set_field_wrong_len_and_assert_reject(&test_revocation(), "signature", 63);
}
#[test]
fn revocation_wrong_len_signature_65() {
    set_field_wrong_len_and_assert_reject(&test_revocation(), "signature", 65);
}
#[test]
fn checkpoint_wrong_len_mesh_digest_31() {
    set_field_wrong_len_and_assert_reject(&test_checkpoint(), "mesh_log_digest", 31);
}

#[test]
fn member_null_machine_cert() {
    set_field_null_and_assert_reject(&test_member(), "machine_cert");
}
#[test]
fn revocation_null_owner_person_cert() {
    set_field_null_and_assert_reject(&test_revocation(), "owner_person_cert");
}
#[test]
fn checkpoint_null_owner_person_cert() {
    set_field_null_and_assert_reject(&test_checkpoint(), "owner_person_cert");
}

#[test]
fn member_m_pub_off_curve_04_prefix() {
    let bytes = cbor::to_canonical_vec(&test_member()).unwrap();
    let mut v: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut e) = v {
        for (k, fv) in e.iter_mut() {
            if *k == ciborium::value::Value::Text("m_pub".into()) {
                let mut bad = [0x04u8; 33];
                bad[0] = 0x04;
                *fv = ciborium::value::Value::Bytes(bad.to_vec());
            }
        }
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf).unwrap();
    assert!(cbor::from_canonical_slice::<MachineRosterMemberV1>(&buf).is_err());
}

#[test]
fn revocation_m_pub_all_zeros_off_curve() {
    let bytes = cbor::to_canonical_vec(&test_revocation()).unwrap();
    let mut v: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut e) = v {
        for (k, fv) in e.iter_mut() {
            if *k == ciborium::value::Value::Text("m_pub".into()) {
                *fv = ciborium::value::Value::Bytes(vec![0u8; 33]);
            }
        }
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf).unwrap();
    assert!(cbor::from_canonical_slice::<MachineRosterRevocationV1>(&buf).is_err());
}

// ─── CP2 crypto/authority tests ─────────────────────────────────────────

fn det_kp(s: &[u8; 32]) -> crate::keys::P256Keypair {
    crate::keys::P256Keypair::from_secret_scalar(s).unwrap()
}

fn make_owner_cert(
    root_kp: &crate::keys::P256Keypair,
    owner_pub: &P256PublicKey,
    hh_id: &HouseholdId,
) -> crate::person_cert::PersonCert {
    let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
        root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 1000,
        },
        crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    cert.nonce = vec![
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C,
    ];
    // Pin every field the byte-exact vectors below depend on. The random
    // nonce is one; `not_before` became another when minting started
    // backdating it by a clock-skew allowance. That allowance is POLICY,
    // and these vectors exist to pin the preimage's SHAPE — a domain
    // separator, a key order, an encoding. Normalising it here keeps them
    // measuring that, instead of turning every future change to the
    // allowance into two hashes to re-record by hand.
    cert.not_before = cert.issued_at;
    let sb = cert.signing_bytes().unwrap();
    cert.signature = root_kp.sign(&sb).unwrap();
    cert
}

fn make_machine_cert(
    root_kp: &crate::keys::P256Keypair,
    m_pub: &P256PublicKey,
    hh_id: &HouseholdId,
) -> crate::machine_cert::MachineCert {
    crate::machine_cert::MachineCert::sign(
        root_kp,
        m_pub,
        &crate::machine_cert::SignOptions {
            hh_id: hh_id.clone(),
            hostname: "test-host".into(),
            platform: crate::machine_cert::Platform::Macos,
            joined_at: 1000,
        },
    )
    .unwrap()
}

/// The roster wire's `machine_cert_fingerprint` and the pair-device QR's
/// `m_cert_fp` must be the same bytes for the same cert. Delegation makes
/// that true today; this pins it so a future edit that re-inlines the hash
/// here — a different domain separator, a different encoding — fails
/// loudly instead of shipping two fingerprints that quietly disagree.
#[test]
fn roster_and_qr_fingerprints_are_the_same_value() {
    let root_kp = det_kp(&SCALAR_A);
    let hh = crate::ids::derive_household_id(&root_kp.public());
    let m_kp = det_kp(&SCALAR_B);
    let cert = make_machine_cert(&root_kp, &m_kp.public(), &hh);
    assert_eq!(
        machine_cert_fingerprint(&cert).expect("roster fingerprint"),
        crate::machine_cert::fingerprint(&cert).expect("qr fingerprint"),
    );
}

fn owner_cert_bytes(cert: &crate::person_cert::PersonCert) -> Vec<u8> {
    crate::cbor::to_canonical_vec(cert).unwrap()
}

// ─── Preimage/hash byte-exact + domain separation ───────────────────────

#[test]
fn revocation_preimage_domain_and_determinism() {
    let r = test_revocation();
    let p = revocation_preimage(&r).unwrap();
    assert!(p.starts_with(b"soyeht/household-machine-roster-revocation/v1\x00"));
    assert_eq!(p, revocation_preimage(&r).unwrap());
}

#[test]
fn checkpoint_preimage_domain_and_determinism() {
    let c = test_checkpoint();
    let p = checkpoint_preimage(&c).unwrap();
    assert!(p.starts_with(b"soyeht/household-machine-roster-checkpoint/v1\x00"));
    assert_eq!(p, checkpoint_preimage(&c).unwrap());
}

#[test]
fn domain_separation_revocation_vs_checkpoint() {
    let r = test_revocation();
    let c = test_checkpoint();
    assert_ne!(
        revocation_preimage(&r).unwrap(),
        checkpoint_preimage(&c).unwrap()
    );
}

#[test]
fn event_hash_and_checkpoint_hash_deterministic_nonzero() {
    let r = test_revocation();
    let h = revocation_event_hash(&r).unwrap();
    assert_eq!(h, revocation_event_hash(&r).unwrap());
    assert_ne!(h, [0u8; 32]);
    let c = test_checkpoint();
    let ch = checkpoint_hash(&c).unwrap();
    assert_eq!(ch, checkpoint_hash(&c).unwrap());
    assert_ne!(ch, [0u8; 32]);
    assert_ne!(h, ch);
}

#[test]
fn preimage_rejects_wrong_version_and_kind() {
    let mut r = test_revocation();
    r.v = 2;
    assert_eq!(
        revocation_preimage(&r),
        Err(RosterCryptoError::SchemaInvalid)
    );
    r.v = REVOCATION_VERSION;
    r.kind = "bad".into();
    assert_eq!(
        revocation_preimage(&r),
        Err(RosterCryptoError::SchemaInvalid)
    );
    let mut c = test_checkpoint();
    c.v = 99;
    assert_eq!(
        checkpoint_preimage(&c),
        Err(RosterCryptoError::SchemaInvalid)
    );
    c.v = CHECKPOINT_VERSION;
    c.kind = "bad".into();
    assert_eq!(
        checkpoint_preimage(&c),
        Err(RosterCryptoError::SchemaInvalid)
    );
}

#[test]
fn epoch_deterministic_nonce_key_separation() {
    let pk = det_pub(&SCALAR_A);
    let hh = crate::ids::derive_household_id(&pk);
    let n1 = [1u8; 32];
    let n2 = [2u8; 32];
    assert_eq!(derive_epoch(&hh, &pk, &n1), derive_epoch(&hh, &pk, &n1));
    assert_ne!(derive_epoch(&hh, &pk, &n1), derive_epoch(&hh, &pk, &n2));
    assert_ne!(
        derive_epoch(&hh, &pk, &n1),
        derive_epoch(&hh, &det_pub(&SCALAR_B), &n1)
    );
}

// ─── Sign/verify through helpers with real PersonCert ───────────────────

#[test]
fn sign_verify_revocation_authority_green() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    )
    .unwrap();
    assert!(verify_revocation_authority(&r, &hh, &root_pub, &p_id, &owner_pub, 2000).is_ok());
}

#[test]
fn sign_verify_checkpoint_authority_green() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let mut c = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0xDD; 32],
        issued_at: 1000,
        not_after: 1300,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        active: vec![],
        revocations: vec![],
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut c,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        1000,
    )
    .unwrap();
    assert!(verify_checkpoint_authority(&c, &hh, &root_pub, &p_id, &owner_pub, 1000).is_ok());
}

#[test]
fn verify_revocation_tamper_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Lost,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    )
    .unwrap();
    let mut tampered = r.clone();
    tampered.sequence = 999;
    assert_eq!(
        verify_revocation_authority(&tampered, &hh, &root_pub, &p_id, &owner_pub, 2000),
        Err(RosterCryptoError::SignatureRejected)
    );
}

#[test]
fn sign_revocation_wrong_signer_pub_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let wrong_kp = det_kp(&[
        3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Retired,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let result = sign_revocation(
        &mut r,
        &wrong_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    );
    assert_eq!(result, Err(RosterCryptoError::SignerPubMismatch));
}

#[test]
fn sign_revocation_wrong_household_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let wrong_hh =
        HouseholdId("hh_wrong_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: wrong_hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::OwnerAction,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let result = sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &wrong_hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    );
    assert!(result.is_err());
}

#[test]
fn verify_wrong_owner_pub_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let wrong_pub = det_pub(&[
        4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    )
    .unwrap();
    assert_eq!(
        verify_revocation_authority(&r, &hh, &root_pub, &p_id, &wrong_pub, 2000),
        Err(RosterCryptoError::OwnerPubMismatch)
    );
}

#[test]
fn fingerprint_mismatch_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: [0xFF; 32],
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    )
    .unwrap();
    let mut bad = r.clone();
    bad.owner_cert_fingerprint = [0x00; 32];
    assert_eq!(
        verify_revocation_authority(&bad, &hh, &root_pub, &p_id, &owner_pub, 2000),
        Err(RosterCryptoError::FingerprintMismatch)
    );
}

// ─── Member provenance ──────────────────────────────────────────────────

#[test]
fn member_provenance_green() {
    let root_kp = det_kp(&SCALAR_A);
    let root_pub = root_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let m_kp = det_kp(&SCALAR_B);
    let m_pub = m_kp.public();
    let mcert = make_machine_cert(&root_kp, &m_pub, &hh);
    let mcert_bytes = crate::cbor::to_canonical_vec(&mcert).unwrap();
    let mfp = machine_cert_fingerprint(&mcert).unwrap();
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let member = MachineRosterMemberV1 {
        m_id,
        m_pub,
        machine_cert: mcert_bytes,
        machine_cert_fingerprint: mfp,
    };
    assert!(validate_member_provenance(&member, &root_pub, &hh).is_ok());
}

#[test]
fn member_provenance_wrong_root() {
    let root_kp = det_kp(&SCALAR_A);
    let wrong_root = det_kp(&[
        5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let root_pub = root_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let m_kp = det_kp(&SCALAR_B);
    let m_pub = m_kp.public();
    let mcert = make_machine_cert(&root_kp, &m_pub, &hh);
    let mcert_bytes = crate::cbor::to_canonical_vec(&mcert).unwrap();
    let mfp = machine_cert_fingerprint(&mcert).unwrap();
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let member = MachineRosterMemberV1 {
        m_id,
        m_pub,
        machine_cert: mcert_bytes,
        machine_cert_fingerprint: mfp,
    };
    let wrong_pub = wrong_root.public();
    assert_eq!(
        validate_member_provenance(&member, &wrong_pub, &hh),
        Err(RosterCryptoError::MachineCertInvalid)
    );
}

#[test]
fn member_provenance_wrong_fingerprint() {
    let root_kp = det_kp(&SCALAR_A);
    let root_pub = root_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let m_kp = det_kp(&SCALAR_B);
    let m_pub = m_kp.public();
    let mcert = make_machine_cert(&root_kp, &m_pub, &hh);
    let mcert_bytes = crate::cbor::to_canonical_vec(&mcert).unwrap();
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let member = MachineRosterMemberV1 {
        m_id,
        m_pub,
        machine_cert: mcert_bytes,
        machine_cert_fingerprint: [0xEE; 32],
    };
    assert_eq!(
        validate_member_provenance(&member, &root_pub, &hh),
        Err(RosterCryptoError::MachineFingerprintMismatch)
    );
}

#[test]
fn member_provenance_noncanonical_cert() {
    let root_kp = det_kp(&SCALAR_A);
    let root_pub = root_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let m_kp = det_kp(&SCALAR_B);
    let m_pub = m_kp.public();
    let mcert = make_machine_cert(&root_kp, &m_pub, &hh);
    let canonical_bytes = crate::cbor::to_canonical_vec(&mcert).unwrap();
    let mut val: ciborium::value::Value =
        ciborium::de::from_reader(canonical_bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut entries) = val {
        entries.reverse();
    }
    let mut noncanonical = Vec::new();
    ciborium::ser::into_writer(&val, &mut noncanonical).unwrap();
    assert_ne!(noncanonical, canonical_bytes);
    let mfp = machine_cert_fingerprint(&mcert).unwrap();
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let member = MachineRosterMemberV1 {
        m_id,
        m_pub,
        machine_cert: noncanonical,
        machine_cert_fingerprint: mfp,
    };
    assert_eq!(
        validate_member_provenance(&member, &root_pub, &hh),
        Err(RosterCryptoError::MachineCertNotCanonical)
    );
}

// ─── Schema gate ────────────────────────────────────────────────────────

#[test]
fn schema_gate_rejects_invalid_v_kind() {
    let mut r = test_revocation();
    r.v = 0;
    assert_eq!(
        check_revocation_schema(&r),
        Err(RosterCryptoError::SchemaInvalid)
    );
    let mut c = test_checkpoint();
    c.kind = "bad".into();
    assert_eq!(
        check_checkpoint_schema(&c),
        Err(RosterCryptoError::SchemaInvalid)
    );
}

// ─── CP2 matrix expansion ───────────────────────────────────────────────

#[test]
fn sign_fills_placeholder_owner_fields() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: PersonId("p_WRONG".into()),
        owner_cert_fingerprint: [0u8; 32],
        owner_person_cert: vec![],
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    )
    .unwrap();
    assert_eq!(r.owner_p_id, p_id);
    assert_eq!(r.owner_cert_fingerprint, fp);
    assert_eq!(r.owner_person_cert, cert_bytes);
    assert!(verify_revocation_authority(&r, &hh, &root_pub, &p_id, &owner_pub, 2000).is_ok());
}

#[test]
fn sign_household_mismatch_exact() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let wrong_hh =
        HouseholdId("hh_wrong_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: wrong_hh,
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Lost,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let result = sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    );
    assert_eq!(result, Err(RosterCryptoError::HouseholdMismatch));
}

#[test]
fn verify_wrong_root_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let wrong_root_kp = det_kp(&[
        5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    )
    .unwrap();
    let wrong_root_pub = wrong_root_kp.public();
    let result = verify_revocation_authority(&r, &hh, &wrong_root_pub, &p_id, &owner_pub, 2000);
    assert_eq!(result, Err(RosterCryptoError::OwnerCertInvalid));
}

#[test]
fn verify_wrong_active_p_id_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let wrong_p_id = PersonId("p_wrong_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    )
    .unwrap();
    let result = verify_revocation_authority(&r, &hh, &root_pub, &wrong_p_id, &owner_pub, 2000);
    assert_eq!(result, Err(RosterCryptoError::OwnerIdMismatch));
}

#[test]
fn checkpoint_tamper_signature_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let mut c = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0xDD; 32],
        issued_at: 1000,
        not_after: 1300,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        active: vec![],
        revocations: vec![],
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut c,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        1000,
    )
    .unwrap();
    let mut tampered = c.clone();
    tampered.issued_at = 9999;
    assert_eq!(
        verify_checkpoint_authority(&tampered, &hh, &root_pub, &p_id, &owner_pub, 1000),
        Err(RosterCryptoError::SignatureRejected)
    );
}

#[test]
fn member_provenance_household_mismatch() {
    let root_kp = det_kp(&SCALAR_A);
    let root_pub = root_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let wrong_hh =
        HouseholdId("hh_wrong_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    let m_kp = det_kp(&SCALAR_B);
    let m_pub = m_kp.public();
    let mcert = make_machine_cert(&root_kp, &m_pub, &hh);
    let mcert_bytes = crate::cbor::to_canonical_vec(&mcert).unwrap();
    let mfp = machine_cert_fingerprint(&mcert).unwrap();
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let member = MachineRosterMemberV1 {
        m_id,
        m_pub,
        machine_cert: mcert_bytes,
        machine_cert_fingerprint: mfp,
    };
    assert_eq!(
        validate_member_provenance(&member, &root_pub, &wrong_hh),
        Err(RosterCryptoError::MachineHouseholdMismatch)
    );
}

#[test]
fn member_provenance_m_id_mismatch() {
    let root_kp = det_kp(&SCALAR_A);
    let root_pub = root_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let m_kp = det_kp(&SCALAR_B);
    let m_pub = m_kp.public();
    let mcert = make_machine_cert(&root_kp, &m_pub, &hh);
    let mcert_bytes = crate::cbor::to_canonical_vec(&mcert).unwrap();
    let mfp = machine_cert_fingerprint(&mcert).unwrap();
    let wrong_m_id = MachineId("m_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    let member = MachineRosterMemberV1 {
        m_id: wrong_m_id,
        m_pub,
        machine_cert: mcert_bytes,
        machine_cert_fingerprint: mfp,
    };
    assert_eq!(
        validate_member_provenance(&member, &root_pub, &hh),
        Err(RosterCryptoError::MachineIdMismatch)
    );
}

#[test]
fn member_provenance_m_pub_mismatch() {
    let root_kp = det_kp(&SCALAR_A);
    let root_pub = root_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let m_kp = det_kp(&SCALAR_B);
    let m_pub = m_kp.public();
    let mcert = make_machine_cert(&root_kp, &m_pub, &hh);
    let mcert_bytes = crate::cbor::to_canonical_vec(&mcert).unwrap();
    let mfp = machine_cert_fingerprint(&mcert).unwrap();
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let wrong_pub = det_pub(&[
        7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let member = MachineRosterMemberV1 {
        m_id,
        m_pub: wrong_pub,
        machine_cert: mcert_bytes,
        machine_cert_fingerprint: mfp,
    };
    assert_eq!(
        validate_member_provenance(&member, &root_pub, &hh),
        Err(RosterCryptoError::MachinePubMismatch)
    );
}

#[test]
fn unsigned_revocation_14_keys_excludes_cert_sig() {
    let r = test_revocation();
    let unsigned_bytes = revocation_unsigned_cbor(&r).unwrap();
    let v: ciborium::value::Value = ciborium::de::from_reader(unsigned_bytes.as_slice()).unwrap();
    let keys: Vec<String> = match v {
        ciborium::value::Value::Map(e) => e
            .iter()
            .map(|(k, _)| match k {
                ciborium::value::Value::Text(s) => s.clone(),
                _ => panic!(),
            })
            .collect(),
        _ => panic!(),
    };
    assert_eq!(keys.len(), 14);
    assert!(!keys.contains(&"owner_person_cert".to_string()));
    assert!(!keys.contains(&"signature".to_string()));
    let mut r2 = r.clone();
    r2.owner_person_cert = vec![99, 98, 97];
    r2.signature = P256Signature([0xFF; 64]);
    assert_eq!(revocation_unsigned_cbor(&r2).unwrap(), unsigned_bytes);
    let mut r3 = r.clone();
    r3.owner_cert_fingerprint = [0x01; 32];
    assert_ne!(revocation_unsigned_cbor(&r3).unwrap(), unsigned_bytes);
}

#[test]
fn unsigned_checkpoint_15_keys_includes_active_revocations() {
    let c = test_checkpoint();
    let unsigned_bytes = checkpoint_unsigned_cbor(&c).unwrap();
    let v: ciborium::value::Value = ciborium::de::from_reader(unsigned_bytes.as_slice()).unwrap();
    let keys: Vec<String> = match v {
        ciborium::value::Value::Map(e) => e
            .iter()
            .map(|(k, _)| match k {
                ciborium::value::Value::Text(s) => s.clone(),
                _ => panic!(),
            })
            .collect(),
        _ => panic!(),
    };
    assert_eq!(keys.len(), 15);
    assert!(keys.contains(&"active".to_string()));
    assert!(keys.contains(&"revocations".to_string()));
    assert!(!keys.contains(&"owner_person_cert".to_string()));
    assert!(!keys.contains(&"signature".to_string()));
    let mut c2 = c.clone();
    c2.active = vec![];
    assert_ne!(checkpoint_unsigned_cbor(&c2).unwrap(), unsigned_bytes);
}

// ─── Byte-exact hex oracles ─────────────────────────────────────────────

fn fixture_revocation_signed() -> (
    MachineRosterRevocationV1,
    Vec<u8>,
    HouseholdId,
    PersonId,
    P256PublicKey,
    P256PublicKey,
) {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    )
    .unwrap();
    (r, cert_bytes, hh, p_id, root_pub, owner_pub)
}

#[test]
fn revocation_event_hash_byte_exact() {
    let (r, _, _, _, _, _) = fixture_revocation_signed();
    let h = revocation_event_hash(&r).unwrap();
    let p = revocation_preimage(&r).unwrap();
    assert_eq!(
        hex::encode(&p),
        "736f796568742f686f757365686f6c642d6d616368696e652d726f737465722d7265766f636174696f6e2f763100ae617601646b696e647826686f757365686f6c642d6d616368696e652d726f737465722d7265766f636174696f6e2f7631646d5f696478366d5f6d63716132786f737663667061616c71796a64653467636436676364616b66347277346a69787833776470616c613635706d6b616565706f63685820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6568685f6964783768685f6d63716132786f737663667061616c71796a64653467636436676364616b66347277346a69787833776470616c613635706d6b61656d5f7075625821029bbf06dad9ab5905e05471ce16d5222c89c2caa39f26267ac0747129885fbd4466726561736f6e006763617363616465006873657175656e6365016a6f776e65725f705f69647836705f36623564686d77347570327773667775726a6e686a623635343261776a37627079676a6135676d697274766168786d36707473616a7265766f6b65645f61741903e86f707265765f6576656e745f6861736858200000000000000000000000000000000000000000000000000000000000000000766f776e65725f636572745f66696e6765727072696e745820a0fb4c5f4288aa0a13542819b043c24d69d59bfc592b021f1f3e648886ca33c978186d616368696e655f636572745f66696e6765727072696e745820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(
        hex::encode(h),
        "ec7b1b3e091977d03a0816cb76ae24cae35026396113cbf39506c87df57862d5"
    );
}

#[test]
fn revocation_preimage_len_and_domain() {
    let (r, _, _, _, _, _) = fixture_revocation_signed();
    let p = revocation_preimage(&r).unwrap();
    assert!(p.starts_with(b"soyeht/household-machine-roster-revocation/v1\x00"));
}

#[test]
fn checkpoint_hash_byte_exact() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let mut c = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0xDD; 32],
        issued_at: 1000,
        not_after: 1300,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        active: vec![],
        revocations: vec![],
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut c,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        1000,
    )
    .unwrap();
    let h = checkpoint_hash(&c).unwrap();
    let cp = checkpoint_preimage(&c).unwrap();
    assert_eq!(
        hex::encode(&cp),
        "736f796568742f686f757365686f6c642d6d616368696e652d726f737465722d636865636b706f696e742f763100af617601646b696e647826686f757365686f6c642d6d616368696e652d726f737465722d636865636b706f696e742f76316565706f63685820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6568685f6964783768685f6d63716132786f737663667061616c71796a64653467636436676364616b66347277346a69787833776470616c613635706d6b616661637469766580696973737565645f61741903e8696e6f745f61667465721905146a6f776e65725f705f69647836705f36623564686d77347570327773667775726a6e686a623635343261776a37627079676a6135676d697274766168786d36707473616b7265766f636174696f6e73806e6576656e745f73657175656e6365006f6576656e745f686561645f68617368582000000000000000000000000000000000000000000000000000000000000000006f6d6573685f6c6f675f6469676573745820dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd73636865636b706f696e745f73657175656e63650174707265765f636865636b706f696e745f6861736858200000000000000000000000000000000000000000000000000000000000000000766f776e65725f636572745f66696e6765727072696e745820a0fb4c5f4288aa0a13542819b043c24d69d59bfc592b021f1f3e648886ca33c9"
    );
    assert_eq!(
        hex::encode(h),
        "4f1ab2dbe8a5bb4f9a0911ec501f3edfcf230a3ccccb7e567e4832c986b1d4a9"
    );
}

#[test]
fn epoch_byte_exact() {
    let pk = det_pub(&SCALAR_B);
    let root_pub = det_pub(&SCALAR_A);
    let hh = crate::ids::derive_household_id(&root_pub);
    let nonce = [0x42u8; 32];
    let epoch = derive_epoch(&hh, &pk, &nonce);
    assert_eq!(
        hex::encode(epoch),
        "e3849048191b5bbc7e4be17a0e9c4a3d16c62d1f96a3505512cb2f5d15f8708d"
    );
}

// ─── Weak provenance ────────────────────────────────────────────────────

#[test]
fn weak_provenance_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = crate::person_cert::PersonCert::sign_owner(
        &root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: hh.clone(),
            p_pub: owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 1000,
        },
    )
    .unwrap();
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let result = sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    );
    assert_eq!(result, Err(RosterCryptoError::WeakProvenance));
}

// ─── Missing caveats (root-resigned) ────────────────────────────────────

fn resign_cert_with_caveats(
    root_kp: &crate::keys::P256Keypair,
    cert: &mut crate::person_cert::PersonCert,
    caveats: Vec<crate::caveats::Caveat>,
) {
    cert.caveats = caveats;
    let signing_bytes = cert.signing_bytes().unwrap();
    cert.signature = root_kp.sign(&signing_bytes).unwrap();
}

#[test]
fn missing_caveat_add_machine_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let mut cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    resign_cert_with_caveats(
        &root_kp,
        &mut cert,
        vec![crate::caveats::Caveat::new(
            crate::caveats::Operation::HouseholdRevoke,
            None,
        )],
    );
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Lost,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let result = sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    );
    assert_eq!(result, Err(RosterCryptoError::MissingCaveatAddMachine));
}

#[test]
fn missing_caveat_revoke_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let mut cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    resign_cert_with_caveats(
        &root_kp,
        &mut cert,
        vec![crate::caveats::Caveat::new(
            crate::caveats::Operation::HouseholdAddMachine,
            None,
        )],
    );
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Retired,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let result = sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    );
    assert_eq!(result, Err(RosterCryptoError::MissingCaveatRevoke));
}

#[test]
fn empty_caveats_rejected_as_missing_add_machine() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let mut cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    resign_cert_with_caveats(&root_kp, &mut cert, vec![]);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::OwnerAction,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let result = sign_revocation(
        &mut r,
        &owner_kp,
        &cert_bytes,
        &hh,
        &root_pub,
        &p_id,
        &owner_pub,
        2000,
    );
    assert_eq!(result, Err(RosterCryptoError::MissingCaveatAddMachine));
}

// ─── Owner cert non-canonical ───────────────────────────────────────────

#[test]
fn owner_cert_noncanonical_rejected() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let mut val: ciborium::value::Value = ciborium::de::from_reader(cert_bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut entries) = val {
        entries.reverse();
    }
    let mut noncanonical = Vec::new();
    ciborium::ser::into_writer(&val, &mut noncanonical).unwrap();
    assert_ne!(noncanonical, cert_bytes);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let mut r = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: noncanonical,
        signature: P256Signature([0u8; 64]),
    };
    let nc_bytes = r.owner_person_cert.clone();
    let result = sign_revocation(
        &mut r, &owner_kp, &nc_bytes, &hh, &root_pub, &p_id, &owner_pub, 2000,
    );
    assert_eq!(result, Err(RosterCryptoError::CertNotCanonical));
}

// ─── Unsigned key names literal ─────────────────────────────────────────

#[test]
fn unsigned_revocation_exact_14_key_names() {
    let (r, _, _, _, _, _) = fixture_revocation_signed();
    let unsigned_bytes = revocation_unsigned_cbor(&r).unwrap();
    let v: ciborium::value::Value = ciborium::de::from_reader(unsigned_bytes.as_slice()).unwrap();
    let mut keys: Vec<String> = match v {
        ciborium::value::Value::Map(e) => e
            .iter()
            .map(|(k, _)| match k {
                ciborium::value::Value::Text(s) => s.clone(),
                _ => panic!(),
            })
            .collect(),
        _ => panic!(),
    };
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "cascade",
            "epoch",
            "hh_id",
            "kind",
            "m_id",
            "m_pub",
            "machine_cert_fingerprint",
            "owner_cert_fingerprint",
            "owner_p_id",
            "prev_event_hash",
            "reason",
            "revoked_at",
            "sequence",
            "v"
        ]
    );
}

#[test]
fn unsigned_checkpoint_exact_15_key_names() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let c = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: hh,
        epoch: [0xAA; 32],
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0xDD; 32],
        issued_at: 1000,
        not_after: 1300,
        owner_p_id: p_id,
        owner_cert_fingerprint: fp,
        active: vec![],
        revocations: vec![],
        owner_person_cert: cert_bytes,
        signature: P256Signature([0u8; 64]),
    };
    let unsigned_bytes = checkpoint_unsigned_cbor(&c).unwrap();
    let v: ciborium::value::Value = ciborium::de::from_reader(unsigned_bytes.as_slice()).unwrap();
    let mut keys: Vec<String> = match v {
        ciborium::value::Value::Map(e) => e
            .iter()
            .map(|(k, _)| match k {
                ciborium::value::Value::Text(s) => s.clone(),
                _ => panic!(),
            })
            .collect(),
        _ => panic!(),
    };
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "active",
            "checkpoint_sequence",
            "epoch",
            "event_head_hash",
            "event_sequence",
            "hh_id",
            "issued_at",
            "kind",
            "mesh_log_digest",
            "not_after",
            "owner_cert_fingerprint",
            "owner_p_id",
            "prev_checkpoint_hash",
            "revocations",
            "v"
        ]
    );
}

#[test]
fn checkpoint_preimage_changes_with_nested_revocation() {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m_pub = det_pub(&SCALAR_A);
    let m_id = crate::ids::derive_machine_id(&m_pub);
    let rev = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id,
        m_pub,
        machine_cert_fingerprint: [0xBB; 32],
        revoked_at: 1000,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let c_empty = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: hh.clone(),
        epoch: [0xAA; 32],
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0xDD; 32],
        issued_at: 1000,
        not_after: 1300,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: fp,
        active: vec![],
        revocations: vec![],
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let c_with_rev = MachineRosterCheckpointV1 {
        revocations: vec![rev.clone()],
        event_sequence: 1,
        event_head_hash: [0x11; 32],
        ..c_empty.clone()
    };
    assert_ne!(
        checkpoint_preimage(&c_empty).unwrap(),
        checkpoint_preimage(&c_with_rev).unwrap()
    );
    let mut rev_mutated = rev.clone();
    rev_mutated.revoked_at = 9999;
    let c_mutated = MachineRosterCheckpointV1 {
        revocations: vec![rev_mutated],
        event_sequence: 1,
        event_head_hash: [0x11; 32],
        ..c_empty.clone()
    };
    assert_ne!(
        checkpoint_preimage(&c_with_rev).unwrap(),
        checkpoint_preimage(&c_mutated).unwrap()
    );
}

// ─── CP3 material tests ─────────────────────────────────────────────────

struct TestRig {
    root_kp: crate::keys::P256Keypair,
    owner_kp: crate::keys::P256Keypair,
    root_pub: P256PublicKey,
    owner_pub: P256PublicKey,
    hh: HouseholdId,
    p_id: PersonId,
    cert_bytes: Vec<u8>,
    cert_fp: [u8; 32],
    m1_kp: crate::keys::P256Keypair,
    m2_kp: crate::keys::P256Keypair,
}

fn test_rig() -> TestRig {
    let root_kp = det_kp(&SCALAR_A);
    let owner_kp = det_kp(&SCALAR_B);
    use crate::keys::IdentityKey as _;
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let cert = make_owner_cert(&root_kp, &owner_pub, &hh);
    let cert_bytes = owner_cert_bytes(&cert);
    let cert_fp = owner_cert_fingerprint(&cert).unwrap();
    let m1_kp = det_kp(&[
        10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let m2_kp = det_kp(&[
        20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    TestRig {
        root_kp,
        owner_kp,
        root_pub,
        owner_pub,
        hh,
        p_id,
        cert_bytes,
        cert_fp,
        m1_kp,
        m2_kp,
    }
}

fn make_member(rig: &TestRig, m_kp: &crate::keys::P256Keypair) -> MachineRosterMemberV1 {
    use crate::keys::IdentityKey as _;
    let m_pub = m_kp.public();
    let mcert = make_machine_cert(&rig.root_kp, &m_pub, &rig.hh);
    let mcert_bytes = crate::cbor::to_canonical_vec(&mcert).unwrap();
    let mfp = machine_cert_fingerprint(&mcert).unwrap();
    let m_id = crate::ids::derive_machine_id(&m_pub);
    MachineRosterMemberV1 {
        m_id,
        m_pub,
        machine_cert: mcert_bytes,
        machine_cert_fingerprint: mfp,
    }
}

fn make_genesis_checkpoint(
    rig: &TestRig,
    members: Vec<MachineRosterMemberV1>,
    epoch_nonce: [u8; 32],
) -> MachineRosterCheckpointV1 {
    let epoch = derive_epoch(&rig.hh, &rig.owner_pub, &epoch_nonce);
    let mut c = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0u8; 32],
        issued_at: 1000,
        not_after: 1200,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: members,
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut c,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1000,
    )
    .unwrap();
    c
}

fn rig_ctx(rig: &TestRig, now: u64, bound_fp: Option<[u8; 32]>) -> AdmissionContext<'_> {
    AdmissionContext {
        authority: RosterAuthorityContext {
            hh_pub: &rig.root_pub,
            expected_hh_id: &rig.hh,
            expected_p_id: &rig.p_id,
            expected_p_pub: &rig.owner_pub,
            effective_now: now,
        },
        clock_available: true,
        bound_owner_cert_fingerprint: bound_fp,
    }
}

fn canonical(c: &MachineRosterCheckpointV1) -> CanonicalCheckpoint {
    let bytes = crate::cbor::to_canonical_vec(c).unwrap();
    CanonicalCheckpoint::from_raw(&bytes).unwrap()
}

#[test]
fn cp3_genesis_green() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1, m2];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members.clone(), [1u8; 32]);
    let ctx = rig_ctx(&rig, 1000, None);
    let (state, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(result, CheckpointAdmissionResult::Accepted);
    assert!(matches!(state, AcceptedRosterChainState::Accepted(_)));
}

#[test]
fn cp3_genesis_seq_not_1_gap() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    genesis.checkpoint_sequence = 2;
    let ctx = rig_ctx(&rig, 1000, None);
    let (_, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedGap);
}

#[test]
fn cp3_duplicate_idempotent() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let ctx = rig_ctx(&rig, 1000, Some(rig.cert_fp));
    let (state, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    let (_, result) = admit_checkpoint(&canonical(&genesis), &state, &ctx);
    assert_eq!(result, CheckpointAdmissionResult::IdempotentDuplicate);
}

#[test]
fn cp3_replay_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Accept seq=2
    let mut next = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: genesis.epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0x22; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![m1],
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut next,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, _) = admit_checkpoint(
        &canonical(&next),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    // Now submit genesis again (seq=1 < accepted seq=2) => replay
    let ctx = rig_ctx(&rig, 1050, Some(rig.cert_fp));
    let (_, result) = admit_checkpoint(&canonical(&genesis), &state2, &ctx);
    assert_eq!(result, CheckpointAdmissionResult::RejectedReplay);
}

#[test]
fn cp3_epoch_migration_required() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let (state, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    let mut other_epoch = make_genesis_checkpoint(&rig, vec![m1], [2u8; 32]);
    other_epoch.checkpoint_sequence = 2;
    other_epoch.prev_checkpoint_hash = checkpoint_hash(&genesis).unwrap();
    other_epoch.issued_at = 1001;
    other_epoch.not_after = 1201;
    sign_checkpoint(
        &mut other_epoch,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1001,
    )
    .unwrap();
    let ctx = rig_ctx(&rig, 1001, Some(rig.cert_fp));
    let (_, result) = admit_checkpoint(&canonical(&other_epoch), &state, &ctx);
    assert_eq!(result, CheckpointAdmissionResult::EpochMigrationRequired);
}

#[test]
fn cp3_temporal_stale_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let ctx = rig_ctx(&rig, 2000, None); // now > not_after=1200
    let (_, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedTemporal);
}

#[test]
fn cp3_temporal_future_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    // Modify issued_at to be > now+60 while cert remains valid at now=1000
    genesis.issued_at = 1061;
    genesis.not_after = 1261;
    sign_checkpoint(
        &mut genesis,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1061,
    )
    .unwrap();
    let ctx = rig_ctx(&rig, 1000, None); // issued_at=1061 > 1000+60=1060
    let (_, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedTemporal);
}

#[test]
fn cp3_clock_unavailable_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let mut ctx = rig_ctx(&rig, 1000, None);
    ctx.clock_available = false;
    let (_, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedTemporal);
}

#[test]
fn cp3_terminal_fork_no_outgoing() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let fork_state = AcceptedRosterChainState::CheckpointForkConflict {
        epoch: [1u8; 32],
        sequence: 1,
        hashes: vec![[0xAA; 32], [0xBB; 32]],
    };
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let ctx = rig_ctx(&rig, 1000, Some(rig.cert_fp));
    let (_, result) = admit_checkpoint(&canonical(&genesis), &fork_state, &ctx);
    assert_eq!(
        result,
        CheckpointAdmissionResult::CheckpointForkConflictRecorded
    );
}

#[test]
fn cp3_currency_active() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m1_id = m1.m_id.clone();
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let (state, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    let ctx = rig_ctx(&rig, 1000, Some(rig.cert_fp));
    let currency = derive_machine_currency(&state, &m1_id, &ctx);
    assert!(matches!(currency, MachineCurrencyResult::Active { .. }));
}

#[test]
fn cp3_currency_not_listed() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let (state, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    let unknown_id = MachineId("m_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    let ctx = rig_ctx(&rig, 1000, Some(rig.cert_fp));
    let currency = derive_machine_currency(&state, &unknown_id, &ctx);
    assert_eq!(currency, MachineCurrencyResult::NotListed);
}

#[test]
fn cp3_currency_stale() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m1_id = m1.m_id.clone();
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let (state, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    let ctx = rig_ctx(&rig, 1300, Some(rig.cert_fp)); // now > not_after=1200
    let currency = derive_machine_currency(&state, &m1_id, &ctx);
    assert_eq!(
        currency,
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::CheckpointStale
        }
    );
}

#[test]
fn cp3_currency_no_genesis() {
    let rig = test_rig();
    let ctx = rig_ctx(&rig, 1000, None);
    let currency = derive_machine_currency(
        &AcceptedRosterChainState::NoGenesis,
        &MachineId("m_x".into()),
        &ctx,
    );
    assert_eq!(
        currency,
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::NoGenesis
        }
    );
}

#[test]
fn cp3_currency_fork_unavailable() {
    let rig = test_rig();
    let ctx = rig_ctx(&rig, 1000, Some(rig.cert_fp));
    let fork = AcceptedRosterChainState::CheckpointForkConflict {
        epoch: [0u8; 32],
        sequence: 1,
        hashes: vec![],
    };
    let currency = derive_machine_currency(&fork, &MachineId("m_x".into()), &ctx);
    assert_eq!(
        currency,
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::CheckpointForkConflict
        }
    );
}

#[test]
fn cp3_currency_clock_unavailable() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m1_id = m1.m_id.clone();
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let (state, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    let mut ctx = rig_ctx(&rig, 1000, Some(rig.cert_fp));
    ctx.clock_available = false;
    let currency = derive_machine_currency(&state, &m1_id, &ctx);
    assert_eq!(
        currency,
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::ClockStateUnavailable
        }
    );
}

#[test]
fn cp3_currency_owner_unavailable() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m1_id = m1.m_id.clone();
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let (state, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    let ctx = rig_ctx(&rig, 1000, None); // None => owner unavailable after Accepted
    let currency = derive_machine_currency(&state, &m1_id, &ctx);
    assert_eq!(
        currency,
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::OwnerAuthorityUnavailable
        }
    );
}

#[test]
fn cp3_issued_at_rollback_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let (state, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Same seq=1, different hash (different mesh_log_digest), issued_at < accepted.issued_at=1000
    let mut rollback = genesis.clone();
    rollback.issued_at = 1000; // same issued_at but different content
    rollback.not_after = 1200;
    rollback.mesh_log_digest = [0xFF; 32]; // force different hash
    // But issued_at must be < accepted to trigger D18b; use 999
    rollback.issued_at = 999;
    rollback.not_after = 1199;
    sign_checkpoint(
        &mut rollback,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1000,
    )
    .unwrap();
    // ctx.bound must match state fp; cert valid at now=1000
    let ctx = rig_ctx(&rig, 1000, Some(rig.cert_fp));
    let (_, result) = admit_checkpoint(&canonical(&rollback), &state, &ctx);
    assert_eq!(result, CheckpointAdmissionResult::RejectedTemporal);
}

#[test]
fn cp3_valid_linked_after_replay_succeeds() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m1_id = m1.m_id.clone();
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let (state, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Replay (same seq, same hash) => idempotent
    let (_, r1) = admit_checkpoint(
        &canonical(&genesis),
        &state,
        &rig_ctx(&rig, 1000, Some(rig.cert_fp)),
    );
    assert_eq!(r1, CheckpointAdmissionResult::IdempotentDuplicate);
    // Valid next checkpoint
    let mut next = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: genesis.epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0x11; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![m1],
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut next,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, r2) = admit_checkpoint(
        &canonical(&next),
        &state,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r2, CheckpointAdmissionResult::Accepted);
    let currency =
        derive_machine_currency(&state2, &m1_id, &rig_ctx(&rig, 1050, Some(rig.cert_fp)));
    assert!(matches!(currency, MachineCurrencyResult::Active { .. }));
}

#[test]
fn cp3_genesis_with_revocations_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    genesis.event_sequence = 1;
    let ctx = rig_ctx(&rig, 1000, None);
    let (_, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedMalformed);
}

// ─── F: Real revocation + remove-wins + Revoked currency ────────────────

fn make_signed_revocation(
    rig: &TestRig,
    member: &MachineRosterMemberV1,
    epoch: [u8; 32],
    seq: u64,
    prev_hash: [u8; 32],
) -> MachineRosterRevocationV1 {
    let mut rev = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        sequence: seq,
        prev_event_hash: prev_hash,
        m_id: member.m_id.clone(),
        m_pub: member.m_pub.clone(),
        machine_cert_fingerprint: member.machine_cert_fingerprint,
        revoked_at: 1050,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut rev,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    rev
}

#[test]
fn cp3_revocation_remove_wins_and_currency_revoked() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let m1_id = m1.m_id.clone();
    let m2_id = m2.m_id.clone();
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members, [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Create revocation for m1
    let rev1 = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    // Refresh checkpoint with revocation
    let mut active_after: Vec<MachineRosterMemberV1> = vec![m2.clone()];
    active_after.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut refresh = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0x33; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active_after,
        revocations: vec![rev1],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut refresh,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, result) = admit_checkpoint(
        &canonical(&refresh),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(result, CheckpointAdmissionResult::Accepted);
    // Currency: m1 Revoked, m2 Active
    let ctx = rig_ctx(&rig, 1050, Some(rig.cert_fp));
    let c1 = derive_machine_currency(&state2, &m1_id, &ctx);
    assert!(matches!(c1, MachineCurrencyResult::Revoked { .. }));
    let c2 = derive_machine_currency(&state2, &m2_id, &ctx);
    assert!(matches!(c2, MachineCurrencyResult::Active { .. }));
}

// ─── D: Real CheckpointForkConflict via signed candidate ────────────────

#[test]
fn cp3_checkpoint_fork_persistent() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Alternative seq=1 with different content (same prev=0, valid projection)
    let mut alt = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    alt.mesh_log_digest = [0xEE; 32]; // different hash
    sign_checkpoint(
        &mut alt,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1000,
    )
    .unwrap();
    let alt_hash = checkpoint_hash(&alt).unwrap();
    assert_ne!(alt_hash, checkpoint_hash(&genesis).unwrap());
    let (state2, result) = admit_checkpoint(
        &canonical(&alt),
        &state1,
        &rig_ctx(&rig, 1000, Some(rig.cert_fp)),
    );
    assert_eq!(
        result,
        CheckpointAdmissionResult::CheckpointForkConflictRecorded
    );
    assert!(matches!(
        state2,
        AcceptedRosterChainState::CheckpointForkConflict { .. }
    ));
    // Fork is terminal: returned state == fork state exactly
    let (s3, r2) = admit_checkpoint(
        &canonical(&genesis),
        &state2,
        &rig_ctx(&rig, 1000, Some(rig.cert_fp)),
    );
    assert_eq!(
        r2,
        CheckpointAdmissionResult::CheckpointForkConflictRecorded
    );
    assert_eq!(s3, state2);
    // Assert exact fork fields
    if let AcceptedRosterChainState::CheckpointForkConflict {
        epoch,
        sequence,
        hashes,
    } = &state2
    {
        assert_eq!(*epoch, genesis.epoch);
        assert_eq!(*sequence, 1);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], checkpoint_hash(&genesis).unwrap());
        assert_eq!(hashes[1], alt_hash);
    } else {
        panic!("expected CheckpointForkConflict");
    }
}

// ─── J: No-write proofs ─────────────────────────────────────────────────

#[test]
fn cp3_no_write_replay_gap_epoch() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Accept seq=2
    let mut next = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: genesis.epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0x44; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![m1.clone()],
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut next,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, _) = admit_checkpoint(
        &canonical(&next),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    // Replay seq=1 => no-write
    let (s, r) = admit_checkpoint(
        &canonical(&genesis),
        &state2,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedReplay);
    assert_eq!(s, state2);
    // Gap seq=5 => no-write
    let mut gap = next.clone();
    gap.checkpoint_sequence = 5;
    gap.issued_at = 1060;
    gap.not_after = 1260;
    sign_checkpoint(
        &mut gap,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&gap),
        &state2,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedGap);
    assert_eq!(s, state2);
    // Epoch mismatch => no-write
    let mut wrong_epoch = next.clone();
    wrong_epoch.epoch = [0xFF; 32];
    wrong_epoch.checkpoint_sequence = 3;
    wrong_epoch.prev_checkpoint_hash = checkpoint_hash(&next).unwrap();
    wrong_epoch.issued_at = 1060;
    wrong_epoch.not_after = 1260;
    sign_checkpoint(
        &mut wrong_epoch,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&wrong_epoch),
        &state2,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::EpochMigrationRequired);
    assert_eq!(s, state2);
}

// ─── B: Owner/RC classification ─────────────────────────────────────────

#[test]
fn cp3_bad_root_rejected_owner() {
    let rig = test_rig();
    let wrong_root = det_kp(&[
        99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let wrong_root_pub = wrong_root.public();
    let mut ctx = rig_ctx(&rig, 1000, None);
    ctx.authority.hh_pub = &wrong_root_pub;
    let (_, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedOwner);
}

#[test]
fn cp3_genesis_bound_fp_mismatch_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let wrong_fp = [0xDD; 32];
    let ctx = rig_ctx(&rig, 1000, Some(wrong_fp));
    let (_, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedOwner);
}

#[test]
fn cp3_genesis_bound_fp_equal_green() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let ctx = rig_ctx(&rig, 1000, Some(rig.cert_fp));
    let (_, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(result, CheckpointAdmissionResult::Accepted);
}

// ─── A: Raw canonical negatives ─────────────────────────────────────────

#[test]
fn cp3_canonical_rejects_noncanonical_map_order() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let canonical_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
    let mut val: ciborium::value::Value =
        ciborium::de::from_reader(canonical_bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut entries) = val {
        entries.reverse();
    }
    let mut noncanonical = Vec::new();
    ciborium::ser::into_writer(&val, &mut noncanonical).unwrap();
    assert!(CanonicalCheckpoint::from_raw(&noncanonical).is_err());
}

#[test]
fn cp3_canonical_rejects_wrong_version() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    genesis.v = 2;
    let bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
    assert!(matches!(
        CanonicalCheckpoint::from_raw(&bytes),
        Err(CheckpointAdmissionResult::RejectedMalformed)
    ));
}

// ─── K: Owner continuity ────────────────────────────────────────────────

#[test]
fn cp3_owner_fp_continuity_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Create SECOND PersonCert for same owner (different nonce => different fp)
    use crate::keys::IdentityKey as _;
    let mut cert2 = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
        &rig.root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: rig.hh.clone(),
            p_pub: rig.owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 1000,
        },
        crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    cert2.nonce = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let sb2 = cert2.signing_bytes().unwrap();
    cert2.signature = rig.root_kp.sign(&sb2).unwrap();
    let cert2_bytes = owner_cert_bytes(&cert2);
    let cert2_fp = owner_cert_fingerprint(&cert2).unwrap();
    assert_ne!(cert2_fp, rig.cert_fp); // different fingerprint
    // Sign checkpoint with cert2 (authority valid in isolation)
    let mut next = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: genesis.epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0x55; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: cert2_fp,
        active: vec![m1],
        revocations: vec![],
        owner_person_cert: cert2_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut next,
        &rig.owner_kp,
        &cert2_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    // State bound to old fp => candidate with cert2_fp => RejectedOwner + no-write
    let (s, r) = admit_checkpoint(
        &canonical(&next),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedOwner);
    assert_eq!(s, state1);
}

// ─── E: Temporal boundaries ─────────────────────────────────────────────

#[test]
fn cp3_lifetime_over_300_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    genesis.not_after = 1000 + 301; // lifetime 301 > 300
    sign_checkpoint(
        &mut genesis,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1000,
    )
    .unwrap();
    let (_, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedTemporal);
}

#[test]
fn cp3_issued_equal_prior_allowed() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Next with same issued_at=1000 (equal, not lower) => allowed
    let mut next = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: genesis.epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0x66; 32],
        issued_at: 1000,
        not_after: 1200,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![m1],
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut next,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1000,
    )
    .unwrap();
    let (_, result) = admit_checkpoint(
        &canonical(&next),
        &state1,
        &rig_ctx(&rig, 1000, Some(rig.cert_fp)),
    );
    assert_eq!(result, CheckpointAdmissionResult::Accepted);
}

// ─── L: Determinism ─────────────────────────────────────────────────────

#[test]
fn cp3_determinism_same_inputs_same_output() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let ctx = rig_ctx(&rig, 1000, None);
    let (s1, r1) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    let (s2, r2) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(s1, s2);
    assert_eq!(r1, r2);
}

// ─── Genesis full field assertion ───────────────────────────────────────

#[test]
fn cp3_genesis_full_fields() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1, m2];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members.clone(), [7u8; 32]);
    let expected_epoch = derive_epoch(&rig.hh, &rig.owner_pub, &[7u8; 32]);
    let (state, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    assert_eq!(result, CheckpointAdmissionResult::Accepted);
    if let AcceptedRosterChainState::Accepted(data) = &state {
        assert_eq!(data.epoch, expected_epoch);
        assert_eq!(data.checkpoint_sequence, 1);
        assert_eq!(data.prev_checkpoint_hash, [0u8; 32]);
        assert_eq!(data.event_sequence, 0);
        assert_eq!(data.event_head_hash, [0u8; 32]);
        assert_eq!(data.owner_cert_fingerprint, rig.cert_fp);
        assert_eq!(data.genesis_basis.members, members);
        assert_eq!(data.active, members);
        assert!(data.tombstones.is_empty());
    } else {
        panic!("expected Accepted");
    }
}

// ─── F/D17: EventForkConflict real ──────────────────────────────────────

#[test]
fn cp3_event_fork_same_seq_diff_head() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members.clone(), [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Accept seq=2 with revocation of m1 (event_sequence=1)
    let rev1 = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    let mut active_after: Vec<MachineRosterMemberV1> = vec![m2.clone()];
    active_after.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0x77; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active_after.clone(),
        revocations: vec![rev1.clone()],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, _) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert!(matches!(state2, AcceptedRosterChainState::Accepted(_)));
    // Alternative seq=3 with same event_sequence=1 but different head (divergent revocation)
    let rev1_alt = {
        let mut r = rev1.clone();
        r.revoked_at = 1099; // different content => different hash
        sign_revocation(
            &mut r,
            &rig.owner_kp,
            &rig.cert_bytes,
            &rig.hh,
            &rig.root_pub,
            &rig.p_id,
            &rig.owner_pub,
            1099,
        )
        .unwrap();
        r
    };
    let rev1_alt_hash = revocation_event_hash(&rev1_alt).unwrap();
    assert_ne!(rev1_alt_hash, rev1_hash);
    let seq2_hash = checkpoint_hash(&seq2).unwrap();
    let mut seq3_alt = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq2_hash,
        event_sequence: 1,
        event_head_hash: rev1_alt_hash,
        mesh_log_digest: [0x88; 32],
        issued_at: 1060,
        not_after: 1260,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active_after,
        revocations: vec![rev1_alt],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq3_alt,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (state3, result) = admit_checkpoint(
        &canonical(&seq3_alt),
        &state2,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(result, CheckpointAdmissionResult::EventForkConflictRecorded);
    assert!(matches!(
        state3,
        AcceptedRosterChainState::EventForkConflict { .. }
    ));
    // EventFork is terminal
    let (s4, r4) = admit_checkpoint(
        &canonical(&seq2),
        &state3,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(r4, CheckpointAdmissionResult::EventForkConflictRecorded);
    assert_eq!(s4, state3);
}

// ─── G: Projection rejections ───────────────────────────────────────────

#[test]
fn cp3_projection_new_machine_outside_genesis_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    // Genesis with only m1
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Refresh tries to add m2 (not in genesis) => projection mismatch
    let mut bad_members = vec![m1, m2];
    bad_members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut bad_refresh = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: genesis.epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0x99; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: bad_members,
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut bad_refresh,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&bad_refresh),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state1);
}

#[test]
fn cp3_projection_revocation_target_pub_mismatch() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members, [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Revocation with wrong m_pub (m2's key for m1's id)
    let mut bad_rev = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id: m1.m_id.clone(),
        m_pub: m2.m_pub.clone(), // WRONG pub
        machine_cert_fingerprint: m1.machine_cert_fingerprint,
        revoked_at: 1050,
        reason: RevocationReason::Lost,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut bad_rev,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let bad_rev_hash = revocation_event_hash(&bad_rev).unwrap();
    let mut active_after = vec![m2];
    active_after.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut refresh = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: bad_rev_hash,
        mesh_log_digest: [0xAA; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active_after,
        revocations: vec![bad_rev],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut refresh,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&refresh),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state1);
}

#[test]
fn cp3_projection_duplicate_revocation_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members, [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Two revocations for same m1 (duplicate)
    let rev1 = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    let rev2_dup = make_signed_revocation(&rig, &m1, epoch, 2, rev1_hash);
    let rev2_hash = revocation_event_hash(&rev2_dup).unwrap();
    let mut refresh = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 2,
        event_head_hash: rev2_hash,
        mesh_log_digest: [0xBB; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![],
        revocations: vec![rev1, rev2_dup],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut refresh,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&refresh),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state1);
}

// ─── B/RC: verify_rooted_identity + caveat classification ───────────────

#[test]
fn cp3_rooted_identity_accepts_without_caveats() {
    let rig = test_rig();
    use crate::keys::IdentityKey as _;
    // RC2: cert with caveats=[] (empty), root-signed, strong provenance
    let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
        &rig.root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: rig.hh.clone(),
            p_pub: rig.owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 1000,
        },
        crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    cert.caveats = vec![]; // strip ALL caveats
    cert.nonce = vec![0xBB; 16];
    let sb = cert.signing_bytes().unwrap();
    cert.signature = rig.root_kp.sign(&sb).unwrap();
    // verify_rooted_identity passes (structural+root sig, NO caveats check)
    assert!(
        cert.verify_rooted_identity(&rig.hh, &rig.root_pub, 1000)
            .is_ok()
    );
    // Full verify FAILS (missing all owner caveats)
    assert!(cert.verify(&rig.hh, &rig.root_pub, 1000).is_err());
}

#[test]
fn cp3_missing_claws_list_rejected_owner() {
    let rig = test_rig();
    // Create cert with only Add+Revoke (missing ClawsList etc)
    use crate::keys::IdentityKey as _;
    let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
        &rig.root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: rig.hh.clone(),
            p_pub: rig.owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 1000,
        },
        crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    // Strip all caveats except Add+Revoke
    cert.caveats.retain(|c| {
        c.op == crate::caveats::Operation::HouseholdAddMachine
            || c.op == crate::caveats::Operation::HouseholdRevoke
    });
    cert.nonce = vec![0xAA; 16];
    let sb = cert.signing_bytes().unwrap();
    cert.signature = rig.root_kp.sign(&sb).unwrap();
    // rooted identity passes (no caveat check)
    assert!(
        cert.verify_rooted_identity(&rig.hh, &rig.root_pub, 1000)
            .is_ok()
    );
    // full verify fails (missing ClawsList etc)
    assert!(cert.verify(&rig.hh, &rig.root_pub, 1000).is_err());
    // Core: Add+Revoke present but missing other baseline => RejectedOwner (OwnerCertInvalid)
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut genesis = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: derive_epoch(&rig.hh, &rig.owner_pub, &[1u8; 32]),
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0u8; 32],
        issued_at: 1000,
        not_after: 1200,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: fp,
        active: vec![m1],
        revocations: vec![],
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    // Sign manually (sign_checkpoint would reject incomplete cert)
    let preimage = checkpoint_preimage(&genesis).unwrap();
    genesis.signature = rig.owner_kp.sign(&preimage).unwrap();
    let (_, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedOwner);
}

// ─── H: Event rollback no-write + posterior linked ──────────────────────

#[test]
fn cp3_event_rollback_no_write_then_linked_succeeds() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members.clone(), [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Accept seq=2 with event_sequence=1
    let rev1 = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    let mut active_after: Vec<MachineRosterMemberV1> = vec![m2.clone()];
    active_after.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0xCC; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active_after.clone(),
        revocations: vec![rev1],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, _) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    // Rollback: seq=3 with event_sequence=0 < accepted event_sequence=1
    let seq2_hash = checkpoint_hash(&seq2).unwrap();
    let mut rollback = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq2_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0xDD; 32],
        issued_at: 1060,
        not_after: 1260,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: members.clone(),
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut rollback,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&rollback),
        &state2,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedRollback);
    assert_eq!(s, state2); // no-write
    // Valid linked posterior (event_sequence=1, extends)
    let mut valid_next = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq2_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0xEE; 32],
        issued_at: 1060,
        not_after: 1260,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active_after,
        revocations: vec![make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32])],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut valid_next,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (_, r2) = admit_checkpoint(
        &canonical(&valid_next),
        &state2,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(r2, CheckpointAdmissionResult::Accepted);
}

// ─── D17: M>N prefix divergence + exact extension ───────────────────────

#[test]
fn cp3_d17_exact_extension_accepted() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members.clone(), [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // seq=2 with rev1 (event_seq=1)
    let rev1 = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    let mut active1: Vec<MachineRosterMemberV1> = vec![m2.clone()];
    active1.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0x11; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active1,
        revocations: vec![rev1.clone()],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, _) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    // seq=3 extends with rev2 (M=2 > N=1): exact prefix [rev1] + extension [rev2]
    let seq2_hash = checkpoint_hash(&seq2).unwrap();
    let rev2 = make_signed_revocation(&rig, &m2, epoch, 2, rev1_hash);
    let rev2_hash = revocation_event_hash(&rev2).unwrap();
    let mut seq3 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq2_hash,
        event_sequence: 2,
        event_head_hash: rev2_hash,
        mesh_log_digest: [0x22; 32],
        issued_at: 1060,
        not_after: 1260,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![],
        revocations: vec![rev1, rev2],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq3,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (_, result) = admit_checkpoint(
        &canonical(&seq3),
        &state2,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(result, CheckpointAdmissionResult::Accepted);
}

#[test]
fn cp3_d17_prefix_divergence_event_fork() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members.clone(), [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // seq=2 with rev1 (event_seq=1)
    let rev1 = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    let mut active1: Vec<MachineRosterMemberV1> = vec![m2.clone()];
    active1.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0x33; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active1.clone(),
        revocations: vec![rev1.clone()],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, _) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    // seq=3 with DIVERGENT prefix: rev1_alt at position 1 (different from accepted rev1)
    let seq2_hash = checkpoint_hash(&seq2).unwrap();
    let mut rev1_alt = rev1.clone();
    rev1_alt.revoked_at = 1099;
    sign_revocation(
        &mut rev1_alt,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1099,
    )
    .unwrap();
    let rev1_alt_hash = revocation_event_hash(&rev1_alt).unwrap();
    assert_ne!(rev1_alt_hash, rev1_hash);
    let mut seq3_div = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq2_hash,
        event_sequence: 2,
        event_head_hash: rev1_alt_hash,
        mesh_log_digest: [0x44; 32],
        issued_at: 1060,
        not_after: 1260,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active1,
        revocations: vec![rev1_alt.clone()],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    // Need event_sequence=2 with 2 revocations for the hash chain to work
    // Actually rev1_alt is seq1, we need a seq2 after it
    let rev2_alt = {
        let r = make_signed_revocation(&rig, &m2, epoch, 2, rev1_alt_hash);
        r
    };
    let rev2_alt_hash = revocation_event_hash(&rev2_alt).unwrap();
    seq3_div.event_head_hash = rev2_alt_hash;
    seq3_div.revocations = vec![rev1_alt.clone(), rev2_alt];
    seq3_div.active = vec![];
    sign_checkpoint(
        &mut seq3_div,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (state3, result) = admit_checkpoint(
        &canonical(&seq3_div),
        &state2,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(result, CheckpointAdmissionResult::EventForkConflictRecorded);
    assert!(matches!(
        state3,
        AcceptedRosterChainState::EventForkConflict { .. }
    ));
}

// ─── B: missing Add/Revoke separately + weak + wrong id/pub ─────────────

#[test]
fn cp3_missing_add_machine_rejected_caveat() {
    let rig = test_rig();
    use crate::keys::IdentityKey as _;
    let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
        &rig.root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: rig.hh.clone(),
            p_pub: rig.owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 1000,
        },
        crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    cert.caveats
        .retain(|c| c.op != crate::caveats::Operation::HouseholdAddMachine);
    cert.nonce = vec![0xCC; 16];
    let sb = cert.signing_bytes().unwrap();
    cert.signature = rig.root_kp.sign(&sb).unwrap();
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut genesis = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: derive_epoch(&rig.hh, &rig.owner_pub, &[1u8; 32]),
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0u8; 32],
        issued_at: 1000,
        not_after: 1200,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: fp,
        active: vec![m1],
        revocations: vec![],
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let preimage = checkpoint_preimage(&genesis).unwrap();
    genesis.signature = rig.owner_kp.sign(&preimage).unwrap();
    let (s, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedCaveat);
    assert_eq!(s, AcceptedRosterChainState::NoGenesis);
}

#[test]
fn cp3_missing_revoke_rejected_caveat() {
    let rig = test_rig();
    use crate::keys::IdentityKey as _;
    let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
        &rig.root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: rig.hh.clone(),
            p_pub: rig.owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 1000,
        },
        crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    cert.caveats
        .retain(|c| c.op != crate::caveats::Operation::HouseholdRevoke);
    cert.nonce = vec![0xDD; 16];
    let sb = cert.signing_bytes().unwrap();
    cert.signature = rig.root_kp.sign(&sb).unwrap();
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut genesis = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: derive_epoch(&rig.hh, &rig.owner_pub, &[1u8; 32]),
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0u8; 32],
        issued_at: 1000,
        not_after: 1200,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: fp,
        active: vec![m1],
        revocations: vec![],
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let preimage = checkpoint_preimage(&genesis).unwrap();
    genesis.signature = rig.owner_kp.sign(&preimage).unwrap();
    let (s, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedCaveat);
    assert_eq!(s, AcceptedRosterChainState::NoGenesis);
}

// ─── D: invalid same-seq does NOT record fork ───────────────────────────

#[test]
fn cp3_same_seq_bad_signature_no_fork() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Same seq=1, different content, BAD signature
    let mut bad = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    bad.mesh_log_digest = [0xFF; 32];
    // Don't re-sign => signature invalid for new content
    let (s, r) = admit_checkpoint(
        &canonical(&bad),
        &state1,
        &rig_ctx(&rig, 1000, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedSignature);
    assert_eq!(s, state1); // no fork recorded
}

#[test]
fn cp3_same_seq_wrong_predecessor_no_fork() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Same seq=1, different content, valid sig, but wrong prev_checkpoint_hash
    let mut bad = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    bad.mesh_log_digest = [0xEE; 32];
    bad.prev_checkpoint_hash = [0xAB; 32]; // wrong (should be 0 for seq1)
    sign_checkpoint(
        &mut bad,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1000,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&bad),
        &state1,
        &rig_ctx(&rig, 1000, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedGap);
    assert_eq!(s, state1);
}

// ─── K: explicit verify cert2 authority green ───────────────────────────

#[test]
fn cp3_cert2_authority_green_isolated() {
    let rig = test_rig();
    use crate::keys::IdentityKey as _;
    let mut cert2 = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
        &rig.root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: rig.hh.clone(),
            p_pub: rig.owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 1000,
        },
        crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    cert2.nonce = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let sb2 = cert2.signing_bytes().unwrap();
    cert2.signature = rig.root_kp.sign(&sb2).unwrap();
    let cert2_bytes = owner_cert_bytes(&cert2);
    let cert2_fp = owner_cert_fingerprint(&cert2).unwrap();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut candidate = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: derive_epoch(&rig.hh, &rig.owner_pub, &[1u8; 32]),
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0u8; 32],
        issued_at: 1000,
        not_after: 1200,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: cert2_fp,
        active: vec![m1],
        revocations: vec![],
        owner_person_cert: cert2_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut candidate,
        &rig.owner_kp,
        &cert2_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1000,
    )
    .unwrap();
    // Explicit proof: verify_checkpoint_authority with signed cert2 candidate is Ok
    let result = verify_checkpoint_authority(
        &candidate,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1000,
    );
    assert!(result.is_ok());
}

// ─── G: active re-add revoked member rejected ───────────────────────────

#[test]
fn cp3_active_re_add_revoked_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members.clone(), [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Revoke m1
    let rev1 = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    let mut active_after: Vec<MachineRosterMemberV1> = vec![m2.clone()];
    active_after.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0x55; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active_after,
        revocations: vec![rev1],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, _) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    // Try to re-add m1 in active (revoked member) => projection mismatch
    let seq2_hash = checkpoint_hash(&seq2).unwrap();
    let mut bad_active = vec![m1, m2];
    bad_active.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq3_bad = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq2_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0x66; 32],
        issued_at: 1060,
        not_after: 1260,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: bad_active,
        revocations: vec![make_signed_revocation(
            &rig,
            &make_member(&rig, &rig.m1_kp),
            epoch,
            1,
            [0u8; 32],
        )],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq3_bad,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&seq3_bad),
        &state2,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state2);
}

// ─── G: broken prev_event_hash rejected ─────────────────────────────────

#[test]
fn cp3_broken_prev_event_hash_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members, [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Revocation with wrong prev_event_hash
    let mut bad_rev = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        sequence: 1,
        prev_event_hash: [0xFF; 32], // wrong (should be [0u8;32])
        m_id: m1.m_id.clone(),
        m_pub: m1.m_pub.clone(),
        machine_cert_fingerprint: m1.machine_cert_fingerprint,
        revoked_at: 1050,
        reason: RevocationReason::Lost,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut bad_rev,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let bad_hash = revocation_event_hash(&bad_rev).unwrap();
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: bad_hash,
        mesh_log_digest: [0x77; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![m2],
        revocations: vec![bad_rev],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state1);
}

// ─── B: weak provenance + wrong p_id/pub ────────────────────────────────

#[test]
fn cp3_weak_provenance_rejected_owner() {
    let rig = test_rig();
    use crate::keys::IdentityKey as _;
    // sign_owner (without verified provenance) => weak
    let cert = crate::person_cert::PersonCert::sign_owner(
        &rig.root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: rig.hh.clone(),
            p_pub: rig.owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 1000,
        },
    )
    .unwrap();
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut genesis = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: derive_epoch(&rig.hh, &rig.owner_pub, &[1u8; 32]),
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0u8; 32],
        issued_at: 1000,
        not_after: 1200,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: fp,
        active: vec![m1],
        revocations: vec![],
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let preimage = checkpoint_preimage(&genesis).unwrap();
    genesis.signature = rig.owner_kp.sign(&preimage).unwrap();
    let (s, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedOwner);
    assert_eq!(s, AcceptedRosterChainState::NoGenesis);
}

#[test]
fn cp3_wrong_expected_p_id_rejected_owner() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    // Use wrong expected_p_id in ctx (cert p_id won't match)
    let wrong_p_id = PersonId("p_wrong_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    let mut ctx = rig_ctx(&rig, 1000, None);
    ctx.authority.expected_p_id = &wrong_p_id;
    let (s, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedOwner);
    assert_eq!(s, AcceptedRosterChainState::NoGenesis);
}

// ─── A: CanonicalCheckpoint unknown field + null ────────────────────────

#[test]
fn cp3_canonical_rejects_unknown_field() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
    let mut val: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut entries) = val {
        entries.push((
            ciborium::value::Value::Text("unknown_extra".into()),
            ciborium::value::Value::Null,
        ));
    }
    let buf = crate::cbor::to_canonical_vec(&val).unwrap();
    assert!(matches!(
        CanonicalCheckpoint::from_raw(&buf),
        Err(CheckpointAdmissionResult::RejectedMalformed)
    ));
}

#[test]
fn cp3_canonical_rejects_null_epoch() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
    let mut val: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut entries) = val {
        for (k, v) in entries.iter_mut() {
            if *k == ciborium::value::Value::Text("epoch".into()) {
                *v = ciborium::value::Value::Null;
            }
        }
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&val, &mut buf).unwrap();
    assert!(matches!(
        CanonicalCheckpoint::from_raw(&buf),
        Err(CheckpointAdmissionResult::RejectedMalformed)
    ));
}

// ─── G: active unsorted + duplicate id ──────────────────────────────────

#[test]
fn cp3_active_unsorted_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    // Force unsorted (reverse order)
    let mut members = vec![m1, m2];
    members.sort_by(|a, b| b.m_id.as_str().cmp(a.m_id.as_str())); // reverse
    if members[0].m_id.as_str() < members[1].m_id.as_str() {
        members.reverse(); // ensure actually unsorted
    }
    let mut genesis = make_genesis_checkpoint(&rig, members, [1u8; 32]);
    // Override active with unsorted
    let m1b = make_member(&rig, &rig.m1_kp);
    let m2b = make_member(&rig, &rig.m2_kp);
    if m1b.m_id.as_str() < m2b.m_id.as_str() {
        genesis.active = vec![m2b, m1b]; // unsorted
    } else {
        genesis.active = vec![m1b, m2b]; // unsorted
    }
    sign_checkpoint(
        &mut genesis,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1000,
    )
    .unwrap();
    let (s, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, AcceptedRosterChainState::NoGenesis);
}

// ─── Currency: listed never Active under multiple conditions ─────────────

#[test]
fn cp3_currency_listed_never_active_matrix() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m1_id = m1.m_id.clone();
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let (state, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Stale
    let ctx_stale = rig_ctx(&rig, 1300, Some(rig.cert_fp));
    assert_eq!(
        derive_machine_currency(&state, &m1_id, &ctx_stale),
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::CheckpointStale
        }
    );
    // Clock unavailable
    let mut ctx_clock = rig_ctx(&rig, 1000, Some(rig.cert_fp));
    ctx_clock.clock_available = false;
    assert_eq!(
        derive_machine_currency(&state, &m1_id, &ctx_clock),
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::ClockStateUnavailable
        }
    );
    // Owner unavailable (None after Accepted)
    let ctx_owner = rig_ctx(&rig, 1000, None);
    assert_eq!(
        derive_machine_currency(&state, &m1_id, &ctx_owner),
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::OwnerAuthorityUnavailable
        }
    );
    // Owner wrong fp
    let ctx_wrong_fp = rig_ctx(&rig, 1000, Some([0xEE; 32]));
    assert_eq!(
        derive_machine_currency(&state, &m1_id, &ctx_wrong_fp),
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::OwnerAuthorityUnavailable
        }
    );
    // CheckpointFork
    let fork = AcceptedRosterChainState::CheckpointForkConflict {
        epoch: [0u8; 32],
        sequence: 1,
        hashes: vec![],
    };
    let ctx_ok = rig_ctx(&rig, 1000, Some(rig.cert_fp));
    assert_eq!(
        derive_machine_currency(&fork, &m1_id, &ctx_ok),
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::CheckpointForkConflict
        }
    );
    // EventFork
    let efork = AcceptedRosterChainState::EventForkConflict {
        epoch: [0u8; 32],
        sequence: 1,
        hashes: vec![],
    };
    assert_eq!(
        derive_machine_currency(&efork, &m1_id, &ctx_ok),
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::EventForkConflict
        }
    );
    // NoGenesis
    assert_eq!(
        derive_machine_currency(&AcceptedRosterChainState::NoGenesis, &m1_id, &ctx_ok),
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::NoGenesis
        }
    );
    // Active (control)
    assert!(matches!(
        derive_machine_currency(&state, &m1_id, &ctx_ok),
        MachineCurrencyResult::Active { .. }
    ));
}

// ─── A: closed-enum invalid via CanonicalCheckpoint ─────────────────────

#[test]
fn cp3_canonical_rejects_invalid_enum() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members, [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let rev1 = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    let mut active1: Vec<MachineRosterMemberV1> = vec![make_member(&rig, &rig.m2_kp)];
    active1.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0x11; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active1,
        revocations: vec![rev1],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();
    // Mutate nested revocation reason to invalid uint 99
    let mut val: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    if let ciborium::value::Value::Map(ref mut entries) = val {
        for (k, v) in entries.iter_mut() {
            if *k == ciborium::value::Value::Text("revocations".into()) {
                if let ciborium::value::Value::Array(revs) = v {
                    if let Some(ciborium::value::Value::Map(rev_entries)) = revs.first_mut() {
                        for (rk, rv) in rev_entries.iter_mut() {
                            if *rk == ciborium::value::Value::Text("reason".into()) {
                                *rv = ciborium::value::Value::Integer(99.into());
                            }
                        }
                    }
                }
            }
        }
    }
    let buf = crate::cbor::to_canonical_vec(&val).unwrap();
    assert!(matches!(
        CanonicalCheckpoint::from_raw(&buf),
        Err(CheckpointAdmissionResult::RejectedMalformed)
    ));
}

#[test]
fn cp3_checkpoint_fork_precedence_over_event_fork() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members.clone(), [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Accept seq=2 with event_seq=1
    let rev1 = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    let mut active1: Vec<MachineRosterMemberV1> = vec![m2.clone()];
    active1.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0x11; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active1.clone(),
        revocations: vec![rev1.clone()],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, _) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    // Same seq=2, different hash AND different event head => CheckpointFork (not EventFork)
    // Must be projection-valid: real alternative prefix (rev1_alt different content)
    let mut rev1_alt = rev1.clone();
    rev1_alt.revoked_at = 1099;
    sign_revocation(
        &mut rev1_alt,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1099,
    )
    .unwrap();
    let rev1_alt_hash = revocation_event_hash(&rev1_alt).unwrap();
    assert_ne!(rev1_alt_hash, rev1_hash);
    let mut alt = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev1_alt_hash,
        mesh_log_digest: [0xFF; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active1,
        revocations: vec![rev1_alt],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut alt,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&alt),
        &state2,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    // CheckpointFork takes precedence over EventFork for same checkpoint seq
    assert_eq!(r, CheckpointAdmissionResult::CheckpointForkConflictRecorded);
    assert!(matches!(
        s,
        AcceptedRosterChainState::CheckpointForkConflict { .. }
    ));
}

// ─── G: active superset (extra member) rejected ─────────────────────────

#[test]
fn cp3_active_superset_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    // Genesis with only m1
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Refresh with m1+m2 (superset; m2 not in genesis)
    let mut superset = vec![m1, m2];
    superset.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut refresh = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: genesis.epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0x22; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: superset,
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut refresh,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&refresh),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state1);
}

// ─── G: active subset (missing member without revocation) rejected ──────

#[test]
fn cp3_active_subset_without_revocation_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members, [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Refresh with only m2 (subset; m1 missing without revocation)
    let mut refresh = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: genesis.epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0x33; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![m2],
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut refresh,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&refresh),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state1);
}

// ─── J: signature rejection no-write state equality ─────────────────────

#[test]
fn cp3_signature_rejected_no_write() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Sign properly, then alter a signed field => signature structurally valid but wrong
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let mut next = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: genesis.epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0x44; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![m1],
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut next,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    // Alter signed field AFTER signing => signature invalid for new content
    next.mesh_log_digest = [0xFF; 32];
    let (s, r) = admit_checkpoint(
        &canonical(&next),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedSignature);
    assert_eq!(s, state1);
}

// ─── B: wrong expected p_pub ────────────────────────────────────────────

#[test]
fn cp3_wrong_expected_p_pub_rejected_owner() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let wrong_pub = det_pub(&[
        77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let mut ctx = rig_ctx(&rig, 1000, None);
    ctx.authority.expected_p_pub = &wrong_pub;
    let (s, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &ctx,
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedOwner);
    assert_eq!(s, AcceptedRosterChainState::NoGenesis);
}

// ─── G: event owner fp mismatch rejected ────────────────────────────────

#[test]
fn cp3_revocation_owner_fp_mismatch_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members, [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Create cert2 (different nonce => different fp, same owner)
    use crate::keys::IdentityKey as _;
    let mut cert2 = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
        &rig.root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: rig.hh.clone(),
            p_pub: rig.owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 1000,
        },
        crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    cert2.nonce = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let sb2 = cert2.signing_bytes().unwrap();
    cert2.signature = rig.root_kp.sign(&sb2).unwrap();
    let cert2_bytes = owner_cert_bytes(&cert2);
    let cert2_fp = owner_cert_fingerprint(&cert2).unwrap();
    assert_ne!(cert2_fp, rig.cert_fp);
    // Sign revocation with cert2 => owner_cert_fingerprint = cert2_fp
    let mut rev = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id: m1.m_id.clone(),
        m_pub: m1.m_pub.clone(),
        machine_cert_fingerprint: m1.machine_cert_fingerprint,
        revoked_at: 1050,
        reason: RevocationReason::Lost,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: cert2_fp,
        owner_person_cert: cert2_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut rev,
        &rig.owner_kp,
        &cert2_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    assert_eq!(rev.owner_cert_fingerprint, cert2_fp); // sign preserved cert2 fp
    let rev_hash = revocation_event_hash(&rev).unwrap();
    // Checkpoint uses cert1 (rig.cert_fp) => event owner fp != checkpoint owner fp
    let mut active_after: Vec<MachineRosterMemberV1> = vec![m2];
    active_after.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev_hash,
        mesh_log_digest: [0x55; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active_after,
        revocations: vec![rev],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state1);
}

// ─── G: member provenance mismatch (cert bytes don't match) ──────────────

#[test]
fn cp3_member_cert_bytes_mismatch_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut bad_member = m1.clone();
    bad_member.machine_cert = vec![1, 2, 3, 4, 5]; // corrupt cert bytes
    let genesis = make_genesis_checkpoint(&rig, vec![bad_member], [1u8; 32]);
    let (s, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, AcceptedRosterChainState::NoGenesis);
}

// ─── J: projection rejection full state equality ────────────────────────

#[test]
fn cp3_projection_rejected_state_unchanged() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members.clone(), [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Accept seq=2
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: genesis.epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0x66; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: members,
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, _) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    // Projection-invalid candidate (new machine outside genesis)
    let seq2_hash = checkpoint_hash(&seq2).unwrap();
    let m3_kp = det_kp(&[
        50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let m3 = make_member(&rig, &m3_kp);
    let m1b = make_member(&rig, &rig.m1_kp);
    let m2b = make_member(&rig, &rig.m2_kp);
    let mut bad_active = vec![m1b, m2b, m3];
    bad_active.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut bad_seq3 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: genesis.epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq2_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0x77; 32],
        issued_at: 1060,
        not_after: 1260,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: bad_active,
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut bad_seq3,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&bad_seq3),
        &state2,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state2); // full state unchanged
}

// ─── D19: same-seq fork with predecessor verification ───────────────────

fn setup_seq2_with_rev(
    rig: &TestRig,
) -> (
    AcceptedRosterChainState,
    MachineRosterCheckpointV1,
    MachineRosterMemberV1,
    MachineRosterMemberV1,
    [u8; 32],
) {
    let m1 = make_member(rig, &rig.m1_kp);
    let m2 = make_member(rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(rig, members, [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, r1) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(rig, 1000, None),
    );
    assert_eq!(r1, CheckpointAdmissionResult::Accepted);
    let rev1 = make_signed_revocation(rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    let mut active1: Vec<MachineRosterMemberV1> = vec![m2.clone()];
    active1.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0x11; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active1.clone(),
        revocations: vec![rev1.clone()],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, r2) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r2, CheckpointAdmissionResult::Accepted);
    // Accept seq3 (same event_seq=1, predecessor_event_sequence becomes 1 from seq2)
    let seq2_hash = checkpoint_hash(&seq2).unwrap();
    let mut seq3 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq2_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0x22; 32],
        issued_at: 1060,
        not_after: 1260,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active1,
        revocations: vec![rev1],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq3,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (state3, r3) = admit_checkpoint(
        &canonical(&seq3),
        &state2,
        &rig_ctx(rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(r3, CheckpointAdmissionResult::Accepted);
    // Assert exact derived fields of state3
    let expected_seq3_hash = checkpoint_hash(&seq3).unwrap();
    if let AcceptedRosterChainState::Accepted(data) = &state3 {
        assert_eq!(data.checkpoint_sequence, 3);
        assert_eq!(data.checkpoint_hash, expected_seq3_hash);
        assert_eq!(data.prev_checkpoint_hash, seq2_hash);
        assert_eq!(data.event_sequence, 1);
        assert_eq!(data.event_head_hash, rev1_hash);
        assert_eq!(data.predecessor_event_sequence, 1);
        assert_eq!(data.predecessor_event_head_hash, rev1_hash);
    } else {
        panic!("expected Accepted");
    }
    (state3, seq3, m1, m2, epoch)
}

#[test]
fn cp3_d19_same_seq_prefix_exact_fork() {
    let rig = test_rig();
    let (state3, seq3, _m1, _m2, _epoch) = setup_seq2_with_rev(&rig);
    // Same seq=3, same predecessor (prev=hash(seq2)), same prefix (exact rev1), different mesh_log => fork
    let mut alt = seq3.clone();
    alt.mesh_log_digest = [0xFF; 32];
    sign_checkpoint(
        &mut alt,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&alt),
        &state3,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::CheckpointForkConflictRecorded);
    let current_hash = checkpoint_hash(&seq3).unwrap();
    let candidate_hash = checkpoint_hash(&alt).unwrap();
    if let AcceptedRosterChainState::CheckpointForkConflict {
        epoch: e,
        sequence,
        hashes,
    } = &s
    {
        assert_eq!(*e, seq3.epoch);
        assert_eq!(*sequence, 3);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], current_hash);
        assert_eq!(hashes[1], candidate_hash);
    } else {
        panic!("expected CheckpointForkConflict");
    }
}

#[test]
fn cp3_d19_same_seq_prefix_alt_rejected_projection() {
    let rig = test_rig();
    let (state3, seq3, m1, _m2, epoch) = setup_seq2_with_rev(&rig);
    // Same seq=3 but DIVERGENT prefix at position 1 (rev1_alt different content)
    // Nprev=1, so intermediate head = hash(revocations[0]) must match predecessor_event_head_hash
    let mut rev1_alt = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    rev1_alt.revoked_at = 1099;
    sign_revocation(
        &mut rev1_alt,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1099,
    )
    .unwrap();
    let rev1_alt_hash = revocation_event_hash(&rev1_alt).unwrap();
    let mut active1: Vec<MachineRosterMemberV1> = vec![make_member(&rig, &rig.m2_kp)];
    active1.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut alt = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq3.prev_checkpoint_hash,
        event_sequence: 1,
        event_head_hash: rev1_alt_hash,
        mesh_log_digest: [0xEE; 32],
        issued_at: 1060,
        not_after: 1260,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active1,
        revocations: vec![rev1_alt],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut alt,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&alt),
        &state3,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    // Intermediate head at Nprev=1 differs from predecessor_event_head_hash => RejectedProjection
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state3);
}

#[test]
fn cp3_d19_m_less_than_nprev_rollback() {
    let rig = test_rig();
    let (state3, seq3, _m1, m2, _epoch) = setup_seq2_with_rev(&rig);
    // Same seq=3 with event_sequence=0 < predecessor_event_sequence=1 => RejectedRollback
    let mut seq3_rollback = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: seq3.epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq3.prev_checkpoint_hash,
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0xAA; 32],
        issued_at: 1070,
        not_after: 1270,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![m2],
        revocations: vec![],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq3_rollback,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1070,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&seq3_rollback),
        &state3,
        &rig_ctx(&rig, 1070, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedRollback);
    assert_eq!(s, state3);
}

#[test]
fn cp3_d19_prefix_exact_m_greater_than_nprev_fork() {
    let rig = test_rig();
    let (state3, seq3, m1, m2, epoch) = setup_seq2_with_rev(&rig);
    // Same seq=3, exact prefix (rev1 matches), M=2 > Nprev=1 (extension with rev2)
    let rev1 = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    let rev2 = make_signed_revocation(&rig, &m2, epoch, 2, rev1_hash);
    let rev2_hash = revocation_event_hash(&rev2).unwrap();
    let mut alt = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: seq3.epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq3.prev_checkpoint_hash,
        event_sequence: 2,
        event_head_hash: rev2_hash,
        mesh_log_digest: [0xBB; 32],
        issued_at: 1070,
        not_after: 1270,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![],
        revocations: vec![rev1, rev2],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut alt,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1070,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&alt),
        &state3,
        &rig_ctx(&rig, 1070, Some(rig.cert_fp)),
    );
    // Prefix exact at Nprev=1 (rev1 matches), M=2 > Nprev=1 => CheckpointForkConflict
    assert_eq!(r, CheckpointAdmissionResult::CheckpointForkConflictRecorded);
    let current_hash = checkpoint_hash(&seq3).unwrap();
    let candidate_hash = checkpoint_hash(&alt).unwrap();
    if let AcceptedRosterChainState::CheckpointForkConflict {
        epoch: e,
        sequence,
        hashes,
    } = &s
    {
        assert_eq!(*e, seq3.epoch);
        assert_eq!(*sequence, 3);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], current_hash);
        assert_eq!(hashes[1], candidate_hash);
    } else {
        panic!("expected CheckpointForkConflict");
    }
}

#[test]
fn cp3_d19_seq1_alternative_genesis_fork() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    // Genesis with m1 only
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Alternative seq=1 with DIFFERENT active roster (m2 instead of m1)
    let mut alt = make_genesis_checkpoint(&rig, vec![m2], [1u8; 32]);
    alt.mesh_log_digest = [0xBB; 32]; // different hash
    sign_checkpoint(
        &mut alt,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1000,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&alt),
        &state1,
        &rig_ctx(&rig, 1000, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::CheckpointForkConflictRecorded);
    assert!(matches!(
        s,
        AcceptedRosterChainState::CheckpointForkConflict { .. }
    ));
}

// ─── Remaining: owner expired + nested enum + duplicate/rollback equality ─

#[test]
fn cp3_owner_cert_expired_rejected_owner() {
    let rig = test_rig();
    use crate::keys::IdentityKey as _;
    // Cert with not_after in the past relative to effective_now
    let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
        &rig.root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: rig.hh.clone(),
            p_pub: rig.owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 500,
        },
        crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    cert.not_after = Some(900); // expires at 900
    cert.nonce = vec![0xEE; 16];
    let sb = cert.signing_bytes().unwrap();
    cert.signature = rig.root_kp.sign(&sb).unwrap();
    let cert_bytes = owner_cert_bytes(&cert);
    let fp = owner_cert_fingerprint(&cert).unwrap();
    let m1 = make_member(&rig, &rig.m1_kp);
    let mut genesis = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch: derive_epoch(&rig.hh, &rig.owner_pub, &[1u8; 32]),
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0u8; 32],
        issued_at: 1000,
        not_after: 1200,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: fp,
        active: vec![m1],
        revocations: vec![],
        owner_person_cert: cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let preimage = checkpoint_preimage(&genesis).unwrap();
    genesis.signature = rig.owner_kp.sign(&preimage).unwrap();
    // effective_now=1000 > cert.not_after=900 => cert expired => RejectedOwner
    let (s, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedOwner);
    assert_eq!(s, AcceptedRosterChainState::NoGenesis);
}

#[test]
fn cp3_duplicate_idempotent_state_equality() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1], [1u8; 32]);
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    let (s, r) = admit_checkpoint(
        &canonical(&genesis),
        &state1,
        &rig_ctx(&rig, 1000, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::IdempotentDuplicate);
    assert_eq!(s, state1); // full state equality
}

#[test]
fn cp3_issued_at_rollback_state_equality() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone()], [1u8; 32]);
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    let mut rollback = genesis.clone();
    rollback.issued_at = 999;
    rollback.not_after = 1199;
    rollback.mesh_log_digest = [0xFF; 32];
    sign_checkpoint(
        &mut rollback,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1000,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&rollback),
        &state1,
        &rig_ctx(&rig, 1000, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedTemporal);
    assert_eq!(s, state1); // full state equality
}

// ─── G: revoked not in genesis + target fp mismatch + duplicate active ──

#[test]
fn cp3_revoked_not_in_genesis_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let m3_kp = det_kp(&[
        60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let m3 = make_member(&rig, &m3_kp);
    // Genesis with m1+m2 only
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members, [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Revocation for m3 (NOT in genesis)
    let rev_m3 = make_signed_revocation(&rig, &m3, epoch, 1, [0u8; 32]);
    let rev_hash = revocation_event_hash(&rev_m3).unwrap();
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev_hash,
        mesh_log_digest: [0xCC; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: vec![m1, m2],
        revocations: vec![rev_m3],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state1);
}

#[test]
fn cp3_revocation_target_fp_mismatch_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members, [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    // Revocation with wrong machine_cert_fingerprint
    let mut bad_rev = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id: m1.m_id.clone(),
        m_pub: m1.m_pub.clone(),
        machine_cert_fingerprint: [0xEE; 32], // WRONG fp
        revoked_at: 1050,
        reason: RevocationReason::Lost,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_revocation(
        &mut bad_rev,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let rev_hash = revocation_event_hash(&bad_rev).unwrap();
    let mut active_after: Vec<MachineRosterMemberV1> = vec![m2];
    active_after.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev_hash,
        mesh_log_digest: [0xDD; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active_after,
        revocations: vec![bad_rev],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (s, r) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    assert_eq!(r, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, state1);
}

#[test]
fn cp3_active_duplicate_member_rejected() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    // Active with same member twice
    let genesis = make_genesis_checkpoint(&rig, vec![m1.clone(), m1], [1u8; 32]);
    let (s, result) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    assert_eq!(result, CheckpointAdmissionResult::RejectedProjection);
    assert_eq!(s, AcceptedRosterChainState::NoGenesis);
}

// ─── EventFork exact fields + terminal + currency ───────────────────────

#[test]
fn cp3_event_fork_exact_fields_terminal_currency() {
    let rig = test_rig();
    let m1 = make_member(&rig, &rig.m1_kp);
    let m2 = make_member(&rig, &rig.m2_kp);
    let mut members = vec![m1.clone(), m2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let genesis = make_genesis_checkpoint(&rig, members.clone(), [1u8; 32]);
    let genesis_hash = checkpoint_hash(&genesis).unwrap();
    let epoch = genesis.epoch;
    let (state1, _) = admit_checkpoint(
        &canonical(&genesis),
        &AcceptedRosterChainState::NoGenesis,
        &rig_ctx(&rig, 1000, None),
    );
    let rev1 = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    let rev1_hash = revocation_event_hash(&rev1).unwrap();
    let mut active1: Vec<MachineRosterMemberV1> = vec![m2.clone()];
    active1.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut seq2 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev1_hash,
        mesh_log_digest: [0x22; 32],
        issued_at: 1050,
        not_after: 1250,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active1.clone(),
        revocations: vec![rev1],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq2,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1050,
    )
    .unwrap();
    let (state2, _) = admit_checkpoint(
        &canonical(&seq2),
        &state1,
        &rig_ctx(&rig, 1050, Some(rig.cert_fp)),
    );
    // seq=3 same event_seq=1 but different head
    let seq2_hash = checkpoint_hash(&seq2).unwrap();
    let mut rev1_alt = make_signed_revocation(&rig, &m1, epoch, 1, [0u8; 32]);
    rev1_alt.revoked_at = 1099;
    sign_revocation(
        &mut rev1_alt,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1099,
    )
    .unwrap();
    let rev1_alt_hash = revocation_event_hash(&rev1_alt).unwrap();
    let mut seq3 = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: rig.hh.clone(),
        epoch,
        checkpoint_sequence: 3,
        prev_checkpoint_hash: seq2_hash,
        event_sequence: 1,
        event_head_hash: rev1_alt_hash,
        mesh_log_digest: [0x33; 32],
        issued_at: 1060,
        not_after: 1260,
        owner_p_id: rig.p_id.clone(),
        owner_cert_fingerprint: rig.cert_fp,
        active: active1,
        revocations: vec![rev1_alt],
        owner_person_cert: rig.cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    sign_checkpoint(
        &mut seq3,
        &rig.owner_kp,
        &rig.cert_bytes,
        &rig.hh,
        &rig.root_pub,
        &rig.p_id,
        &rig.owner_pub,
        1060,
    )
    .unwrap();
    let (state3, result) = admit_checkpoint(
        &canonical(&seq3),
        &state2,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(result, CheckpointAdmissionResult::EventForkConflictRecorded);
    // Exact fields
    if let AcceptedRosterChainState::EventForkConflict {
        epoch: e,
        sequence: s,
        hashes,
    } = &state3
    {
        assert_eq!(*e, epoch);
        assert_eq!(*s, 1);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], rev1_hash);
        assert_eq!(hashes[1], rev1_alt_hash);
    } else {
        panic!("expected EventForkConflict");
    }
    // Terminal
    let (s4, r4) = admit_checkpoint(
        &canonical(&seq2),
        &state3,
        &rig_ctx(&rig, 1060, Some(rig.cert_fp)),
    );
    assert_eq!(r4, CheckpointAdmissionResult::EventForkConflictRecorded);
    assert_eq!(s4, state3);
    // Currency
    let m1_id = m1.m_id.clone();
    let ctx = rig_ctx(&rig, 1060, Some(rig.cert_fp));
    assert_eq!(
        derive_machine_currency(&state3, &m1_id, &ctx),
        MachineCurrencyResult::Unavailable {
            reason: UnavailableReason::EventForkConflict
        }
    );
}

// ─── Vector fixture regeneration ────────────────────────────────────────

#[test]
#[ignore = "manual public fixture regeneration helper"]
fn regenerate_vector_fixture() {
    use crate::keys::IdentityKey as _;
    let root_kp = crate::keys::P256Keypair::from_secret_scalar(&[
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ])
    .unwrap();
    let owner_kp = crate::keys::P256Keypair::from_secret_scalar(&[
        2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ])
    .unwrap();
    let m1_kp = crate::keys::P256Keypair::from_secret_scalar(&[
        3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ])
    .unwrap();
    let m2_kp = crate::keys::P256Keypair::from_secret_scalar(&[
        4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ])
    .unwrap();
    let root_pub = root_kp.public();
    let owner_pub = owner_kp.public();
    let m1_pub = m1_kp.public();
    let m2_pub = m2_kp.public();
    let hh = crate::ids::derive_household_id(&root_pub);
    let p_id = crate::person_cert::derive_person_id(&owner_pub);
    let m1_id = crate::ids::derive_machine_id(&m1_pub);
    let m2_id = crate::ids::derive_machine_id(&m2_pub);

    // Owner cert (fixed nonce)
    let mut owner_cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
        &root_kp,
        crate::person_cert::SignOwnerOptions {
            hh_id: hh.clone(),
            p_pub: owner_pub.clone(),
            display_name: "Owner".into(),
            issued_at: 1000,
        },
        crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    owner_cert.nonce = vec![0xDE; 16];
    let sb = owner_cert.signing_bytes().unwrap();
    owner_cert.signature = root_kp.sign(&sb).unwrap();
    let owner_cert_bytes = crate::cbor::to_canonical_vec(&owner_cert).unwrap();
    let owner_cert_fp = owner_cert_fingerprint(&owner_cert).unwrap();

    // Machine certs
    let mcert1 = make_machine_cert(&root_kp, &m1_pub, &hh);
    let mcert1_bytes = crate::cbor::to_canonical_vec(&mcert1).unwrap();
    let mcert1_fp = machine_cert_fingerprint(&mcert1).unwrap();
    let mcert2 = make_machine_cert(&root_kp, &m2_pub, &hh);
    let mcert2_bytes = crate::cbor::to_canonical_vec(&mcert2).unwrap();
    let mcert2_fp = machine_cert_fingerprint(&mcert2).unwrap();

    // Members
    let member1 = MachineRosterMemberV1 {
        m_id: m1_id.clone(),
        m_pub: m1_pub.clone(),
        machine_cert: mcert1_bytes.clone(),
        machine_cert_fingerprint: mcert1_fp,
    };
    let member2 = MachineRosterMemberV1 {
        m_id: m2_id.clone(),
        m_pub: m2_pub.clone(),
        machine_cert: mcert2_bytes.clone(),
        machine_cert_fingerprint: mcert2_fp,
    };
    let member1_bytes = crate::cbor::to_canonical_vec(&member1).unwrap();
    let member2_bytes = crate::cbor::to_canonical_vec(&member2).unwrap();

    // Epoch
    let epoch_nonce = [0x42u8; 32];
    let epoch = derive_epoch(&hh, &owner_pub, &epoch_nonce);

    // Genesis checkpoint
    let mut members = vec![member1.clone(), member2.clone()];
    members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut genesis = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: hh.clone(),
        epoch,
        checkpoint_sequence: 1,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 0,
        event_head_hash: [0u8; 32],
        mesh_log_digest: [0u8; 32],
        issued_at: 1000,
        not_after: 1300,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: owner_cert_fp,
        active: members.clone(),
        revocations: vec![],
        owner_person_cert: owner_cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let ctx = RosterAuthorityContext {
        hh_pub: &root_pub,
        expected_hh_id: &hh,
        expected_p_id: &p_id,
        expected_p_pub: &owner_pub,
        effective_now: 1000,
    };
    super::sign_checkpoint(&mut genesis, &owner_kp, &owner_cert_bytes, &ctx).unwrap();
    let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
    let genesis_preimage = checkpoint_preimage(&genesis).unwrap();
    let genesis_hash = checkpoint_hash(&genesis).unwrap();

    // Revocation of member1
    let mut rev = MachineRosterRevocationV1 {
        v: REVOCATION_VERSION,
        kind: REVOCATION_KIND.into(),
        hh_id: hh.clone(),
        epoch,
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id: m1_id.clone(),
        m_pub: m1_pub.clone(),
        machine_cert_fingerprint: mcert1_fp,
        revoked_at: 1050,
        reason: RevocationReason::Compromised,
        cascade: RevocationCascade::MachineOnly,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: owner_cert_fp,
        owner_person_cert: owner_cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let ctx_rev = RosterAuthorityContext {
        hh_pub: &root_pub,
        expected_hh_id: &hh,
        expected_p_id: &p_id,
        expected_p_pub: &owner_pub,
        effective_now: 1050,
    };
    super::sign_revocation(&mut rev, &owner_kp, &owner_cert_bytes, &ctx_rev).unwrap();
    let rev_bytes = crate::cbor::to_canonical_vec(&rev).unwrap();
    let rev_preimage = revocation_preimage(&rev).unwrap();
    let rev_hash = revocation_event_hash(&rev).unwrap();

    // Refresh checkpoint (with revocation)
    let mut active_after = vec![member2.clone()];
    active_after.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    let mut refresh = MachineRosterCheckpointV1 {
        v: CHECKPOINT_VERSION,
        kind: CHECKPOINT_KIND.into(),
        hh_id: hh.clone(),
        epoch,
        checkpoint_sequence: 2,
        prev_checkpoint_hash: genesis_hash,
        event_sequence: 1,
        event_head_hash: rev_hash,
        mesh_log_digest: [0x11; 32],
        issued_at: 1050,
        not_after: 1350,
        owner_p_id: p_id.clone(),
        owner_cert_fingerprint: owner_cert_fp,
        active: active_after,
        revocations: vec![rev.clone()],
        owner_person_cert: owner_cert_bytes.clone(),
        signature: P256Signature([0u8; 64]),
    };
    let ctx2 = RosterAuthorityContext {
        hh_pub: &root_pub,
        expected_hh_id: &hh,
        expected_p_id: &p_id,
        expected_p_pub: &owner_pub,
        effective_now: 1050,
    };
    super::sign_checkpoint(&mut refresh, &owner_kp, &owner_cert_bytes, &ctx2).unwrap();
    let refresh_bytes = crate::cbor::to_canonical_vec(&refresh).unwrap();
    let refresh_preimage = checkpoint_preimage(&refresh).unwrap();
    let refresh_hash = checkpoint_hash(&refresh).unwrap();

    let json = serde_json::json!({
        "contract": "household-machine-roster-currency-v1",
        "version": 1,
        "meta": { "generated_by": "household-rs machine_roster_authority Rust oracle", "about": "public synthetic household roster oracle; public material only" },
        "keys": {
            "root_pub_hex": hex::encode(root_pub.as_bytes()),
            "owner_pub_hex": hex::encode(owner_pub.as_bytes()),
            "member1_pub_hex": hex::encode(m1_pub.as_bytes()),
            "member2_pub_hex": hex::encode(m2_pub.as_bytes()),
            "root_hh_id": hh.as_str(),
            "owner_p_id": p_id.0.as_str(),
            "member1_m_id": m1_id.as_str(),
            "member2_m_id": m2_id.as_str(),
        },
        "owner_cert": { "canonical_hex": hex::encode(&owner_cert_bytes), "fingerprint_hex": hex::encode(owner_cert_fp) },
        "member1_cert": { "canonical_hex": hex::encode(&mcert1_bytes), "fingerprint_hex": hex::encode(mcert1_fp) },
        "member2_cert": { "canonical_hex": hex::encode(&mcert2_bytes), "fingerprint_hex": hex::encode(mcert2_fp) },
        "member1": { "canonical_hex": hex::encode(&member1_bytes) },
        "member2": { "canonical_hex": hex::encode(&member2_bytes) },
        "epoch": { "nonce_hex": hex::encode(epoch_nonce), "epoch_hex": hex::encode(epoch) },
        "genesis_checkpoint": { "canonical_hex": hex::encode(&genesis_bytes), "preimage_hex": hex::encode(&genesis_preimage), "hash_hex": hex::encode(genesis_hash), "signature_hex": hex::encode(genesis.signature.0) },
        "revocation": { "canonical_hex": hex::encode(&rev_bytes), "preimage_hex": hex::encode(&rev_preimage), "event_hash_hex": hex::encode(rev_hash), "signature_hex": hex::encode(rev.signature.0) },
        "refresh_checkpoint": { "canonical_hex": hex::encode(&refresh_bytes), "preimage_hex": hex::encode(&refresh_preimage), "hash_hex": hex::encode(refresh_hash), "signature_hex": hex::encode(refresh.signature.0) },
        "enum_encodings": { "reason_compromised": 0, "reason_lost": 1, "reason_retired": 2, "reason_replaced": 3, "reason_owner_action": 4, "cascade_machine_only": 0, "cascade_machine_and_dependents": 1 },
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

// ─── Vector fixture validation tests ────────────────────────────────────

const VECTOR_FIXTURE: &str = include_str!("../../tests/data/machine_roster_authority_v1.json");

fn load_fixture() -> serde_json::Value {
    serde_json::from_str(VECTOR_FIXTURE).unwrap()
}

#[test]
fn vector_fixture_contract_and_version() {
    let f = load_fixture();
    assert_eq!(f["contract"], "household-machine-roster-currency-v1");
    assert_eq!(f["version"], 1);
}

#[test]
fn vector_fixture_canonical_roundtrip_genesis() {
    let f = load_fixture();
    let genesis_hex = f["genesis_checkpoint"]["canonical_hex"].as_str().unwrap();
    let bytes = hex::decode(genesis_hex).unwrap();
    let decoded: MachineRosterCheckpointV1 = crate::cbor::from_canonical_slice(&bytes).unwrap();
    let reencoded = crate::cbor::to_canonical_vec(&decoded).unwrap();
    assert_eq!(bytes, reencoded);
}

#[test]
fn vector_fixture_canonical_roundtrip_revocation() {
    let f = load_fixture();
    let rev_hex = f["revocation"]["canonical_hex"].as_str().unwrap();
    let bytes = hex::decode(rev_hex).unwrap();
    let decoded: MachineRosterRevocationV1 = crate::cbor::from_canonical_slice(&bytes).unwrap();
    let reencoded = crate::cbor::to_canonical_vec(&decoded).unwrap();
    assert_eq!(bytes, reencoded);
}

#[test]
fn vector_fixture_canonical_roundtrip_refresh() {
    let f = load_fixture();
    let refresh_hex = f["refresh_checkpoint"]["canonical_hex"].as_str().unwrap();
    let bytes = hex::decode(refresh_hex).unwrap();
    let decoded: MachineRosterCheckpointV1 = crate::cbor::from_canonical_slice(&bytes).unwrap();
    let reencoded = crate::cbor::to_canonical_vec(&decoded).unwrap();
    assert_eq!(bytes, reencoded);
}

#[test]
fn vector_fixture_canonical_roundtrip_members() {
    let f = load_fixture();
    for key in ["member1", "member2"] {
        let member_hex = f[key]["canonical_hex"].as_str().unwrap();
        let bytes = hex::decode(member_hex).unwrap();
        let decoded: MachineRosterMemberV1 = crate::cbor::from_canonical_slice(&bytes).unwrap();
        let reencoded = crate::cbor::to_canonical_vec(&decoded).unwrap();
        assert_eq!(bytes, reencoded);
    }
}

#[test]
fn vector_fixture_hash_determinism() {
    let f = load_fixture();
    let genesis_hex = f["genesis_checkpoint"]["canonical_hex"].as_str().unwrap();
    let bytes = hex::decode(genesis_hex).unwrap();
    let decoded: MachineRosterCheckpointV1 = crate::cbor::from_canonical_slice(&bytes).unwrap();
    let computed_hash = checkpoint_hash(&decoded).unwrap();
    let expected_hash = hex::decode(f["genesis_checkpoint"]["hash_hex"].as_str().unwrap()).unwrap();
    assert_eq!(computed_hash.as_slice(), expected_hash.as_slice());
}

#[test]
fn vector_fixture_preimage_determinism() {
    let f = load_fixture();
    let genesis_hex = f["genesis_checkpoint"]["canonical_hex"].as_str().unwrap();
    let bytes = hex::decode(genesis_hex).unwrap();
    let decoded: MachineRosterCheckpointV1 = crate::cbor::from_canonical_slice(&bytes).unwrap();
    let computed_preimage = checkpoint_preimage(&decoded).unwrap();
    let expected_preimage =
        hex::decode(f["genesis_checkpoint"]["preimage_hex"].as_str().unwrap()).unwrap();
    assert_eq!(computed_preimage, expected_preimage);
}

#[test]
fn vector_fixture_revocation_hash_and_preimage() {
    let f = load_fixture();
    let rev_hex = f["revocation"]["canonical_hex"].as_str().unwrap();
    let bytes = hex::decode(rev_hex).unwrap();
    let decoded: MachineRosterRevocationV1 = crate::cbor::from_canonical_slice(&bytes).unwrap();
    let computed_hash = revocation_event_hash(&decoded).unwrap();
    let expected_hash = hex::decode(f["revocation"]["event_hash_hex"].as_str().unwrap()).unwrap();
    assert_eq!(computed_hash.as_slice(), expected_hash.as_slice());
    let computed_preimage = revocation_preimage(&decoded).unwrap();
    let expected_preimage = hex::decode(f["revocation"]["preimage_hex"].as_str().unwrap()).unwrap();
    assert_eq!(computed_preimage, expected_preimage);
}

#[test]
fn vector_fixture_signature_verify_all_three() {
    let f = load_fixture();
    let owner_pub = fixture_owner_pub(&f);
    // Genesis: signature_hex == embedded, then verify
    let genesis_bytes =
        hex::decode(f["genesis_checkpoint"]["canonical_hex"].as_str().unwrap()).unwrap();
    let genesis: MachineRosterCheckpointV1 =
        crate::cbor::from_canonical_slice(&genesis_bytes).unwrap();
    let expected_gen_sig =
        hex::decode(f["genesis_checkpoint"]["signature_hex"].as_str().unwrap()).unwrap();
    assert_eq!(genesis.signature.0.as_slice(), expected_gen_sig.as_slice());
    let gp = checkpoint_preimage(&genesis).unwrap();
    assert!(crate::keys::verify_signature(&owner_pub, &gp, &genesis.signature).is_ok());
    // Revocation: signature_hex == embedded, then verify
    let rev_bytes = hex::decode(f["revocation"]["canonical_hex"].as_str().unwrap()).unwrap();
    let rev: MachineRosterRevocationV1 = crate::cbor::from_canonical_slice(&rev_bytes).unwrap();
    let expected_rev_sig = hex::decode(f["revocation"]["signature_hex"].as_str().unwrap()).unwrap();
    assert_eq!(rev.signature.0.as_slice(), expected_rev_sig.as_slice());
    let rp = revocation_preimage(&rev).unwrap();
    assert!(crate::keys::verify_signature(&owner_pub, &rp, &rev.signature).is_ok());
    // Refresh: signature_hex == embedded, then verify
    let refresh_bytes =
        hex::decode(f["refresh_checkpoint"]["canonical_hex"].as_str().unwrap()).unwrap();
    let refresh: MachineRosterCheckpointV1 =
        crate::cbor::from_canonical_slice(&refresh_bytes).unwrap();
    let expected_ref_sig =
        hex::decode(f["refresh_checkpoint"]["signature_hex"].as_str().unwrap()).unwrap();
    assert_eq!(refresh.signature.0.as_slice(), expected_ref_sig.as_slice());
    let fp = checkpoint_preimage(&refresh).unwrap();
    assert!(crate::keys::verify_signature(&owner_pub, &fp, &refresh.signature).is_ok());
}

#[test]
fn vector_fixture_epoch_determinism() {
    let f = load_fixture();
    let hh_str = f["keys"]["root_hh_id"].as_str().unwrap();
    let hh = HouseholdId(hh_str.to_string());
    let owner_pub_hex = f["keys"]["owner_pub_hex"].as_str().unwrap();
    let owner_pub_bytes = hex::decode(owner_pub_hex).unwrap();
    let owner_pub = P256PublicKey(owner_pub_bytes.try_into().unwrap());
    let nonce_hex = f["epoch"]["nonce_hex"].as_str().unwrap();
    let nonce_bytes = hex::decode(nonce_hex).unwrap();
    let nonce: [u8; 32] = nonce_bytes.try_into().unwrap();
    let computed = derive_epoch(&hh, &owner_pub, &nonce);
    let expected = hex::decode(f["epoch"]["epoch_hex"].as_str().unwrap()).unwrap();
    assert_eq!(computed.as_slice(), expected.as_slice());
}

#[test]
fn vector_fixture_enum_encodings() {
    let f = load_fixture();
    assert_eq!(f["enum_encodings"]["reason_compromised"], 0);
    assert_eq!(f["enum_encodings"]["reason_lost"], 1);
    assert_eq!(f["enum_encodings"]["reason_retired"], 2);
    assert_eq!(f["enum_encodings"]["reason_replaced"], 3);
    assert_eq!(f["enum_encodings"]["reason_owner_action"], 4);
    assert_eq!(f["enum_encodings"]["cascade_machine_only"], 0);
    assert_eq!(f["enum_encodings"]["cascade_machine_and_dependents"], 1);
    // Verify serialize matches
    assert_eq!(
        crate::cbor::to_canonical_vec(&RevocationReason::Compromised).unwrap(),
        vec![0u8]
    );
    assert_eq!(
        crate::cbor::to_canonical_vec(&RevocationReason::OwnerAction).unwrap(),
        vec![4u8]
    );
    assert_eq!(
        crate::cbor::to_canonical_vec(&RevocationCascade::MachineAndDependents).unwrap(),
        vec![1u8]
    );
}

#[test]
fn vector_fixture_tamper_genesis_hash_changes() {
    let f = load_fixture();
    let owner_pub = fixture_owner_pub(&f);
    let genesis_hex = f["genesis_checkpoint"]["canonical_hex"].as_str().unwrap();
    let bytes = hex::decode(genesis_hex).unwrap();
    let decoded: MachineRosterCheckpointV1 = crate::cbor::from_canonical_slice(&bytes).unwrap();
    let original_hash = checkpoint_hash(&decoded).unwrap();
    let mut tampered = decoded.clone();
    tampered.mesh_log_digest = [0xFF; 32];
    let tampered_hash = checkpoint_hash(&tampered).unwrap();
    assert_ne!(original_hash, tampered_hash);
    let tampered_preimage = checkpoint_preimage(&tampered).unwrap();
    assert!(
        crate::keys::verify_signature(&owner_pub, &tampered_preimage, &decoded.signature).is_err()
    );
}

#[test]
fn vector_fixture_tamper_revocation_hash_changes() {
    let f = load_fixture();
    let owner_pub = fixture_owner_pub(&f);
    let rev_hex = f["revocation"]["canonical_hex"].as_str().unwrap();
    let bytes = hex::decode(rev_hex).unwrap();
    let decoded: MachineRosterRevocationV1 = crate::cbor::from_canonical_slice(&bytes).unwrap();
    let original_hash = revocation_event_hash(&decoded).unwrap();
    let mut tampered = decoded.clone();
    tampered.revoked_at = 9999;
    let tampered_hash = revocation_event_hash(&tampered).unwrap();
    assert_ne!(original_hash, tampered_hash);
    let tampered_preimage = revocation_preimage(&tampered).unwrap();
    assert!(
        crate::keys::verify_signature(&owner_pub, &tampered_preimage, &decoded.signature).is_err()
    );
}

fn fixture_owner_pub(f: &serde_json::Value) -> P256PublicKey {
    let owner_pub_hex = f["keys"]["owner_pub_hex"].as_str().unwrap();
    let owner_pub_bytes = hex::decode(owner_pub_hex).unwrap();
    P256PublicKey(owner_pub_bytes.try_into().unwrap())
}

#[test]
fn vector_fixture_fingerprint_consistency() {
    let f = load_fixture();
    let owner_cert_hex = f["owner_cert"]["canonical_hex"].as_str().unwrap();
    let cert_bytes = hex::decode(owner_cert_hex).unwrap();
    let cert: crate::person_cert::PersonCert =
        crate::cbor::from_canonical_slice(&cert_bytes).unwrap();
    let computed_fp = owner_cert_fingerprint(&cert).unwrap();
    let expected_fp = hex::decode(f["owner_cert"]["fingerprint_hex"].as_str().unwrap()).unwrap();
    assert_eq!(computed_fp.as_slice(), expected_fp.as_slice());
}

#[test]
fn vector_fixture_refresh_hash_preimage() {
    let f = load_fixture();
    let refresh_bytes =
        hex::decode(f["refresh_checkpoint"]["canonical_hex"].as_str().unwrap()).unwrap();
    let refresh: MachineRosterCheckpointV1 =
        crate::cbor::from_canonical_slice(&refresh_bytes).unwrap();
    let computed_hash = checkpoint_hash(&refresh).unwrap();
    let expected_hash = hex::decode(f["refresh_checkpoint"]["hash_hex"].as_str().unwrap()).unwrap();
    assert_eq!(computed_hash.as_slice(), expected_hash.as_slice());
    let computed_preimage = checkpoint_preimage(&refresh).unwrap();
    let expected_preimage =
        hex::decode(f["refresh_checkpoint"]["preimage_hex"].as_str().unwrap()).unwrap();
    assert_eq!(computed_preimage, expected_preimage);
}

#[test]
fn vector_fixture_member_cert_fingerprints() {
    let f = load_fixture();
    for (key, member_key) in [("member1_cert", "member1"), ("member2_cert", "member2")] {
        let cert_bytes = hex::decode(f[key]["canonical_hex"].as_str().unwrap()).unwrap();
        let cert: crate::machine_cert::MachineCert =
            crate::cbor::from_canonical_slice(&cert_bytes).unwrap();
        let computed_fp = machine_cert_fingerprint(&cert).unwrap();
        let expected_fp = hex::decode(f[key]["fingerprint_hex"].as_str().unwrap()).unwrap();
        assert_eq!(computed_fp.as_slice(), expected_fp.as_slice());
        // Member links cert fingerprint
        let member_bytes = hex::decode(f[member_key]["canonical_hex"].as_str().unwrap()).unwrap();
        let member: MachineRosterMemberV1 =
            crate::cbor::from_canonical_slice(&member_bytes).unwrap();
        assert_eq!(
            member.machine_cert_fingerprint.as_slice(),
            expected_fp.as_slice()
        );
    }
}

#[test]
fn vector_fixture_bstr_encoding() {
    use ciborium::value::Value;
    let f = load_fixture();
    // Genesis checkpoint: bstr32 epoch/hashes/fingerprints, bstr64 signature, bstr-var owner_person_cert
    let genesis_bytes =
        hex::decode(f["genesis_checkpoint"]["canonical_hex"].as_str().unwrap()).unwrap();
    let val: Value = ciborium::de::from_reader(genesis_bytes.as_slice()).unwrap();
    let entries = match &val {
        Value::Map(e) => e,
        _ => panic!("genesis not a map"),
    };
    for (k, v) in entries {
        let key = match k {
            Value::Text(t) => t.as_str(),
            _ => continue,
        };
        match key {
            "epoch"
            | "prev_checkpoint_hash"
            | "event_head_hash"
            | "mesh_log_digest"
            | "owner_cert_fingerprint" => {
                assert!(
                    matches!(v, Value::Bytes(b) if b.len() == 32),
                    "expected bstr32 for {key}"
                );
            }
            "signature" => {
                assert!(
                    matches!(v, Value::Bytes(b) if b.len() == 64),
                    "expected bstr64 for signature"
                );
            }
            "owner_person_cert" => {
                assert!(
                    matches!(v, Value::Bytes(b) if !b.is_empty()),
                    "expected bstr-var for owner_person_cert"
                );
            }
            _ => {}
        }
    }
    // Member: bstr33 m_pub, bstr32 machine_cert_fingerprint, bstr-var machine_cert
    let member_bytes = hex::decode(f["member1"]["canonical_hex"].as_str().unwrap()).unwrap();
    let mval: Value = ciborium::de::from_reader(member_bytes.as_slice()).unwrap();
    let mentries = match &mval {
        Value::Map(e) => e,
        _ => panic!("member not a map"),
    };
    for (k, v) in mentries {
        let key = match k {
            Value::Text(t) => t.as_str(),
            _ => continue,
        };
        match key {
            "m_pub" => assert!(
                matches!(v, Value::Bytes(b) if b.len() == 33),
                "expected bstr33 for m_pub"
            ),
            "machine_cert_fingerprint" => assert!(
                matches!(v, Value::Bytes(b) if b.len() == 32),
                "expected bstr32 for machine_cert_fingerprint"
            ),
            "machine_cert" => assert!(
                matches!(v, Value::Bytes(b) if !b.is_empty()),
                "expected bstr-var for machine_cert"
            ),
            _ => {}
        }
    }
    // Revocation: bstr32 epoch/prev_event_hash/machine_cert_fingerprint/owner_cert_fingerprint, bstr64 signature, bstr-var owner_person_cert
    let rev_bytes = hex::decode(f["revocation"]["canonical_hex"].as_str().unwrap()).unwrap();
    let rval: Value = ciborium::de::from_reader(rev_bytes.as_slice()).unwrap();
    let rentries = match &rval {
        Value::Map(e) => e,
        _ => panic!("revocation not a map"),
    };
    for (k, v) in rentries {
        let key = match k {
            Value::Text(t) => t.as_str(),
            _ => continue,
        };
        match key {
            "epoch" | "prev_event_hash" | "machine_cert_fingerprint" | "owner_cert_fingerprint" => {
                assert!(
                    matches!(v, Value::Bytes(b) if b.len() == 32),
                    "expected bstr32 for {key}"
                );
            }
            "signature" => assert!(
                matches!(v, Value::Bytes(b) if b.len() == 64),
                "expected bstr64 for signature"
            ),
            "owner_person_cert" => assert!(
                matches!(v, Value::Bytes(b) if !b.is_empty()),
                "expected bstr-var"
            ),
            _ => {}
        }
    }
}

#[test]
fn vector_fixture_cross_link_coherence() {
    let f = load_fixture();
    let root_pub_hex = f["keys"]["root_pub_hex"].as_str().unwrap();
    let root_pub_bytes = hex::decode(root_pub_hex).unwrap();
    let root_pub = P256PublicKey(root_pub_bytes.try_into().unwrap());
    let hh_str = f["keys"]["root_hh_id"].as_str().unwrap();
    let hh = HouseholdId(hh_str.to_string());
    let m1_id_str = f["keys"]["member1_m_id"].as_str().unwrap();
    let m2_id_str = f["keys"]["member2_m_id"].as_str().unwrap();
    let m1_pub_hex = f["keys"]["member1_pub_hex"].as_str().unwrap();
    let m2_pub_hex = f["keys"]["member2_pub_hex"].as_str().unwrap();

    // Owner cert verifies under root/household
    let owner_cert_bytes = hex::decode(f["owner_cert"]["canonical_hex"].as_str().unwrap()).unwrap();
    let owner_cert: crate::person_cert::PersonCert =
        crate::cbor::from_canonical_slice(&owner_cert_bytes).unwrap();
    assert!(owner_cert.verify(&hh, &root_pub, 1000).is_ok());
    // Cross-link: root_pub derives hh; owner_cert p_pub/p_id match JSON
    assert_eq!(crate::ids::derive_household_id(&root_pub), hh);
    let owner_pub = fixture_owner_pub(&f);
    assert_eq!(owner_cert.p_pub, owner_pub);
    let owner_p_id_str = f["keys"]["owner_p_id"].as_str().unwrap();
    assert_eq!(owner_cert.p_id.0.as_str(), owner_p_id_str);

    // MachineCerts verify under root
    let mcert1_bytes = hex::decode(f["member1_cert"]["canonical_hex"].as_str().unwrap()).unwrap();
    let mcert1: crate::machine_cert::MachineCert =
        crate::cbor::from_canonical_slice(&mcert1_bytes).unwrap();
    assert!(mcert1.verify(&root_pub).is_ok());
    let mcert2_bytes = hex::decode(f["member2_cert"]["canonical_hex"].as_str().unwrap()).unwrap();
    let mcert2: crate::machine_cert::MachineCert =
        crate::cbor::from_canonical_slice(&mcert2_bytes).unwrap();
    assert!(mcert2.verify(&root_pub).is_ok());

    // Members: m_id/m_pub match keys JSON, machine_cert bytes == cert fixture, fingerprint matches
    let member1_bytes = hex::decode(f["member1"]["canonical_hex"].as_str().unwrap()).unwrap();
    let member1: MachineRosterMemberV1 = crate::cbor::from_canonical_slice(&member1_bytes).unwrap();
    assert_eq!(member1.m_id.as_str(), m1_id_str);
    assert_eq!(hex::encode(member1.m_pub.as_bytes()), m1_pub_hex);
    assert_eq!(member1.machine_cert, mcert1_bytes);
    assert_eq!(
        hex::encode(member1.machine_cert_fingerprint),
        f["member1_cert"]["fingerprint_hex"].as_str().unwrap()
    );

    let member2_bytes = hex::decode(f["member2"]["canonical_hex"].as_str().unwrap()).unwrap();
    let member2: MachineRosterMemberV1 = crate::cbor::from_canonical_slice(&member2_bytes).unwrap();
    assert_eq!(member2.m_id.as_str(), m2_id_str);
    assert_eq!(hex::encode(member2.m_pub.as_bytes()), m2_pub_hex);
    assert_eq!(member2.machine_cert, mcert2_bytes);
    assert_eq!(
        hex::encode(member2.machine_cert_fingerprint),
        f["member2_cert"]["fingerprint_hex"].as_str().unwrap()
    );

    // Genesis: active == 2 members sorted, revocations empty
    let genesis_bytes =
        hex::decode(f["genesis_checkpoint"]["canonical_hex"].as_str().unwrap()).unwrap();
    let genesis: MachineRosterCheckpointV1 =
        crate::cbor::from_canonical_slice(&genesis_bytes).unwrap();
    let mut expected_members = vec![member1.clone(), member2.clone()];
    expected_members.sort_by(|a, b| a.m_id.as_str().cmp(b.m_id.as_str()));
    assert_eq!(genesis.active, expected_members);
    assert!(genesis.revocations.is_empty());

    // Refresh: active == member2, revocations == [revocation], prev == genesis hash, event_head == rev hash
    let refresh_bytes =
        hex::decode(f["refresh_checkpoint"]["canonical_hex"].as_str().unwrap()).unwrap();
    let refresh: MachineRosterCheckpointV1 =
        crate::cbor::from_canonical_slice(&refresh_bytes).unwrap();
    assert_eq!(refresh.active, vec![member2]);
    let rev_bytes = hex::decode(f["revocation"]["canonical_hex"].as_str().unwrap()).unwrap();
    let revocation: MachineRosterRevocationV1 =
        crate::cbor::from_canonical_slice(&rev_bytes).unwrap();
    assert_eq!(refresh.revocations, vec![revocation]);
    let genesis_hash = hex::decode(f["genesis_checkpoint"]["hash_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        refresh.prev_checkpoint_hash.as_slice(),
        genesis_hash.as_slice()
    );
    let rev_hash = hex::decode(f["revocation"]["event_hash_hex"].as_str().unwrap()).unwrap();
    assert_eq!(refresh.event_head_hash.as_slice(), rev_hash.as_slice());
}

/// D-1 (B-ROSTER-ADAPTER v2 CFX-4, erratum1): `PeerExpectation` has no
/// production constructor — this exercises the only implementable code
/// this round, the `#[cfg(test)]` harness constructor, and pins that it
/// round-trips the fields it was given. RED-R23 (no production
/// constructor exists at all) is a compile-time property, not a runtime
/// assertion: it is proven by `from_snapshot` simply not existing
/// outside `#[cfg(test)]` anywhere in this file.
#[test]
fn peer_expectation_test_constructor_round_trips_its_fields() {
    let m_id = MachineId("m-peer-expectation-test".to_string());
    let checkpoint_hash = [9u8; 32];
    let expectation = PeerExpectation::injected_for_harness(
        checkpoint_hash,
        m_id.clone(),
        PeerSelectionSource::LocalOwnerPresentSelection,
    );
    assert_eq!(expectation.checkpoint_hash(), checkpoint_hash);
    assert_eq!(expectation.m_id(), &m_id);
    assert_eq!(
        expectation.source(),
        PeerSelectionSource::LocalOwnerPresentSelection
    );
}

/// RED-R17/POS-R8, mutant-proof: `checkpoint_hash`, `event_head_hash`
/// and `prev_checkpoint_hash` are three DISTINCT byte patterns here
/// (0xAA / 0xBB / 0xCC), not all-zero as a fresh-genesis fixture would
/// naturally have them. A `project()` that wired
/// `checkpoint_event_head` to `checkpoint_hash` or
/// `prev_checkpoint_hash` by mistake would still pass a test built on
/// an all-zero genesis (every field reads back as the same zero value)
/// but fails this one, since the three fields disagree.
#[test]
fn project_wires_checkpoint_event_head_to_event_head_hash_specifically() {
    let hh_id = HouseholdId("hh-project-field-wiring-test".to_string());
    let data = AcceptedRosterData {
        epoch: [1u8; 32],
        checkpoint_sequence: 7,
        checkpoint_hash: [0xAAu8; 32],
        prev_checkpoint_hash: [0xCCu8; 32],
        event_sequence: 3,
        event_head_hash: [0xBBu8; 32],
        predecessor_event_sequence: 2,
        predecessor_event_head_hash: [0xDDu8; 32],
        issued_at: 1,
        not_after: 999,
        owner_cert_fingerprint: [4u8; 32],
        genesis_basis: VerifiedGenesisRoster {
            epoch: [1u8; 32],
            members: Vec::new(),
        },
        active: Vec::new(),
        tombstones: Vec::new(),
    };
    let view = RosterSnapshotView::project(&hh_id, &data);
    assert_eq!(view.checkpoint_hash(), [0xAAu8; 32]);
    assert_eq!(view.checkpoint_event_head(), [0xBBu8; 32]);
    assert_ne!(view.checkpoint_event_head(), view.checkpoint_hash());
    assert_ne!(view.checkpoint_event_head(), data.prev_checkpoint_hash);
    assert_eq!(view.checkpoint_sequence(), 7);
    assert_eq!(view.not_after(), 999);
}

/// RED-R17, as a compile guard, not just runtime values (round 3, point
/// d): exhaustively destructures every field of `RosterSnapshotView`.
/// If a field is ever added without updating this pattern, this FAILS
/// TO COMPILE (E0027, pattern does not mention field) — caught before
/// any test even runs, not only if some other test happens to notice a
/// wrong value.
#[test]
fn roster_snapshot_view_field_set_is_exhaustively_matched_at_compile_time() {
    let view = RosterSnapshotView::project(
        &HouseholdId("hh-exhaustive-field-guard".to_string()),
        &AcceptedRosterData {
            epoch: [1u8; 32],
            checkpoint_sequence: 1,
            checkpoint_hash: [1u8; 32],
            prev_checkpoint_hash: [1u8; 32],
            event_sequence: 1,
            event_head_hash: [1u8; 32],
            predecessor_event_sequence: 0,
            predecessor_event_head_hash: [0u8; 32],
            issued_at: 1,
            not_after: 1,
            owner_cert_fingerprint: [1u8; 32],
            genesis_basis: VerifiedGenesisRoster {
                epoch: [1u8; 32],
                members: Vec::new(),
            },
            active: Vec::new(),
            tombstones: Vec::new(),
        },
    );
    let RosterSnapshotView {
        hh_id: _,
        checkpoint_hash: _,
        checkpoint_sequence: _,
        checkpoint_event_head: _,
        not_after: _,
        active: _,
        revoked_m_ids: _,
    } = view;
}

fn test_snapshot_for_responder(
    checkpoint_hash: [u8; 32],
    active_m_id: Option<&MachineId>,
    revoked_m_id: Option<&MachineId>,
) -> RosterSnapshotView {
    let hh_id = HouseholdId("hh-expected-responder-test".to_string());
    let active = active_m_id
        .map(|m_id| MachineRosterMemberV1 {
            m_id: m_id.clone(),
            m_pub: crate::keys::P256PublicKey([0x02; 33]),
            machine_cert: Vec::new(),
            machine_cert_fingerprint: [0xAAu8; 32],
        })
        .into_iter()
        .collect();
    let tombstones = revoked_m_id
        .map(|m_id| MachineRosterRevocationV1 {
            v: 1,
            kind: "machine_roster_revocation_v1".to_string(),
            hh_id: hh_id.clone(),
            epoch: [1u8; 32],
            sequence: 1,
            prev_event_hash: [0u8; 32],
            m_id: m_id.clone(),
            m_pub: crate::keys::P256PublicKey([0x02; 33]),
            machine_cert_fingerprint: [0xBBu8; 32],
            revoked_at: 1,
            reason: RevocationReason::OwnerAction,
            cascade: RevocationCascade::MachineOnly,
            owner_p_id: crate::machine_cert::PersonId("owner".to_string()),
            owner_cert_fingerprint: [4u8; 32],
            owner_person_cert: Vec::new(),
            signature: crate::keys::P256Signature([7u8; 64]),
        })
        .into_iter()
        .collect();
    let data = AcceptedRosterData {
        epoch: [1u8; 32],
        checkpoint_sequence: 1,
        checkpoint_hash,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: 1,
        event_head_hash: [3u8; 32],
        predecessor_event_sequence: 0,
        predecessor_event_head_hash: [0u8; 32],
        issued_at: 1,
        not_after: u64::MAX,
        owner_cert_fingerprint: [4u8; 32],
        genesis_basis: VerifiedGenesisRoster {
            epoch: [1u8; 32],
            members: Vec::new(),
        },
        active,
        tombstones,
    };
    RosterSnapshotView::project(&hh_id, &data)
}

/// RED-R18, checked first: a `PeerExpectation` sealed against one
/// `checkpoint_hash` redeemed against a snapshot with a different hash
/// is `ExpectationSnapshotMismatch` — even though, in this fixture, the
/// `m_id` would ALSO fail "not active" if the hash check didn't run
/// first. Pins the order, not just the outcome.
#[test]
fn expected_responder_rejects_snapshot_hash_mismatch_before_checking_membership() {
    let m_id = MachineId("m-responder-hash-mismatch".to_string());
    let expectation = PeerExpectation::injected_for_harness(
        [1u8; 32],
        m_id.clone(),
        PeerSelectionSource::LocalOwnerPresentSelection,
    );
    // Different hash AND m_id absent from active — if "not active" were
    // checked first this would return MachineNotActive instead.
    let snapshot = test_snapshot_for_responder([2u8; 32], None, None);
    let result = ExpectedResponder::from_peer_expectation(expectation, &snapshot);
    assert_eq!(
        result,
        Err(ExpectedResponderError::ExpectationSnapshotMismatch)
    );
}

#[test]
fn expected_responder_rejects_revoked_machine_on_matching_snapshot() {
    let checkpoint_hash = [5u8; 32];
    let m_id = MachineId("m-responder-revoked".to_string());
    let expectation = PeerExpectation::injected_for_harness(
        checkpoint_hash,
        m_id.clone(),
        PeerSelectionSource::LocalOwnerPresentSelection,
    );
    let snapshot = test_snapshot_for_responder(checkpoint_hash, None, Some(&m_id));
    let result = ExpectedResponder::from_peer_expectation(expectation, &snapshot);
    assert_eq!(result, Err(ExpectedResponderError::MachineRevoked));
}

#[test]
fn expected_responder_rejects_not_listed_machine_on_matching_snapshot() {
    let checkpoint_hash = [6u8; 32];
    let m_id = MachineId("m-responder-not-listed".to_string());
    let expectation = PeerExpectation::injected_for_harness(
        checkpoint_hash,
        m_id.clone(),
        PeerSelectionSource::LocalOwnerPresentSelection,
    );
    let snapshot = test_snapshot_for_responder(checkpoint_hash, None, None);
    let result = ExpectedResponder::from_peer_expectation(expectation, &snapshot);
    assert_eq!(result, Err(ExpectedResponderError::MachineNotActive));
}

#[test]
fn expected_responder_succeeds_for_active_machine_on_matching_snapshot() {
    let checkpoint_hash = [7u8; 32];
    let hh_id = HouseholdId("hh-expected-responder-test".to_string());
    let m_id = MachineId("m-responder-active".to_string());
    let expectation = PeerExpectation::injected_for_harness(
        checkpoint_hash,
        m_id.clone(),
        PeerSelectionSource::LocalOwnerPresentSelection,
    );
    let snapshot = test_snapshot_for_responder(checkpoint_hash, Some(&m_id), None);
    let responder = ExpectedResponder::from_peer_expectation(expectation, &snapshot)
        .expect("active machine, matching snapshot");
    assert_eq!(responder.hh_id(), &hh_id);
    assert_eq!(responder.m_id(), &m_id);
    assert_eq!(responder.cert_fingerprint(), [0xAAu8; 32]);
}

/// D-1 (audit round 3): `SealedBinding` carries exactly the fields
/// derived from a real, snapshot-validated `ExpectedResponder`, plus the
/// checkpoint sequence `ExpectedResponder` itself does not carry.
#[test]
fn sealed_binding_projects_expected_responder_and_snapshot_sequence() {
    let checkpoint_hash = [8u8; 32];
    let hh_id = HouseholdId("hh-expected-responder-test".to_string());
    let m_id = MachineId("m-sealed-binding".to_string());
    let expectation = PeerExpectation::injected_for_harness(
        checkpoint_hash,
        m_id.clone(),
        PeerSelectionSource::LocalOwnerPresentSelection,
    );
    let snapshot = test_snapshot_for_responder(checkpoint_hash, Some(&m_id), None);
    let responder = ExpectedResponder::from_peer_expectation(expectation, &snapshot)
        .expect("active machine, matching snapshot");
    let binding = SealedBinding::from_expected_responder(&responder, &snapshot);
    assert_eq!(binding.hh_id(), &hh_id);
    assert_eq!(binding.m_id(), &m_id);
    assert_eq!(binding.machine_cert_fingerprint(), [0xAAu8; 32]);
    assert_eq!(binding.checkpoint_hash(), checkpoint_hash);
    assert_eq!(
        binding.checkpoint_sequence(),
        snapshot.checkpoint_sequence()
    );
}

/// D-1 successor (@kiana E1): the responder path mirrors the
/// initiator path's revoked-first ordering — a revoked machine is
/// rejected as `MachineRevoked` even though (in a fixture with only
/// one of active/revoked populated) it is trivially also "not active".
#[test]
fn responding_peer_rejects_revoked_machine() {
    let checkpoint_hash = [9u8; 32];
    let m_id = MachineId("m-responder-inbound-revoked".to_string());
    let claim = AuthenticatedPeerClaim::injected_for_harness(m_id.clone());
    let snapshot = test_snapshot_for_responder(checkpoint_hash, None, Some(&m_id));
    let result = SealedBinding::from_responding_peer(&claim, &snapshot);
    assert_eq!(result, Err(RespondingPeerError::MachineRevoked));
}

#[test]
fn responding_peer_rejects_not_listed_machine() {
    let checkpoint_hash = [10u8; 32];
    let m_id = MachineId("m-responder-inbound-not-listed".to_string());
    let claim = AuthenticatedPeerClaim::injected_for_harness(m_id);
    let snapshot = test_snapshot_for_responder(checkpoint_hash, None, None);
    let result = SealedBinding::from_responding_peer(&claim, &snapshot);
    assert_eq!(result, Err(RespondingPeerError::MachineNotActive));
}

/// The end-to-end compile/API proof for E1: a responder — which has no
/// `PeerExpectation`/`ExpectedResponder` to redeem at all, only an
/// (already-authenticated, here harness-injected) claimed `m_id` — can
/// still produce a `SealedBinding` carrying exactly what the snapshot
/// proves for that machine, without ever constructing or naming
/// `PeerExpectation`/`ExpectedResponder` in this test.
#[test]
fn responding_peer_succeeds_for_active_machine_and_projects_into_sealed_binding() {
    let checkpoint_hash = [11u8; 32];
    let hh_id = HouseholdId("hh-expected-responder-test".to_string());
    let m_id = MachineId("m-responder-inbound-active".to_string());
    let claim = AuthenticatedPeerClaim::injected_for_harness(m_id.clone());
    let snapshot = test_snapshot_for_responder(checkpoint_hash, Some(&m_id), None);
    let binding = SealedBinding::from_responding_peer(&claim, &snapshot)
        .expect("active machine, real snapshot");
    assert_eq!(binding.hh_id(), &hh_id);
    assert_eq!(binding.m_id(), &m_id);
    assert_eq!(binding.machine_cert_fingerprint(), [0xAAu8; 32]);
    assert_eq!(binding.checkpoint_hash(), checkpoint_hash);
    assert_eq!(
        binding.checkpoint_sequence(),
        snapshot.checkpoint_sequence()
    );
}
