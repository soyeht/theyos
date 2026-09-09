#![cfg(test)]

use super::*;
use std::time::{Duration, Instant};
use test_support::sample_delegation as sample;

fn far_future_deadline() -> CeremonyDeadline {
    CeremonyDeadline::for_test(Instant::now(), Duration::from_secs(3600))
}

fn wire(not_before: u64, not_after: u64) -> DelegationWire {
    DelegationWire {
        version: DELEGATION_VERSION,
        kind: DELEGATION_KIND.to_string(),
        domain: DELEGATION_DOMAIN.to_string(),
        hh_id: "hh-1".to_string(),
        delegator_m_id: "m-1".to_string(),
        delegator_cert_fingerprint: vec![0xAB; 32],
        delegated_pub: vec![0x02; 33],
        delegated_key_id: "key-1".to_string(),
        profile: DELEGATION_PROFILE.to_string(),
        transcript_kinds: vec!["identity-proof".to_string()],
        roles: vec!["initiator".to_string(), "responder".to_string()],
        channel: "dev".to_string(),
        serial: 1,
        not_before,
        not_after,
        sig: vec![0u8; 64],
    }
}

#[test]
fn wrong_version_rejected() {
    let mut w = wire(100, 200);
    w.version = 2;
    assert_eq!(
        MeshSessionDelegation::try_from(w),
        Err(DelegationError::VersionMismatch)
    );
}

#[test]
fn wrong_kind_rejected() {
    let mut w = wire(100, 200);
    w.kind = "not-the-frozen-kind".to_string();
    assert_eq!(
        MeshSessionDelegation::try_from(w),
        Err(DelegationError::KindMismatch)
    );
}

#[test]
fn wrong_domain_rejected() {
    let mut w = wire(100, 200);
    w.domain = "soyeht/mesh-connection-intent/v1".to_string(); // a real, but WRONG, domain literal
    assert_eq!(
        MeshSessionDelegation::try_from(w),
        Err(DelegationError::DomainMismatch)
    );
}

#[test]
fn wrong_profile_rejected() {
    let mut w = wire(100, 200);
    w.profile = "roster-sync".to_string();
    assert_eq!(
        MeshSessionDelegation::try_from(w),
        Err(DelegationError::ProfileMismatch)
    );
}

#[test]
fn channel_outside_dev_or_release_rejected() {
    let mut w = wire(100, 200);
    w.channel = "staging".to_string();
    assert_eq!(
        MeshSessionDelegation::try_from(w),
        Err(DelegationError::ChannelInvalid)
    );
}

#[test]
fn release_channel_is_accepted() {
    let mut w = wire(100, 200);
    w.channel = "release".to_string();
    MeshSessionDelegation::try_from(w).unwrap();
}

#[test]
fn transcript_kinds_and_roles_accept_arbitrary_text_not_a_fixed_list() {
    // v6 §5 fixes only the shape ([text]), never the exact allowed
    // values — this crate must not invent a list to check against.
    let mut w = wire(100, 200);
    w.transcript_kinds = vec!["anything-goes-here".to_string()];
    w.roles = vec!["also-anything".to_string()];
    MeshSessionDelegation::try_from(w).unwrap();
}

#[test]
fn round_trip_canonical() {
    let d = sample(100, 200);
    let bytes = d.to_canonical_bytes().unwrap();
    let back = MeshSessionDelegation::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(d, back);
}

#[test]
fn round_trip_rejects_noncanonical_bytes() {
    use ciborium::Value;
    // Same fields, declared out of canonical (sorted) order.
    let raw = Value::Map(vec![
        (Value::Text("version".into()), Value::Integer(1.into())),
        (
            Value::Text("kind".into()),
            Value::Text(DELEGATION_KIND.into()),
        ),
        (Value::Text("hh_id".into()), Value::Text("hh-1".into())),
        (
            Value::Text("domain".into()),
            Value::Text(DELEGATION_DOMAIN.into()),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&raw, &mut bytes).unwrap();
    assert!(MeshSessionDelegation::from_canonical_bytes(&bytes).is_err());
}

#[test]
fn wrong_size_bstr_is_rejected() {
    let mut w = wire(100, 200);
    w.delegator_cert_fingerprint = vec![0xAB; 31]; // one byte short
    assert_eq!(
        MeshSessionDelegation::try_from(w),
        Err(DelegationError::NonCanonical)
    );
}

#[test]
fn red_delegated_pub_right_length_wrong_curve_point_is_rejected() {
    // 33 bytes, correctly shaped, but 0xAB is not a valid SEC1 compressed-
    // point prefix (must be 0x02 or 0x03) — proves the check is a real
    // curve-point parse, not just a length check.
    let mut w = wire(100, 200);
    w.delegated_pub = vec![0xAB; 33];
    assert_eq!(
        MeshSessionDelegation::try_from(w),
        Err(DelegationError::InvalidDelegatedPubPoint)
    );
}

#[test]
fn wrong_size_sig_is_rejected() {
    let mut w = wire(100, 200);
    w.sig = vec![0xAB; 63]; // one byte short of the wire-field size
    assert_eq!(
        MeshSessionDelegation::try_from(w),
        Err(DelegationError::NonCanonical)
    );
}

#[test]
fn embedding_in_a_larger_struct_validates_too() {
    // Regression for the audit finding: validation used to run only in
    // from_canonical_bytes's own explicit call, so a
    // MeshSessionDelegation deserialized as a *field* of some other
    // struct (e.g. an auth frame) skipped it entirely. The
    // try_from-based Deserialize impl means any embedding struct's
    // derive now validates automatically.
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        delegation: MeshSessionDelegation,
    }
    let mut w = wire(100, 200);
    w.channel = "not-dev-or-release".to_string();
    let bad_wire_bytes = cbor::to_canonical_vec(&w).unwrap();
    // Build the envelope's bytes by hand: a map with one key
    // "delegation" whose value is the (invalid) delegation map.
    let delegation_value: ciborium::Value =
        ciborium::de::from_reader(std::io::Cursor::new(&bad_wire_bytes)).unwrap();
    let envelope_value = ciborium::Value::Map(vec![(
        ciborium::Value::Text("delegation".into()),
        delegation_value,
    )]);
    let mut envelope_bytes = Vec::new();
    ciborium::ser::into_writer(&envelope_value, &mut envelope_bytes).unwrap();
    assert!(cbor::from_canonical_bytes::<Envelope>(&envelope_bytes).is_err());
}

#[test]
fn no_verifier_configured_fails_closed_even_for_an_internally_consistent_delegation() {
    let d = sample(100, 200);
    assert_eq!(
        d.verify_signature(&NoVerifierConfigured, &far_future_deadline()),
        Err(DelegationError::BadSignature)
    );
}

#[test]
fn red45_ttl_reversed_rejected() {
    let policy = DelegationPolicy::test(3600);
    assert_eq!(
        policy.validate_window(200, 100),
        Err(DelegationError::InvalidTtlWindow)
    );
}

#[test]
fn red46_ttl_equal_rejected() {
    let policy = DelegationPolicy::test(3600);
    assert_eq!(
        policy.validate_window(200, 200),
        Err(DelegationError::InvalidTtlWindow)
    );
}

#[test]
fn production_policy_rejects_everything_until_measured() {
    let policy = DelegationPolicy::production();
    assert!(matches!(
        policy.validate_window(0, 1),
        Err(DelegationError::TtlExceedsPolicy { ttl: 1, max_ttl: 0 })
    ));
}

#[test]
fn pos3_fixture_with_test_policy_is_accepted() {
    let policy = DelegationPolicy::test(3600);
    let d = sample(1_000, 1_000 + 3600);
    policy.validate(&d).unwrap();
}

#[test]
fn ttl_over_policy_max_is_rejected() {
    let policy = DelegationPolicy::test(3600);
    let d = sample(1_000, 1_000 + 3601);
    assert!(matches!(
        policy.validate(&d),
        Err(DelegationError::TtlExceedsPolicy {
            ttl: 3601,
            max_ttl: 3600
        })
    ));
}

#[test]
fn partial_binding_matching_inputs_accepted() {
    let d = sample(100, 200);
    let ctx = PartialBindingInputs {
        proof_hh_id: "hh-1".to_string(),
        local_hh_id: "hh-1".to_string(),
        proof_self_m_id: "m-1".to_string(),
        proof_self_cert_fingerprint: vec![0xAB; 32],
    };
    d.check_partial_binding(&ctx).unwrap();
}

#[test]
fn partial_binding_household_mismatch_rejected() {
    let d = sample(100, 200);
    let ctx = PartialBindingInputs {
        proof_hh_id: "hh-1".to_string(),
        local_hh_id: "hh-DIFFERENT".to_string(),
        proof_self_m_id: "m-1".to_string(),
        proof_self_cert_fingerprint: vec![0xAB; 32],
    };
    assert_eq!(
        d.check_partial_binding(&ctx),
        Err(DelegationError::HouseholdBindingMismatch)
    );
}

#[test]
fn partial_binding_delegator_m_id_mismatch_rejected() {
    let d = sample(100, 200);
    let ctx = PartialBindingInputs {
        proof_hh_id: "hh-1".to_string(),
        local_hh_id: "hh-1".to_string(),
        proof_self_m_id: "m-DIFFERENT".to_string(),
        proof_self_cert_fingerprint: vec![0xAB; 32],
    };
    assert_eq!(
        d.check_partial_binding(&ctx),
        Err(DelegationError::DelegatorBindingMismatch)
    );
}

#[test]
fn partial_binding_fingerprint_mismatch_rejected() {
    let d = sample(100, 200);
    let ctx = PartialBindingInputs {
        proof_hh_id: "hh-1".to_string(),
        local_hh_id: "hh-1".to_string(),
        proof_self_m_id: "m-1".to_string(),
        proof_self_cert_fingerprint: vec![0xFF; 32],
    };
    assert_eq!(
        d.check_partial_binding(&ctx),
        Err(DelegationError::DelegatorBindingMismatch)
    );
}

#[test]
fn accessors_reflect_constructed_fields() {
    let d = sample(100, 200);
    assert_eq!(d.version(), 1);
    assert_eq!(d.kind(), DELEGATION_KIND);
    assert_eq!(d.domain(), DELEGATION_DOMAIN);
    assert_eq!(d.hh_id(), "hh-1");
    assert_eq!(d.delegator_m_id(), "m-1");
    assert_eq!(d.delegator_cert_fingerprint(), &[0xABu8; 32][..]);
    assert_eq!(d.delegated_pub(), &[0x02u8; 33][..]);
    assert_eq!(d.delegated_key_id(), "key-1");
    assert_eq!(d.profile(), DELEGATION_PROFILE);
    assert_eq!(d.channel(), "dev");
    assert_eq!(d.serial(), 1);
    assert_eq!(d.not_before(), 100);
    assert_eq!(d.not_after(), 200);
    assert_eq!(d.sig(), &[0u8; 64][..]);
}
