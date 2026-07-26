use std::collections::BTreeMap;

use household_rs::caveat_narrowing::{
    CaveatNarrowingError, DeviceCaveatNarrowingProofV1, verify_explicit_household_add_device_grant,
};
use household_rs::caveats::{
    Caveat, ConstraintValue, Constraints, Operation, Scope, owner_caveats,
};

fn caveat(op: Operation, scope: Option<Scope>, constraints: Option<Constraints>) -> Caveat {
    Caveat {
        op,
        scope,
        constraints,
    }
}

fn machines(values: &[&str]) -> Constraints {
    Constraints::try_from(BTreeMap::from([(
        "machines".to_string(),
        ConstraintValue::Machines(values.iter().map(|value| (*value).to_string()).collect()),
    )]))
    .unwrap()
}

fn expires_at(value: u64) -> Constraints {
    Constraints::try_from(BTreeMap::from([(
        "expires_at".to_string(),
        ConstraintValue::ExpiresAt(value),
    )]))
    .unwrap()
}

fn constraints(machines: Option<&[&str]>, expires_at: Option<u64>) -> Constraints {
    let mut map = BTreeMap::new();
    if let Some(values) = machines {
        map.insert(
            "machines".to_string(),
            ConstraintValue::Machines(values.iter().map(|value| (*value).to_string()).collect()),
        );
    }
    if let Some(value) = expires_at {
        map.insert("expires_at".to_string(), ConstraintValue::ExpiresAt(value));
    }
    Constraints::try_from(map).unwrap()
}

fn grant() -> Caveat {
    caveat(Operation::HouseholdAddDevice, None, None)
}

fn prove(
    person: &[Caveat],
    device: Option<&[Caveat]>,
) -> Result<DeviceCaveatNarrowingProofV1, CaveatNarrowingError> {
    verify_explicit_household_add_device_grant(person, device)
}

fn proof(person: &[Caveat], device: Option<&[Caveat]>) -> DeviceCaveatNarrowingProofV1 {
    verify_explicit_household_add_device_grant(person, device).unwrap()
}

fn assert_error(
    result: Result<DeviceCaveatNarrowingProofV1, CaveatNarrowingError>,
    expected: CaveatNarrowingError,
) {
    assert_eq!(result.unwrap_err(), expected);
}

#[test]
fn explicit_grant_and_empty_device_caveats_produce_opaque_proof() {
    let proof = proof(&[grant()], None);
    assert_eq!(proof.digest().len(), 32);
    assert_eq!(
        format!("{proof:?}"),
        "DeviceCaveatNarrowingProofV1(REDACTED)"
    );
}

#[test]
fn proof_digest_is_stable_for_identical_inputs_and_changes_with_input() {
    let first = prove(&[grant()], None).unwrap();
    let second = prove(&[grant()], None).unwrap();
    assert_eq!(first.digest(), second.digest());

    let narrowed = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(expires_at(100)),
    )];
    let narrowed_proof = prove(&[grant()], Some(&narrowed)).unwrap();
    assert_ne!(first.digest(), narrowed_proof.digest());
}

#[test]
fn grant_missing_when_operation_absent_or_scoped() {
    assert_error(
        prove(&owner_caveats(), None),
        CaveatNarrowingError::GrantMissing,
    );
    let scoped_grant = [caveat(
        Operation::HouseholdAddDevice,
        Some(Scope::all()),
        None,
    )];
    assert_error(
        prove(&scoped_grant, None),
        CaveatNarrowingError::GrantMissing,
    );
}

#[test]
fn duplicate_caveat_operation_is_rejected_without_normalizing() {
    let person = [grant(), grant()];
    assert_error(
        prove(&person, None),
        CaveatNarrowingError::DuplicateOperation,
    );

    let child = [
        caveat(Operation::ClawsList, Some(Scope::all()), None),
        caveat(Operation::ClawsList, Some(Scope::all()), None),
    ];
    assert_error(
        prove(
            &[
                grant(),
                caveat(Operation::ClawsList, Some(Scope::all()), None),
            ],
            Some(&child),
        ),
        CaveatNarrowingError::DuplicateOperation,
    );
}

#[test]
fn false_scope_booleans_are_rejected() {
    let all_false = [caveat(
        Operation::HouseholdAddDevice,
        Some(Scope::All { all: false }),
        None,
    )];
    assert_error(prove(&all_false, None), CaveatNarrowingError::ScopeAllFalse);
    let owned_false = [caveat(
        Operation::HouseholdAddDevice,
        Some(Scope::OwnedBySelf {
            owned_by_self: false,
        }),
        None,
    )];
    assert_error(
        prove(&owned_false, None),
        CaveatNarrowingError::ScopeOwnedBySelfFalse,
    );
}

#[test]
fn malformed_specific_is_rejected_before_scope_comparison() {
    let parent = [
        grant(),
        caveat(Operation::ClawsList, Some(Scope::all()), None),
    ];
    let child = [caveat(
        Operation::ClawsList,
        Some(Scope::Specific { specific: vec![] }),
        None,
    )];
    assert_error(
        prove(&parent, Some(&child)),
        CaveatNarrowingError::InvalidSpecific,
    );

    for specific in [
        vec!["beta".to_string(), "alpha".to_string()],
        vec!["alpha".to_string(), "alpha".to_string()],
    ] {
        let child = [caveat(
            Operation::ClawsList,
            Some(Scope::Specific { specific }),
            None,
        )];
        assert_error(
            prove(&parent, Some(&child)),
            CaveatNarrowingError::InvalidSpecific,
        );
    }
}

#[test]
fn scope_none_only_compares_with_none_as_n1() {
    let child = [caveat(
        Operation::HouseholdAddDevice,
        Some(Scope::all()),
        None,
    )];
    assert_error(
        prove(&[grant()], Some(&child)),
        CaveatNarrowingError::ScopePresenceMismatch,
    );

    let parent = [
        grant(),
        caveat(Operation::ClawsList, Some(Scope::all()), None),
    ];
    let child = [caveat(Operation::ClawsList, None, None)];
    assert_error(
        prove(&parent, Some(&child)),
        CaveatNarrowingError::ScopePresenceMismatch,
    );
}

#[test]
fn child_operation_absent_from_parent_is_rejected() {
    let child = [caveat(Operation::ClawsList, Some(Scope::all()), None)];
    assert_error(
        prove(&[grant()], Some(&child)),
        CaveatNarrowingError::OperationWidening,
    );
}

#[test]
fn scope_partial_order_is_literal() {
    let parent_all = [
        grant(),
        caveat(Operation::ClawsList, Some(Scope::all()), None),
    ];
    let child_owned = [caveat(
        Operation::ClawsList,
        Some(Scope::OwnedBySelf {
            owned_by_self: true,
        }),
        None,
    )];
    assert!(prove(&parent_all, Some(&child_owned)).is_ok());

    let child_specific = [caveat(
        Operation::ClawsList,
        Some(Scope::Specific {
            specific: vec!["alpha".to_string()],
        }),
        None,
    )];
    assert!(prove(&parent_all, Some(&child_specific)).is_ok());

    let parent_owned = [
        grant(),
        caveat(
            Operation::ClawsList,
            Some(Scope::OwnedBySelf {
                owned_by_self: true,
            }),
            None,
        ),
    ];
    let child_all = [caveat(Operation::ClawsList, Some(Scope::all()), None)];
    assert_error(
        prove(&parent_owned, Some(&child_all)),
        CaveatNarrowingError::ScopeWidening,
    );

    let parent_specific = [
        grant(),
        caveat(
            Operation::ClawsList,
            Some(Scope::Specific {
                specific: vec!["alpha".to_string(), "beta".to_string()],
            }),
            None,
        ),
    ];
    let child_subset = [caveat(
        Operation::ClawsList,
        Some(Scope::Specific {
            specific: vec!["alpha".to_string()],
        }),
        None,
    )];
    assert!(prove(&parent_specific, Some(&child_subset)).is_ok());
    let child_not_subset = [caveat(
        Operation::ClawsList,
        Some(Scope::Specific {
            specific: vec!["gamma".to_string()],
        }),
        None,
    )];
    assert_error(
        prove(&parent_specific, Some(&child_not_subset)),
        CaveatNarrowingError::ScopeWidening,
    );
}

#[test]
fn absent_parent_constraint_key_may_narrow_to_present_child_key() {
    let child = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(machines(&["m_alpha"])),
    )];
    assert!(prove(&[grant()], Some(&child)).is_ok());

    let parent = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(constraints(None, Some(100))),
    )];
    let child = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(constraints(Some(&["m_alpha"]), Some(50))),
    )];
    assert!(prove(&parent, Some(&child)).is_ok());

    let parent = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(constraints(Some(&["m_alpha", "m_beta"]), None)),
    )];
    let child = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(constraints(Some(&["m_alpha"]), Some(50))),
    )];
    assert!(prove(&parent, Some(&child)).is_ok());
}

#[test]
fn present_parent_constraint_with_absent_child_is_n2() {
    let parent = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(machines(&["m_alpha"])),
    )];
    assert_error(
        prove(
            &parent,
            Some(&[caveat(Operation::HouseholdAddDevice, None, None)]),
        ),
        CaveatNarrowingError::ConstraintPresenceMismatch,
    );

    let child_empty = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(constraints(None, None)),
    )];
    assert_error(
        prove(&parent, Some(&child_empty)),
        CaveatNarrowingError::ConstraintPresenceMismatch,
    );

    let parent = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(constraints(Some(&["m_alpha"]), Some(100))),
    )];
    let child_missing_expiry = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(machines(&["m_alpha"])),
    )];
    assert_error(
        prove(&parent, Some(&child_missing_expiry)),
        CaveatNarrowingError::ConstraintPresenceMismatch,
    );
}

#[test]
fn machines_subset_and_expiry_order_are_enforced() {
    let parent = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(constraints(Some(&["m_alpha", "m_beta"]), Some(100))),
    )];
    let child_not_subset = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(constraints(Some(&["m_gamma"]), Some(50))),
    )];
    assert_error(
        prove(&parent, Some(&child_not_subset)),
        CaveatNarrowingError::MachinesWidening,
    );

    let child_expiry_wider = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(constraints(Some(&["m_alpha"]), Some(101))),
    )];
    assert_error(
        prove(&parent, Some(&child_expiry_wider)),
        CaveatNarrowingError::ExpiryWidening,
    );

    let child_equal = [caveat(
        Operation::HouseholdAddDevice,
        None,
        Some(constraints(Some(&["m_alpha", "m_beta"]), Some(100))),
    )];
    assert!(prove(&parent, Some(&child_equal)).is_ok());
}

#[test]
fn malformed_machine_lists_are_rejected_without_normalizing() {
    let parent = [grant()];
    for values in [
        Vec::<&str>::new(),
        vec!["m_beta", "m_alpha"],
        vec!["m_alpha", "m_alpha"],
    ] {
        let child = [caveat(
            Operation::HouseholdAddDevice,
            None,
            Some(machines(&values)),
        )];
        assert_error(
            prove(&parent, Some(&child)),
            CaveatNarrowingError::InvalidConstraint,
        );
    }
}

#[test]
fn unknown_constraint_is_rejected_before_proof() {
    let unknown: Option<BTreeMap<String, Vec<String>>> = Some(BTreeMap::from([(
        "other".to_string(),
        vec!["m_alpha".to_string()],
    )]));
    let bytes = household_rs::cbor::to_canonical_vec(&unknown).unwrap();
    assert!(household_rs::cbor::from_canonical_slice::<Option<Constraints>>(&bytes).is_err());
}
