use std::collections::BTreeMap;

use ciborium::value::Value as CborValue;
use household_rs::caveats::{
    Caveat, ConstraintValue, Constraints, Operation, Scope, ScopeClosedError,
    owner_capability_names, owner_caveats, permits,
};
use household_rs::cbor;

#[test]
fn owner_template_contains_protocol_operations() {
    let names = owner_capability_names();
    assert_eq!(
        names,
        vec![
            "claws.list",
            "claws.create",
            "claws.delete",
            "claws.use",
            "claws.assign",
            "household.invite",
            "household.revoke",
            "household.add_machine",
        ]
    );
    assert!(
        !names.iter().any(|name| name == "owner_auth.enroll_initial"),
        "initial owner-auth enrollment is authorized by a dedicated owner-only gate, not the \
         reusable owner caveat template"
    );
    assert!(
        !names.iter().any(|name| name == "household.add_device"),
        "R0a HouseholdAddDevice is explicit-grant only, never part of the owner template"
    );
}

#[test]
fn owner_template_permits_all_owner_operations() {
    let caveats = owner_caveats();
    for op in [
        Operation::ClawsList,
        Operation::ClawsCreate,
        Operation::ClawsDelete,
        Operation::ClawsUse,
        Operation::ClawsAssign,
        Operation::HouseholdInvite,
        Operation::HouseholdRevoke,
        Operation::HouseholdAddMachine,
    ] {
        assert!(permits(&caveats, &op), "{op} should be permitted");
    }
    assert!(
        !permits(&caveats, &Operation::OwnerAuthEnrollInitial),
        "initial owner-auth enrollment must not be delegated by the broad owner caveat template"
    );
    assert!(
        !permits(&caveats, &Operation::HouseholdAddDevice),
        "HouseholdAddDevice must not be delegated by permits or the owner template"
    );
}

#[test]
fn household_add_device_is_recognized_but_not_templated_or_permitted() {
    let op = Operation::try_from("household.add_device").unwrap();
    assert_eq!(op, Operation::HouseholdAddDevice);
    assert_eq!(op.as_str(), "household.add_device");
    assert!(
        !owner_capability_names()
            .iter()
            .any(|name| name == op.as_str())
    );
    let explicit = [Caveat::new(Operation::HouseholdAddDevice, None)];
    assert!(
        !permits(&explicit, &Operation::HouseholdAddDevice),
        "even an explicit HouseholdAddDevice caveat is outside generic permits"
    );
}

#[test]
fn constraints_none_and_machines_legacy_bytes_are_byte_exact() {
    #[derive(serde::Serialize)]
    struct LegacyCaveat {
        op: Operation,
        scope: Option<Scope>,
        constraints: Option<BTreeMap<String, Vec<String>>>,
    }

    let legacy_none: Option<BTreeMap<String, Vec<String>>> = None;
    let closed_none: Option<Constraints> = None;
    assert_eq!(
        cbor::to_canonical_vec(&legacy_none).unwrap(),
        cbor::to_canonical_vec(&closed_none).unwrap()
    );

    let legacy_machines: Option<BTreeMap<String, Vec<String>>> = Some(BTreeMap::from([(
        "machines".to_string(),
        vec!["m_alpha".to_string(), "m_beta".to_string()],
    )]));
    let closed_machines: Option<Constraints> = Some(
        Constraints::try_from(BTreeMap::from([(
            "machines".to_string(),
            ConstraintValue::Machines(vec!["m_alpha".to_string(), "m_beta".to_string()]),
        )]))
        .unwrap(),
    );
    assert_eq!(
        cbor::to_canonical_vec(&legacy_machines).unwrap(),
        cbor::to_canonical_vec(&closed_machines).unwrap()
    );

    let legacy_none_caveat = LegacyCaveat {
        op: Operation::HouseholdAddMachine,
        scope: None,
        constraints: None,
    };
    let closed_none_caveat = Caveat::new(Operation::HouseholdAddMachine, None);
    assert_eq!(
        cbor::to_canonical_vec(&legacy_none_caveat).unwrap(),
        cbor::to_canonical_vec(&closed_none_caveat).unwrap()
    );

    let legacy_machines_caveat = LegacyCaveat {
        op: Operation::HouseholdAddMachine,
        scope: None,
        constraints: Some(BTreeMap::from([(
            "machines".to_string(),
            vec!["m_alpha".to_string(), "m_beta".to_string()],
        )])),
    };
    let closed_machines_caveat = Caveat {
        op: Operation::HouseholdAddMachine,
        scope: None,
        constraints: Some(
            Constraints::try_from(BTreeMap::from([(
                "machines".to_string(),
                ConstraintValue::Machines(vec!["m_alpha".to_string(), "m_beta".to_string()]),
            )]))
            .unwrap(),
        ),
    };
    assert_eq!(
        cbor::to_canonical_vec(&legacy_machines_caveat).unwrap(),
        cbor::to_canonical_vec(&closed_machines_caveat).unwrap()
    );
}

#[test]
fn expires_at_decodes_only_with_matching_key_and_shape() {
    let legacy_expires: Option<BTreeMap<String, u64>> = Some(BTreeMap::from([(
        "expires_at".to_string(),
        1_800_000_000_u64,
    )]));
    let bytes = cbor::to_canonical_vec(&legacy_expires).unwrap();
    let parsed: Option<Constraints> = cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(cbor::to_canonical_vec(&parsed).unwrap(), bytes);

    let wrong_shape: Option<BTreeMap<String, Vec<String>>> = Some(BTreeMap::from([(
        "expires_at".to_string(),
        vec!["not-a-u64".to_string()],
    )]));
    let wrong_bytes = cbor::to_canonical_vec(&wrong_shape).unwrap();
    assert!(cbor::from_canonical_slice::<Option<Constraints>>(&wrong_bytes).is_err());

    let machines_as_u64: Option<BTreeMap<String, u64>> =
        Some(BTreeMap::from([("machines".to_string(), 7_u64)]));
    let wrong_bytes = cbor::to_canonical_vec(&machines_as_u64).unwrap();
    assert!(cbor::from_canonical_slice::<Option<Constraints>>(&wrong_bytes).is_err());
}

#[test]
fn unknown_constraint_key_is_rejected_before_any_proof() {
    let unknown: Option<BTreeMap<String, Vec<String>>> = Some(BTreeMap::from([(
        "other".to_string(),
        vec!["m_alpha".to_string()],
    )]));
    let bytes = cbor::to_canonical_vec(&unknown).unwrap();
    assert!(cbor::from_canonical_slice::<Option<Constraints>>(&bytes).is_err());
}

#[test]
fn duplicate_constraint_key_is_rejected_without_normalizing() {
    let duplicate = CborValue::Map(vec![
        (
            CborValue::Text("machines".to_string()),
            CborValue::Array(vec![CborValue::Text("m_alpha".to_string())]),
        ),
        (
            CborValue::Text("machines".to_string()),
            CborValue::Array(vec![CborValue::Text("m_beta".to_string())]),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&duplicate, &mut bytes).unwrap();
    assert!(cbor::from_canonical_slice::<Option<Constraints>>(&bytes).is_err());
}

#[test]
fn false_scope_booleans_are_rejected() {
    assert_eq!(
        Scope::All { all: false }.validate_closed(),
        Err(ScopeClosedError::AllFalse)
    );
    assert_eq!(
        Scope::OwnedBySelf {
            owned_by_self: false
        }
        .validate_closed(),
        Err(ScopeClosedError::OwnedBySelfFalse)
    );
}

#[test]
fn specific_requires_nonempty_ordered_unique_without_extra_text_rules() {
    assert_eq!(
        Scope::Specific { specific: vec![] }.validate_closed(),
        Err(ScopeClosedError::SpecificEmpty)
    );
    for specific in [
        vec!["b".to_string(), "a".to_string()],
        vec!["a".to_string(), "a".to_string()],
    ] {
        assert_eq!(
            Scope::Specific { specific }.validate_closed(),
            Err(ScopeClosedError::SpecificNotOrderedUnique)
        );
    }
    assert!(
        Scope::Specific {
            specific: vec!["a b".to_string(), "c".to_string()],
        }
        .validate_closed()
        .is_ok(),
        "N does not add trim/control/length rules beyond non-empty, ordered, unique"
    );
}

#[test]
fn unknown_operation_string_is_rejected() {
    assert!(Operation::try_from("mobile.legacy").is_err());
}

#[test]
fn owner_auth_enroll_initial_operation_is_recognized_but_not_templated() {
    let op = Operation::try_from("owner_auth.enroll_initial").unwrap();
    assert_eq!(op, Operation::OwnerAuthEnrollInitial);
    assert_eq!(op.as_str(), "owner_auth.enroll_initial");
    assert!(
        !owner_capability_names()
            .iter()
            .any(|name| name == op.as_str())
    );
}
