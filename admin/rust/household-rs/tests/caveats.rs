use household_rs::caveats::{Operation, owner_capability_names, owner_caveats, permits};

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
