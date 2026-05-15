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
}

#[test]
fn unknown_operation_string_is_rejected() {
    assert!(Operation::try_from("mobile.legacy").is_err());
}
